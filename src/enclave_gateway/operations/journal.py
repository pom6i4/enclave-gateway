"""Private SQLite transaction journal; ambiguous work is never replayed."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import threading
from contextlib import contextmanager
from pathlib import Path

from enclave_gateway.operations.context import OperationError

TERMINAL = frozenset(("completed", "failed", "cancelled"))


class TransactionJournal:
    def __init__(self, path: Path, retention=None) -> None:
        from enclave_gateway.operations.retention import RetentionPolicy
        self.path = Path(path)
        self.retention = retention or RetentionPolicy()
        self._maintenance_lock = threading.Lock()
        self._last_maintenance = 0.0

    @contextmanager
    def connect(self, wait_sec: float = 0.2):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise PermissionError("Transaction journal must not be a symlink")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        if os.name != "nt":
            self.path.chmod(0o600)
        connection = sqlite3.connect(self.path, timeout=wait_sec, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA busy_timeout=" + str(max(1, int(wait_sec * 1000))))
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("""CREATE TABLE IF NOT EXISTS transactions (
                tx_id TEXT PRIMARY KEY, principal TEXT NOT NULL, operation TEXT NOT NULL,
                node TEXT NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL,
                created REAL NOT NULL, updated REAL NOT NULL, expires REAL NOT NULL,
                result TEXT, error TEXT, timings TEXT NOT NULL DEFAULT '{}')""")
            columns = {row[1] for row in connection.execute('PRAGMA table_info(transactions)')}
            if 'archive_ref' not in columns:
                try: connection.execute("ALTER TABLE transactions ADD COLUMN archive_ref TEXT NOT NULL DEFAULT ''")
                except sqlite3.OperationalError:
                    if 'archive_ref' not in {row[1] for row in connection.execute('PRAGMA table_info(transactions)')}: raise
            yield connection
        finally:
            connection.close()

    def reserve(self, tx_id: str, principal: str, operation: str, node: str, fingerprint: str, timeout: float):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", tx_id):
            raise ValueError("Invalid transaction id")
        now = time.time()
        with self.connect(wait_sec=min(0.2, max(0.001, timeout))) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM transactions WHERE tx_id=?", (tx_id,)).fetchone()
                if row:
                    if row["principal"] != principal or row["fingerprint"] != fingerprint or row["operation"] != operation:
                        raise OperationError("transaction_conflict", "journal", tx_id=tx_id, node=node)
                    db.execute("COMMIT")
                    return self.hydrate(self.decode(row))
                if db.execute('SELECT COUNT(*) FROM transactions').fetchone()[0] >= self.retention.max_identities:
                    raise OperationError('journal_capacity', 'journal', tx_id=tx_id, message='Identity capacity reached; choose an explicitly new journal namespace')
                db.execute("INSERT INTO transactions (tx_id,principal,operation,node,fingerprint,state,created,updated,expires) VALUES (?,?,?,?,?,'accepted',?,?,?)",
                           (tx_id, principal, operation, node, fingerprint, now, now, now + timeout))
                db.execute("COMMIT")
                return None
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    @staticmethod
    def decode(row):
        result = dict(row)
        for key in ("result", "error", "timings"):
            result[key] = json.loads(result[key]) if result[key] else None
        return result

    def get(self, tx_id: str, principal: str):
        with self.connect() as db:
            row = db.execute("SELECT * FROM transactions WHERE tx_id=? AND principal=?", (tx_id, principal)).fetchone()
        return self.hydrate(self.decode(row)) if row else None

    def hydrate(self, row):
        if row.get('archive_ref'):
            from enclave_gateway.operations.retention import read_archive
            try:
                archived = read_archive(self.path.with_suffix('.archives'),row['archive_ref'],row['tx_id'],row['principal'])
                row['result'],row['error'] = archived['result'],archived['error']
                row['payload_status'] = 'archived'
            except FileNotFoundError:
                row['payload_status'] = 'expired'
            except (ValueError, OSError):
                row['payload_status'] = 'archive_unavailable'
        else:
            row['payload_status'] = 'retained'
        return row

    def maintain(self, *, force=False):
        from enclave_gateway.operations.retention import maintain
        if not self._maintenance_lock.acquire(blocking=force):
            return {'deferred':True}
        try:
            if force or time.monotonic()-self._last_maintenance >= self.retention.interval_seconds:
                result = maintain(self)
                self._last_maintenance = time.monotonic()
                return result
            return {'deferred':True}
        finally:
            self._maintenance_lock.release()

    def recent(self, principal: str, limit: int = 25):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM transactions WHERE principal=? ORDER BY created DESC LIMIT ?", (principal, max(1, min(1000, limit)))).fetchall()
        return [self.decode(row) for row in rows]

    def update(self, tx_id: str, principal: str, state: str, *, result=None, error=None, timings=None):
        if state not in TERMINAL | {"running", "cancel_requested", "indeterminate"}:
            raise ValueError("Invalid transaction state")
        with self.connect() as db:
            changed = db.execute("UPDATE transactions SET state=?,updated=?,result=?,error=?,timings=? WHERE tx_id=? AND principal=?",
                                 (state, time.time(), json.dumps(result, ensure_ascii=False) if result is not None else None,
                                  json.dumps(error, ensure_ascii=False) if error is not None else None,
                                  json.dumps(timings or {}), tx_id, principal)).rowcount
            if changed != 1:
                raise OperationError("transaction_not_found", "journal", tx_id=tx_id)

        if state in TERMINAL or state=='indeterminate':
            # A maintenance failure cannot replace an already committed outcome.
            # Capacity/identity protection remains active before any new dispatch.
            try:
                with self.connect() as db:
                    count,size=db.execute("SELECT COUNT(*),COALESCE(SUM(length(CAST(COALESCE(result,'') AS BLOB))+length(CAST(COALESCE(error,'') AS BLOB))),0) FROM transactions WHERE archive_ref='' AND state IN ('completed','failed','cancelled','indeterminate')").fetchone()
                self.maintain(force=count>self.retention.max_results or size>self.retention.max_payload_bytes)
            except (OSError,ValueError,sqlite3.Error) as exc:
                self._maintenance_error=type(exc).__name__

    def request_cancel(self, tx_id: str, principal: str) -> bool:
        with self.connect() as db:
            return bool(db.execute("UPDATE transactions SET state='cancel_requested',updated=? WHERE tx_id=? AND principal=? AND state IN ('accepted','running')",
                                   (time.time(), tx_id, principal)).rowcount)

    def reconcile_expired(self, principal: str, nodes: set[str] | None = None) -> int:
        """Expiry establishes ambiguity, never proof that remote execution stopped."""
        with self.connect() as db:
            node_filter = "" if nodes is None else " AND node IN (" + ",".join("?" for _ in nodes) + ")"
            return db.execute("UPDATE transactions SET state='indeterminate',updated=? WHERE principal=? AND expires<? AND state IN ('accepted','running','cancel_requested')" + node_filter,
                              (time.time(), principal, time.time(), *(sorted(nodes) if nodes is not None else ()))).rowcount
