"""Structured JSONL audit logger and Markdown report builder."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections import deque

from enclave_gateway.control.qga_client import _file_lock

GENESIS_HASH = "0" * 64


@dataclass(slots=True)
class AuditRecord:
    tx_id: str
    timestamp_utc: str
    actor: str
    operation: str
    node: str
    summary: str
    exit_code: int
    duration_ms: int
    sha256: str = ""
    prev_hash: str = GENESIS_HASH
    record_hash: str = ""


def _compute_record_hash(payload: dict[str, Any]) -> str:
    canonical = {
        "tx_id": payload.get("tx_id", ""),
        "timestamp_utc": payload.get("timestamp_utc", ""),
        "actor": payload.get("actor", ""),
        "operation": payload.get("operation", ""),
        "node": payload.get("node", ""),
        "summary": payload.get("summary", ""),
        "exit_code": int(payload.get("exit_code", 0)),
        "duration_ms": int(payload.get("duration_ms", 0)),
        "sha256": payload.get("sha256", ""),
        "prev_hash": payload.get("prev_hash", GENESIS_HASH),
    }
    raw = json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest().lower()


class FlightRecorder:
    """Appends structured operation telemetry to a local tamper-evident JSONL audit log."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        default_path = Path(
            os.path.expanduser("~/.local/share/enclave-gateway/audit.jsonl")
        )
        self.log_path = Path(log_path) if log_path else default_path
        self.scrubber = None

    def _last_record_hash(self) -> str:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return GENESIS_HASH
        with self.log_path.open("rb") as stream:
            position = stream.seek(0, 2)
            tail = b""
            while position:
                step = min(position, 4096)
                position -= step
                stream.seek(position)
                tail = stream.read(step) + tail
                lines = tail.splitlines()
                if len(lines) >= 2 or position == 0:
                    try:
                        record = json.loads(lines[-1])
                        if not isinstance(record, dict) or record.get("record_hash") != _compute_record_hash(record):
                            raise ValueError("Invalid audit tail")
                        return record["record_hash"]
                    except (ValueError, TypeError, KeyError, IndexError) as exc:
                        raise RuntimeError("Audit tail is corrupt; refusing to append") from exc
        return GENESIS_HASH

    def record(
        self,
        *,
        tx_id: str,
        actor: str,
        operation: str,
        node: str,
        summary: str,
        exit_code: int,
        duration_ms: int,
        sha256: str = "",
    ) -> AuditRecord:
        with _file_lock(Path(f"{self.log_path}.lock")):
            prev_hash = self._last_record_hash()
            entry = AuditRecord(
                tx_id=tx_id,
                timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                actor=actor,
                operation=operation,
                node=node,
                summary=(self.scrubber.scrub(summary) if self.scrubber else summary)[:240],
                exit_code=exit_code,
                duration_ms=duration_ms,
                sha256=sha256,
                prev_hash=prev_hash,
            )
            entry_dict = asdict(entry)
            entry.record_hash = _compute_record_hash(entry_dict)
            entry_dict["record_hash"] = entry.record_hash
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fp:
                if os.name != "nt":
                    os.fchmod(fp.fileno(), 0o600)
                fp.write(json.dumps(entry_dict, ensure_ascii=False) + "\n")
                fp.flush()
            return entry

    def verify_integrity(self) -> tuple[bool, int]:
        """Verify the cryptographic SHA-256 hash chain across all recorded entries."""
        if not self.log_path.is_file():
            return True, 0
        with _file_lock(Path(f"{self.log_path}.lock")), self.log_path.open(encoding="utf-8", errors="replace") as stream:
            expected_prev = GENESIS_HASH
            verified = 0
            for line in stream:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict) or record.get("prev_hash", GENESIS_HASH) != expected_prev:
                        return False, verified
                    computed = _compute_record_hash(record)
                except (ValueError, TypeError):
                    return False, verified
                if record.get("record_hash") != computed:
                    return False, verified
                expected_prev = computed
                verified += 1
            return True, verified

    def read_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.log_path.is_file():
            return []
        if limit <= 0:
            return []
        with self.log_path.open(encoding="utf-8", errors="replace") as stream:
            lines = deque(stream, maxlen=limit)
        records: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        records.append(record)
                except json.JSONDecodeError:
                    continue
        return records

    def export_markdown_report(self, limit: int = 100) -> str:
        records = self.read_recent(limit=limit)
        lines = [
            "# Enclave Gateway Session Report",
            "",
            "| UTC Timestamp | Transaction ID | Actor | Node | Operation | Exit | Duration | SHA-256 | Summary |",
            "|---|---|---|---|---|---:|---:|---|---|",
        ]
        for rec in records:
            sha_short = (rec.get("sha256") or "")[:12]
            summary = str(rec.get("summary", "")).replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| `{rec.get('timestamp_utc', '')}` | `{rec.get('tx_id', '')}` "
                f"| `{rec.get('actor', '')}` | `{rec.get('node', '')}` "
                f"| `{rec.get('operation', '')}` | `{rec.get('exit_code', 0)}` "
                f"| `{rec.get('duration_ms', 0)} ms` | `{sha_short}` | {summary} |"
            )
        return "\n".join(lines) + "\n"
