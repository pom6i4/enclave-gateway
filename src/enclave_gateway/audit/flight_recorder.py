"""Structured JSONL audit logger and Markdown report builder."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

    def _last_record_hash(self) -> str:
        recent = self.read_recent(limit=1)
        if not recent:
            return GENESIS_HASH
        return str(recent[-1].get("record_hash") or GENESIS_HASH)

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
        prev_hash = self._last_record_hash()
        entry = AuditRecord(
            tx_id=tx_id,
            timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            actor=actor,
            operation=operation,
            node=node,
            summary=summary[:240],
            exit_code=exit_code,
            duration_ms=duration_ms,
            sha256=sha256,
            prev_hash=prev_hash,
        )
        entry_dict = asdict(entry)
        entry.record_hash = _compute_record_hash(entry_dict)
        entry_dict["record_hash"] = entry.record_hash
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(entry_dict, ensure_ascii=False) + "\n")
            try:
                self.log_path.chmod(0o600)
            except OSError:
                pass
        except OSError:
            pass
        return entry

    def verify_integrity(self) -> tuple[bool, int]:
        """Verify the cryptographic SHA-256 hash chain across all recorded entries."""
        if not self.log_path.is_file():
            return True, 0
        lines = [
            ln.strip()
            for ln in self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip()
        ]
        expected_prev = GENESIS_HASH
        verified = 0
        for line in lines:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, verified
            if rec.get("prev_hash", GENESIS_HASH) != expected_prev:
                return False, verified
            computed = _compute_record_hash(rec)
            if rec.get("record_hash") != computed:
                return False, verified
            expected_prev = computed
            verified += 1
        return True, verified

    def read_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.log_path.is_file():
            return []
        lines = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        records: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
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
