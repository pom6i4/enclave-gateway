"""Structured JSONL audit logger and Markdown report builder."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


class FlightRecorder:
    """Appends structured operation telemetry to a local JSONL audit log."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        default_path = Path(
            os.path.expanduser("~/.local/share/enclave-gateway/audit.jsonl")
        )
        self.log_path = Path(log_path) if log_path else default_path

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
        )
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        except OSError:
            pass
        return entry

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
