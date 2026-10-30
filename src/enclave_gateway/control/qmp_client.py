"""QEMU Monitor Protocol (QMP) client for appliance lifecycle and snapshots."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any


class QmpClient:
    """Communicates with QEMU over QMP UNIX domain socket."""

    def __init__(self, socket_path: str | Path) -> None:
        self.socket_path = Path(socket_path)

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(str(self.socket_path))
            reader = sock.makefile("r", encoding="utf-8", errors="replace")
            reader.readline()  # QMP greeting banner
            sock.sendall(b'{"execute":"qmp_capabilities"}\n')
            reader.readline()  # capabilities ack

            payload: dict[str, Any] = {"execute": command}
            if arguments:
                payload["arguments"] = arguments
            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            while True:
                line = reader.readline()
                if not line:
                    return {}
                parsed = json.loads(line)
                if "return" in parsed or "error" in parsed:
                    return dict(parsed)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def system_powerdown(self) -> bool:
        try:
            self.execute("system_powerdown")
            return True
        except OSError:
            return False

    def query_status(self) -> dict[str, Any]:
        try:
            return self.execute("query-status")
        except OSError as exc:
            return {"error": str(exc)}
