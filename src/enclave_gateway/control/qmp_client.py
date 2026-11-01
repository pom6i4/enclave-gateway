"""QEMU Monitor Protocol (QMP) client for appliance lifecycle and snapshots."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any

from enclave_gateway.control.wire import SocketLineReader
from enclave_gateway.control.local_socket import connect_local


class QmpClient:
    """Communicates with QEMU over QMP UNIX domain socket."""

    def __init__(self, socket_path: str | Path) -> None:
        self.socket_path = Path(socket_path)

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        with connect_local(self.socket_path,5.0) as sock:
            reader = SocketLineReader(sock, time.monotonic() + 5.0)
            greeting = json.loads(reader.readline())
            if not isinstance(greeting, dict) or "QMP" not in greeting:
                raise ConnectionError("Invalid QMP greeting")

            def exchange(name, args, req_id):
                payload = {"execute": name, "id": req_id}
                if args is not None:
                    payload["arguments"] = args
                sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
                while True:
                    response = json.loads(reader.readline())
                    if response.get("id") == req_id and ("return" in response or "error" in response):
                        return response

            capabilities = exchange("qmp_capabilities", None, "capabilities")
            if "error" in capabilities:
                raise RuntimeError(f"QMP capability negotiation failed: {capabilities['error']}")
            return exchange(command, arguments, "command")

    def system_powerdown(self) -> bool:
        try:
            return "return" in self.execute("system_powerdown")
        except (OSError, ValueError, RuntimeError):
            return False

    def query_status(self) -> dict[str, Any]:
        try:
            return self.execute("query-status")
        except (OSError, ValueError, RuntimeError) as exc:
            return {"error": str(exc)}
