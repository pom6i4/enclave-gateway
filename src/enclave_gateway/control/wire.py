"""Bounded, deadline-aware line framing for QEMU control sockets."""

from __future__ import annotations

import socket
import time

from enclave_gateway.operations.context import budget, checkpoint


class SocketLineReader:
    def __init__(self, sock: socket.socket, deadline: float, max_bytes: int = 96 * 1024 * 1024):
        self.sock = sock
        self.deadline = deadline
        self.max_bytes = max_bytes
        self.buffer = bytearray()

    def _receive(self) -> None:
        while True:
            checkpoint("control.receive")
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Control channel deadline expired")
            self.sock.settimeout(min(0.2, budget(remaining, "control.receive")))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("EOF on control channel")
            self.buffer.extend(chunk)
            if len(self.buffer) > self.max_bytes:
                raise ValueError("Control channel frame exceeds size limit")
            return

    def sync_marker(self) -> None:
        while 255 not in self.buffer:
            self.buffer.clear()
            self._receive()
        del self.buffer[:self.buffer.index(255) + 1]

    def readline(self, *, sync: bool = False) -> str:
        while 10 not in self.buffer:
            self._receive()
        end = self.buffer.index(10) + 1
        line = bytes(self.buffer[:end])
        del self.buffer[:end]
        if sync:
            line = line.rsplit(b"\xff", 1)[-1]
        return line.decode("utf-8")
