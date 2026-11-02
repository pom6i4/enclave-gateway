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
                # One extra byte distinguishes an oversized frame. Do not
                # charge coalesced later frames against the first frame.
                chunk = self.sock.recv(min(65536, max(1, self.max_bytes + 1 - len(self.buffer))))
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("EOF on control channel")
            self.buffer.extend(chunk)
            return

    def sync_marker(self) -> None:
        while 255 not in self.buffer:
            self.buffer.clear()
            self._receive()
        del self.buffer[:self.buffer.index(255) + 1]

    def readline(self, *, sync: bool = False) -> str:
        while True:
            marker = self.buffer.find(10)
            if marker >= 0:
                if marker + 1 > self.max_bytes:
                    raise ValueError("Control channel frame exceeds size limit")
                break
            if len(self.buffer) > self.max_bytes:
                raise ValueError("Control channel frame exceeds size limit")
            self._receive()
        end = marker + 1
        line = bytes(self.buffer[:end])
        del self.buffer[:end]
        if sync:
            line = line.rsplit(b"\xff", 1)[-1]
        return line.decode("utf-8")
