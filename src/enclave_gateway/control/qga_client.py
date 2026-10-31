"""QEMU Guest Agent (QGA) client with UNIX socket locking and chunked file I/O."""

from __future__ import annotations

import base64
import json
import os
import random
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]


@dataclass(slots=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


class ControlChannel(Protocol):
    """Protocol for executing commands and transferring files on the Appliance."""

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult: ...

    def write_file(self, local_path: Path, guest_path: str) -> None: ...

    def read_file(self, guest_path: str, local_path: Path) -> None: ...

    def write_bytes(self, data: bytes, guest_path: str) -> None: ...

    def read_bytes(self, guest_path: str) -> bytes: ...


@contextmanager
def _file_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fp = lock_path.open("a+")
    try:
        if fcntl is not None:
            fcntl.flock(fp, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(fp, fcntl.LOCK_UN)
            except OSError:
                pass
        fp.close()


class QgaClient:
    """Thread/process-safe client for QEMU Guest Agent over virtio-serial UNIX socket."""

    CHUNK_SIZE = 65536

    def __init__(
        self,
        socket_path: str | Path,
        lock_path: str | Path | None = None,
        *,
        direct_spool_ipc: bool = True,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.lock_path = (
            Path(lock_path) if lock_path else Path(f"{self.socket_path}.lock")
        )
        self.supports_direct_spool_ipc = direct_spool_ipc
        self._thread_lock = threading.RLock()

    @contextmanager
    def _connect_synced(self, timeout_sec: float = 30.0) -> Iterator[tuple[socket.socket, object]]:
        with self._thread_lock, _file_lock(self.lock_path):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout_sec)
            try:
                sock.connect(str(self.socket_path))
                reader = sock.makefile("r", encoding="utf-8", errors="replace")
                sync_id = random.randint(100000, 999999)
                payload = json.dumps({"execute": "guest-sync", "arguments": {"id": sync_id}})
                sock.sendall(b"\xff\n" + (payload + "\n").encode("utf-8"))
                while True:
                    line = reader.readline()
                    if not line:
                        raise ConnectionError("EOF during QGA guest-sync handshake")
                    if f": {sync_id}" in line:
                        break
                yield sock, reader
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        started = time.monotonic()
        encoded_cmd = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        with self._connect_synced(timeout_sec=min(timeout_sec, 30.0)) as (sock, reader):
            req = {
                "execute": "guest-exec",
                "arguments": {
                    "path": "powershell.exe",
                    "arg": [
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-EncodedCommand",
                        encoded_cmd,
                    ],
                    "capture-output": True,
                },
            }
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            raw_line = reader.readline().lstrip("\xff")  # type: ignore[attr-defined]
            resp = json.loads(raw_line)
            if "return" not in resp or "pid" not in resp["return"]:
                raise RuntimeError(f"Unexpected QGA guest-exec response: {resp}")
            pid = resp["return"]["pid"]

        deadline = time.monotonic() + timeout_sec
        poll_delay = 0.015
        while time.monotonic() < deadline:
            time.sleep(poll_delay)
            poll_delay = min(0.15, poll_delay * 1.6)
            with self._connect_synced(timeout_sec=10.0) as (sock, reader):
                status_req = json.dumps(
                    {"execute": "guest-exec-status", "arguments": {"pid": pid}}
                )
                sock.sendall((status_req + "\n").encode("utf-8"))
                st_line = reader.readline().lstrip("\xff")  # type: ignore[attr-defined]
                st = json.loads(st_line).get("return", {})
                if st.get("exited"):
                    out = (
                        base64.b64decode(st.get("out-data", ""))
                        .decode("utf-8", errors="replace")
                        .replace("\r\n", "\n")
                        .strip()
                    )
                    err = (
                        base64.b64decode(st.get("err-data", ""))
                        .decode("utf-8", errors="replace")
                        .replace("\r\n", "\n")
                        .strip()
                    )
                    if err.startswith("#< CLIXML"):
                        err = ""
                    duration_ms = int((time.monotonic() - started) * 1000)
                    return ExecResult(
                        exit_code=int(st.get("exitcode", 0)),
                        stdout=out,
                        stderr=err,
                        duration_ms=duration_ms,
                    )

        raise TimeoutError(f"QGA guest-exec timed out after {timeout_sec}s")

    def write_bytes(self, data: bytes, guest_path: str) -> None:
        with self._connect_synced() as (sock, reader):
            open_req = json.dumps(
                {"execute": "guest-file-open", "arguments": {"path": guest_path, "mode": "wb"}}
            )
            sock.sendall((open_req + "\n").encode("utf-8"))
            handle = json.loads(reader.readline().lstrip("\xff"))["return"]  # type: ignore[attr-defined]
            try:
                for offset in range(0, len(data), self.CHUNK_SIZE):
                    chunk = data[offset : offset + self.CHUNK_SIZE]
                    write_req = json.dumps(
                        {
                            "execute": "guest-file-write",
                            "arguments": {
                                "handle": handle,
                                "buf-b64": base64.b64encode(chunk).decode("ascii"),
                            },
                        }
                    )
                    sock.sendall((write_req + "\n").encode("utf-8"))
                    reader.readline()  # type: ignore[attr-defined]
            finally:
                close_req = json.dumps(
                    {"execute": "guest-file-close", "arguments": {"handle": handle}}
                )
                sock.sendall((close_req + "\n").encode("utf-8"))
                reader.readline()  # type: ignore[attr-defined]

    def read_bytes(self, guest_path: str) -> bytes:
        chunks: list[bytes] = []
        with self._connect_synced() as (sock, reader):
            open_req = json.dumps(
                {"execute": "guest-file-open", "arguments": {"path": guest_path, "mode": "rb"}}
            )
            sock.sendall((open_req + "\n").encode("utf-8"))
            handle = json.loads(reader.readline().lstrip("\xff"))["return"]  # type: ignore[attr-defined]
            try:
                while True:
                    read_req = json.dumps(
                        {
                            "execute": "guest-file-read",
                            "arguments": {"handle": handle, "count": self.CHUNK_SIZE},
                        }
                    )
                    sock.sendall((read_req + "\n").encode("utf-8"))
                    resp = json.loads(reader.readline().lstrip("\xff"))["return"]  # type: ignore[attr-defined]
                    if resp.get("buf-b64"):
                        chunks.append(base64.b64decode(resp["buf-b64"]))
                    if resp.get("eof"):
                        break
            finally:
                close_req = json.dumps(
                    {"execute": "guest-file-close", "arguments": {"handle": handle}}
                )
                sock.sendall((close_req + "\n").encode("utf-8"))
                reader.readline()  # type: ignore[attr-defined]
        return b"".join(chunks)

    def write_file(self, local_path: Path, guest_path: str) -> None:
        self.write_bytes(local_path.read_bytes(), guest_path)

    def read_file(self, guest_path: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(self.read_bytes(guest_path))

    def try_read_bytes(
        self, guest_path: str, *, truncate_after_read: bool = False
    ) -> bytes | None:
        """Attempt to read a guest file via QGA without spawning PowerShell; returns None if missing."""
        chunks: list[bytes] = []
        with self._connect_synced(timeout_sec=10.0) as (sock, reader):
            open_req = json.dumps(
                {"execute": "guest-file-open", "arguments": {"path": guest_path, "mode": "rb"}}
            )
            sock.sendall((open_req + "\n").encode("utf-8"))
            open_resp = json.loads(reader.readline().lstrip("\xff"))  # type: ignore[attr-defined]
            if "return" not in open_resp:
                return None
            handle = open_resp["return"]
            try:
                while True:
                    read_req = json.dumps(
                        {
                            "execute": "guest-file-read",
                            "arguments": {"handle": handle, "count": self.CHUNK_SIZE},
                        }
                    )
                    sock.sendall((read_req + "\n").encode("utf-8"))
                    resp = json.loads(reader.readline().lstrip("\xff"))["return"]  # type: ignore[attr-defined]
                    if resp.get("buf-b64"):
                        chunks.append(base64.b64decode(resp["buf-b64"]))
                    if resp.get("eof"):
                        break
            finally:
                close_req = json.dumps(
                    {"execute": "guest-file-close", "arguments": {"handle": handle}}
                )
                sock.sendall((close_req + "\n").encode("utf-8"))
                reader.readline()  # type: ignore[attr-defined]

            data = b"".join(chunks)
            if truncate_after_read and data:
                trunc_open = json.dumps(
                    {"execute": "guest-file-open", "arguments": {"path": guest_path, "mode": "wb"}}
                )
                sock.sendall((trunc_open + "\n").encode("utf-8"))
                trunc_resp = json.loads(reader.readline().lstrip("\xff"))  # type: ignore[attr-defined]
                if "return" in trunc_resp:
                    trunc_close = json.dumps(
                        {"execute": "guest-file-close", "arguments": {"handle": trunc_resp["return"]}}
                    )
                    sock.sendall((trunc_close + "\n").encode("utf-8"))
                    reader.readline()  # type: ignore[attr-defined]
            return data if data else None

    def sync_guest_clock(self, epoch_ns: int | None = None) -> bool:
        """Synchronize the guest OS clock to the Host clock via QGA guest-set-time."""
        ns = epoch_ns if epoch_ns is not None else time.time_ns()
        try:
            with self._connect_synced(timeout_sec=10.0) as (sock, reader):
                req = json.dumps(
                    {"execute": "guest-set-time", "arguments": {"time": ns}}
                )
                sock.sendall((req + "\n").encode("utf-8"))
                resp = json.loads(reader.readline().lstrip("\xff"))  # type: ignore[attr-defined]
                return "return" in resp
        except Exception:
            return False


class DirectHostControlChannel:
    """Control channel for Windows Direct Mode or local loopback simulation."""

    def __init__(self, root_dir: Path | None = None) -> None:
        self.root_dir = root_dir

    def _map_path(self, guest_path: str) -> Path:
        if self.root_dir is None:
            return Path(guest_path)
        norm = guest_path.replace("\\", "/").lstrip("/")
        if len(norm) >= 2 and norm[1] == ":":
            norm = norm[2:].lstrip("/")
        return self.root_dir / norm

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        started = time.monotonic()
        shell_cmd = (
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
            if os.name == "nt"
            else ["sh", "-c", script]
        )
        res = subprocess.run(
            shell_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return ExecResult(
            exit_code=res.returncode,
            stdout=res.stdout.replace("\r\n", "\n").strip(),
            stderr=res.stderr.replace("\r\n", "\n").strip(),
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    def write_bytes(self, data: bytes, guest_path: str) -> None:
        target = self._map_path(guest_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def read_bytes(self, guest_path: str) -> bytes:
        return self._map_path(guest_path).read_bytes()

    def write_file(self, local_path: Path, guest_path: str) -> None:
        self.write_bytes(local_path.read_bytes(), guest_path)

    def read_file(self, guest_path: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(self.read_bytes(guest_path))

    def try_read_bytes(
        self, guest_path: str, *, truncate_after_read: bool = False
    ) -> bytes | None:
        target = self._map_path(guest_path)
        if not target.is_file():
            return None
        data = target.read_bytes()
        if truncate_after_read and data:
            target.unlink(missing_ok=True)
        return data if data else None

    def sync_guest_clock(self, epoch_ns: int | None = None) -> bool:
        _ = epoch_ns
        return True
