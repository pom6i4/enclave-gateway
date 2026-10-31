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

from enclave_gateway.control.wire import SocketLineReader

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:
    msvcrt = None


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
def _file_lock(lock_path: Path, timeout_sec: float = 30.0) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fp = lock_path.open("a+b")
    acquired = False
    try:
        if not fcntl and not msvcrt:
            raise RuntimeError("No supported interprocess file locking backend")
        if fp.seek(0, 2) == 0:
            fp.write(b"\0")
            fp.flush()
        deadline = time.monotonic() + timeout_sec
        while True:
            try:
                if fcntl is not None:
                    fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    fp.seek(0)
                    msvcrt.locking(fp.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out waiting for control channel lock")
                time.sleep(0.01)
        yield
    finally:
        if acquired and fcntl is not None:
            try:
                fcntl.flock(fp, fcntl.LOCK_UN)
            except OSError:
                pass
        elif acquired and msvcrt is not None:
            fp.seek(0)
            msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
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
        deadline = time.monotonic() + timeout_sec
        if not self._thread_lock.acquire(timeout=max(0.0, timeout_sec)):
            raise TimeoutError("Timed out waiting for control channel thread lock")
        try:
            with _file_lock(self.lock_path, max(0.0, deadline - time.monotonic())):
                with self._open_synced(deadline) as connection:
                    yield connection
        finally:
            self._thread_lock.release()

    @contextmanager
    def _open_synced(self, deadline):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            sock.connect(str(self.socket_path))
            reader = SocketLineReader(sock, deadline)
            sync_id = random.getrandbits(63)
            payload = json.dumps({"execute": "guest-sync-delimited", "arguments": {"id": sync_id}})
            sock.sendall(b"\xff" + (payload + "\n").encode("utf-8"))
            reader.sync_marker()
            while True:
                try:
                    response = json.loads(reader.readline(sync=True))
                except (ValueError, UnicodeError):
                    continue
                if isinstance(response, dict) and type(response.get("return")) is int and response["return"] == sync_id:
                    break
            yield sock, reader

    @staticmethod
    def _request(sock, reader, command: str, arguments: dict | None = None):
        payload = {"execute": command}
        if arguments is not None:
            payload["arguments"] = arguments
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        response = json.loads(reader.readline())
        if not isinstance(response, dict) or "return" not in response:
            raise RuntimeError(f"QGA {command} failed: {response}")
        return response["return"]

    @contextmanager
    def _guest_file(self, sock, reader, guest_path: str, mode: str):
        handle = self._request(sock, reader, "guest-file-open", {"path": guest_path, "mode": mode})
        try:
            yield handle
        finally:
            # A lost connection does not close the guest's handle. Retry cleanup on
            # a freshly synchronized stream, while retaining the original error.
            import sys
            active_error = sys.exc_info()[0] is not None
            try:
                self._request(sock, reader, "guest-file-close", {"handle": handle})
            except Exception:
                try:
                    with self._open_synced(time.monotonic() + 5.0) as (cleanup_sock, cleanup_reader):
                        self._request(cleanup_sock, cleanup_reader, "guest-file-close", {"handle": handle})
                except Exception:
                    if not active_error:
                        raise

    def _write_stream(self, stream, guest_path: str) -> None:
        with self._connect_synced() as (sock, reader):
            with self._guest_file(sock, reader, guest_path, "wb") as handle:
                while chunk := stream.read(self.CHUNK_SIZE):
                    offset = 0
                    while offset < len(chunk):
                        result = self._request(sock, reader, "guest-file-write", {
                            "handle": handle, "buf-b64": base64.b64encode(chunk[offset:]).decode("ascii")})
                        count = result.get("count", 0)
                        if type(count) is not int or not 0 < count <= len(chunk) - offset:
                            raise OSError("QGA file write made no progress or returned invalid count")
                        offset += count
                self._request(sock, reader, "guest-file-flush", {"handle": handle})

    def _read_stream(self, stream, guest_path: str) -> None:
        with self._connect_synced() as (sock, reader):
            with self._guest_file(sock, reader, guest_path, "rb") as handle:
                while True:
                    result = self._request(sock, reader, "guest-file-read", {"handle": handle, "count": self.CHUNK_SIZE})
                    data = base64.b64decode(result.get("buf-b64", ""), validate=True)
                    if len(data) != result.get("count"):
                        raise OSError("QGA file read count mismatch")
                    stream.write(data)
                    if result.get("eof"):
                        break
                    if not data:
                        raise OSError("QGA file read made no progress")

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        started = time.monotonic()
        deadline = started + timeout_sec
        encoded_cmd = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        with self._connect_synced(min(timeout_sec, 30.0)) as (sock, reader):
            result = self._request(sock, reader, "guest-exec", {
                "path": "powershell.exe",
                "arg": ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_cmd],
                "capture-output": True,
            })
            pid = result["pid"]
        delay = 0.015
        while time.monotonic() < deadline:
            time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
            delay = min(0.15, delay * 1.6)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            with self._connect_synced(min(remaining, 10.0)) as (sock, reader):
                status = self._request(sock, reader, "guest-exec-status", {"pid": pid})
            if status.get("exited"):
                def decode(key):
                    return base64.b64decode(status.get(key, ""), validate=True).decode("utf-8", errors="replace").replace("\r\n", "\n")
                return ExecResult(
                    int(status.get("exitcode", 128 + int(status.get("signal", 0)))),
                    decode("out-data"), decode("err-data"),
                    int((time.monotonic() - started) * 1000),
                )
        raise TimeoutError(f"QGA guest-exec timed out after {timeout_sec}s; guest process may still be running")

    def write_bytes(self, data: bytes, guest_path: str) -> None:
        import io
        self._write_stream(io.BytesIO(data), guest_path)

    def read_bytes(self, guest_path: str) -> bytes:
        import io
        stream = io.BytesIO()
        self._read_stream(stream, guest_path)
        return stream.getvalue()

    def publish_bytes(self, data: bytes, guest_path: str) -> None:
        from enclave_gateway.security.quoting import ps_quote
        tmp_path = guest_path + ".tmp"
        self.write_bytes(data, tmp_path)
        result = self.exec_powershell(
            f"$ErrorActionPreference='Stop'; Move-Item -LiteralPath {ps_quote(tmp_path)} -Destination {ps_quote(guest_path)} -Force"
        )
        if result.exit_code:
            raise OSError("Failed to publish guest file atomically")

    def write_file(self, local_path: Path, guest_path: str) -> None:
        with local_path.open("rb") as stream:
            self._write_stream(stream, guest_path)

    def read_file(self, guest_path: str, local_path: Path) -> None:
        from tempfile import NamedTemporaryFile
        local_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = None
        try:
            with NamedTemporaryFile(dir=local_path.parent, delete=False) as stream:
                tmp = Path(stream.name)
                self._read_stream(stream, guest_path)
            tmp.replace(local_path)
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)

    def consume_file(self, guest_path: str) -> None:
        self.write_bytes(b"", guest_path)

    def try_read_bytes(self, guest_path: str, *, truncate_after_read: bool = False) -> bytes | None:
        # Publication uses rename; never consume or truncate an incomplete envelope.
        # Missing files are normal while polling. Other QGA failures remain visible.
        try:
            data = self.read_bytes(guest_path)
        except RuntimeError as exc:
            if any(marker in str(exc).lower() for marker in ("no such file", "cannot find", "not found")):
                return None
            raise
        if truncate_after_read and data:
            self.write_bytes(b"", guest_path)
        return data or None

    def sync_guest_clock(self, epoch_ns: int | None = None) -> bool:
        ns = epoch_ns if epoch_ns is not None else time.time_ns()
        try:
            with self._connect_synced(10.0) as (sock, reader):
                self._request(sock, reader, "guest-set-time", {"time": ns})
            return True
        except (OSError, RuntimeError, ValueError):
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
        root = self.root_dir.resolve()
        target = (root / norm).resolve()
        if not target.is_relative_to(root):
            raise ValueError("Guest path escapes direct control root")
        return target

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

    def publish_bytes(self, data: bytes, guest_path: str) -> None:
        from tempfile import NamedTemporaryFile
        target = self._map_path(guest_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=target.parent, delete=False) as stream:
            tmp = Path(stream.name)
            stream.write(data)
        try:
            tmp.replace(target)
        finally:
            tmp.unlink(missing_ok=True)

    def read_bytes(self, guest_path: str) -> bytes:
        return self._map_path(guest_path).read_bytes()

    def write_file(self, local_path: Path, guest_path: str) -> None:
        self.write_bytes(local_path.read_bytes(), guest_path)

    def read_file(self, guest_path: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(self.read_bytes(guest_path))

    def compare_replace_file(self, staged_path: str, guest_path: str, expected_sha: str) -> None:
        import hashlib
        target = self._map_path(guest_path)
        staged = self._map_path(staged_path)
        with _file_lock(Path(f"{target}.egw-lock")):
            if hashlib.sha256(target.read_bytes()).hexdigest() != expected_sha:
                raise RuntimeError("Patch conflict: destination changed")
            staged.replace(target)

    def consume_file(self, guest_path: str) -> None:
        self._map_path(guest_path).unlink(missing_ok=True)

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
