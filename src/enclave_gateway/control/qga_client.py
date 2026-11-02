"""QEMU Guest Agent (QGA) client with UNIX socket locking and chunked file I/O."""

from __future__ import annotations

import base64
import errno
import json
import os
import random
import socket
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol

from enclave_gateway.control.wire import SocketLineReader
from enclave_gateway.operations.context import budget, checkpoint, current, mark_dispatched, timed, owned_cleanup

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
    tx_id: str = ""
    timings_ms: dict[str, int] = field(default_factory=dict)


class ControlChannel(Protocol):
    """Protocol for executing commands and transferring files on the Appliance."""

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult: ...

    def write_file(self, local_path: Path, guest_path: str) -> None: ...

    def read_file(self, guest_path: str, local_path: Path) -> None: ...

    def write_bytes(self, data: bytes, guest_path: str) -> None: ...

    def read_bytes(self, guest_path: str) -> bytes: ...


@contextmanager
def _os_file_lock(lock_path: Path, timeout_sec: float = 30.0) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fp = lock_path.open("a+b")
    acquired = False
    try:
        if not fcntl and not msvcrt:
            raise RuntimeError("No supported interprocess file locking backend")
        deadline = time.monotonic() + timeout_sec
        while True:
            checkpoint("control.file_lock")
            try:
                if fcntl is not None:
                    fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    fp.seek(0)
                    msvcrt.locking(fp.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
                break
            except OSError as error:
                if error.errno not in (errno.EACCES,errno.EAGAIN,errno.EDEADLK,errno.EINTR):raise
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out waiting for control channel lock")
                time.sleep(0.01)
        # Both OS backends can lock an empty file. Initialize its sentinel only
        # after acquiring the same handle's lock, avoiding a first-open race.
        if fp.seek(0, 2) == 0:
            fp.write(b"\0")
            fp.flush()
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


_thread_file_gates={}
_thread_file_gates_guard=threading.Lock()


@contextmanager
def _file_lock(lock_path: Path, timeout_sec: float = 30.0) -> Iterator[None]:
    if os.name!='nt':
        with _os_file_lock(lock_path,timeout_sec):yield
        return
    # Windows byte-range locks reject concurrent handles within one process.
    # Queue local contenders before OS locking instead of letting hot writers
    # repeatedly win the polling race and starve other recorder instances.
    key=os.path.normcase(os.path.abspath(lock_path));deadline=time.monotonic()+timeout_sec
    with _thread_file_gates_guard:
        gate=_thread_file_gates.get(key)
        if gate is None:
            gate={'condition':threading.Condition(),'waiters':deque(),'users':0};_thread_file_gates[key]=gate
        gate['users']+=1
    token=object();condition=gate['condition']
    try:
        with condition:
            gate['waiters'].append(token)
            while gate['waiters'][0] is not token:
                checkpoint('control.file_lock')
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('Timed out waiting for control channel lock')
                condition.wait(min(.05,remaining))
        with _os_file_lock(lock_path,max(0,deadline-time.monotonic())):yield
    finally:
        with condition:
            if token in gate['waiters']:gate['waiters'].remove(token)
            condition.notify_all()
        with _thread_file_gates_guard:
            gate['users']-=1
            if not gate['users']:del _thread_file_gates[key]


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
        timeout_sec = budget(timeout_sec, "qga.lock")
        deadline = time.monotonic() + timeout_sec
        while True:
            checkpoint("qga.lock")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for control channel thread lock")
            if self._thread_lock.acquire(timeout=min(0.1, remaining)):
                break
        try:
            with _file_lock(self.lock_path, max(0.0, deadline - time.monotonic())):
                with self._open_synced(deadline) as connection:
                    yield connection
        finally:
            self._thread_lock.release()

    @contextmanager
    def _open_synced(self, deadline):
        from enclave_gateway.control.local_socket import connect_local
        with connect_local(self.socket_path,max(0.001,deadline-time.monotonic())) as sock:
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
        checkpoint("qga." + command)
        context = current()
        if context:
            sock.settimeout(context.remaining())
        if command == "guest-exec":
            mark_dispatched()
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
                    with owned_cleanup(), self._open_synced(time.monotonic() + 2.0) as (cleanup_sock, cleanup_reader):
                        self._request(cleanup_sock, cleanup_reader, "guest-file-close", {"handle": handle})
                except Exception:
                    if not active_error:
                        raise

    def _write_stream(self, stream, guest_path: str, *, timeout_sec: float = 30.0) -> None:
        with self._connect_synced(timeout_sec) as (sock, reader):
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

    def _read_stream(self, stream, guest_path: str, *, timeout_sec: float = 30.0) -> None:
        with self._connect_synced(timeout_sec) as (sock, reader):
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

    def shutdown_guest(self,timeout_sec=10.0):
        """Request guest OS shutdown; this command intentionally has no response."""
        with self._connect_synced(timeout_sec) as (sock,reader):
            info=self._request(sock,reader,'guest-info')
            if not any(item.get('name')=='guest-shutdown' and item.get('enabled') for item in info['supported_commands']):
                raise RuntimeError('Guest shutdown is unavailable')
            sock.sendall((json.dumps({'execute':'guest-shutdown','arguments':{'mode':'powerdown'}})+'\n').encode())

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        encoded_cmd=base64.b64encode(script.encode('utf-16le')).decode('ascii')
        return self.exec_guest('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',encoded_cmd],timeout_sec=timeout_sec)

    def exec_guest(self,path: str,arguments=(),*,input_data: bytes | None=None,timeout_sec: float=120.0) -> ExecResult:
        if not isinstance(arguments,(list,tuple)) or not isinstance(path,str) or not path or '\0' in path or any(not isinstance(item,str) or '\0' in item for item in arguments):
            raise ValueError('Invalid guest command')
        timeout_sec=budget(timeout_sec,'qga.exec');started=time.monotonic();deadline=started+timeout_sec
        request={'path':path,'arg':list(arguments),'capture-output':True}
        if input_data is not None:request['input-data']=base64.b64encode(input_data).decode('ascii')
        with self._connect_synced(min(timeout_sec,30.0)) as (sock,reader):
            result=self._request(sock,reader,'guest-exec',request)
            pid=result['pid']
        delay = 0.015
        while time.monotonic() < deadline:
            checkpoint("qga.exec_status")
            time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
            delay = min(0.15, delay * 1.6)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                with self._connect_synced(min(remaining, 10.0)) as (sock, reader):
                    status = self._request(sock, reader, "guest-exec-status", {"pid": pid})
            except (TimeoutError, ConnectionError):
                # Reconnecting may temporarily fail while the guest is busy.
                # Retry only this read-only lookup of an acknowledged process;
                # never resubmit guest-exec after a lost dispatch acknowledgement.
                continue
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

    def write_file(self, local_path: Path, guest_path: str, *, timeout_sec: float = 30.0) -> None:
        with local_path.open("rb") as stream:
            self._write_stream(stream, guest_path, timeout_sec=timeout_sec)

    def read_file(self, guest_path: str, local_path: Path, *, timeout_sec: float = 30.0) -> None:
        from tempfile import NamedTemporaryFile
        local_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = None
        try:
            with NamedTemporaryFile(dir=local_path.parent, delete=False) as stream:
                tmp = Path(stream.name)
                self._read_stream(stream, guest_path, timeout_sec=timeout_sec)
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

    def __init__(self, root_dir: Path | None = None, *, runtime_helper_path=r'%LOCALAPPDATA%\EnclaveGateway\bin\egw-runtime.exe', trusted_signers=(), require_signed=True, use_native_runtime=True) -> None:
        self.root_dir = root_dir
        self.runtime_helper_path=runtime_helper_path
        self.trusted_signers=trusted_signers
        self.require_signed=require_signed
        self.use_native_runtime=use_native_runtime

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
            else ["sh", "-c", 'eval "$(cat)"']
        )
        request_input=script if os.name!='nt' else None
        if os.name=='nt':
            bootstrap='[Console]::InputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'
            shell_cmd=shell_cmd[:-2]+['-Command',bootstrap]
            request_input=script
        if os.name=='nt' and self.use_native_runtime:
            from enclave_gateway.security.native import verified_runtime
            helper=verified_runtime(self.runtime_helper_path,self.trusted_signers,self.require_signed)
            shell_cmd[0]=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
            request_input=json.dumps({'command':shell_cmd,'stdin_b64':base64.b64encode(script.encode()).decode(),'timeout_ms':max(1,int(budget(timeout_sec)*1000))})
            shell_cmd=[helper,'run']
        timeout_sec = budget(timeout_sec, "direct.exec")
        deadline = time.monotonic() + timeout_sec
        mark_dispatched()
        with subprocess.Popen(shell_cmd, stdin=subprocess.PIPE if request_input is not None else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              start_new_session=(os.name != "nt")) as process:
            try:
                while True:
                    checkpoint("direct.exec")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Direct command deadline expired")
                    try:
                        output, error = process.communicate(input=request_input,timeout=min(0.1, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        request_input=None
                        continue
            except BaseException:
                if process.poll() is None:
                    if os.name != "nt":
                        import signal
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    else:
                        process.kill()
                process.communicate()
                raise
        res = subprocess.CompletedProcess(shell_cmd, process.returncode, output, error)
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
        from enclave_gateway.control.published import read_shared
        return read_shared(self._map_path(guest_path))

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
        from enclave_gateway.control.published import try_read_published
        data = try_read_published(target)
        if truncate_after_read and data:
            target.unlink(missing_ok=True)
        return data if data else None

    def sync_guest_clock(self, epoch_ns: int | None = None) -> bool:
        _ = epoch_ns
        return True
