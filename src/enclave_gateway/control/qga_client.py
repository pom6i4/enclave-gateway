"""QEMU Guest Agent (QGA) client with UNIX socket locking and chunked file I/O."""

from __future__ import annotations

import base64
import errno
import json
import os
import random
import re
import secrets
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
from enclave_gateway.operations.context import budget, checkpoint, current, mark_dispatched, timed, owned_cleanup, OperationError

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


class QgaCommandError(RuntimeError):
    """Keep command identity so read-only polling can distinguish open failures."""
    def __init__(self, command, response):
        self.command = command
        self.response = response
        super().__init__(f"QGA {command} failed: {response}")


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
    # Queue contenders on every platform before OS locking. A hot QGA poller
    # must not repeatedly jump ahead of a caller publishing or erasing a result.
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
    _SYNC_ATTEMPT_SEC = 1.0

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
        self._unreaped_pids: set[int] = set()
        self._exec_state_lock = threading.Lock()
        self._active_pids: set[int] = set()
        self._reap_cursor = 0

    @contextmanager
    def _connect_synced(self, timeout_sec: float = 30.0) -> Iterator[tuple[socket.socket, object]]:
        timeout_sec = budget(timeout_sec, "qga.lock")
        deadline = time.monotonic() + timeout_sec
        with _file_lock(self.lock_path, max(0.0, deadline-time.monotonic())):
            with self._open_synced(deadline) as connection:
                yield connection

    @contextmanager
    def _open_synced(self, deadline):
        from enclave_gateway.control.local_socket import connect_local
        while True:
            checkpoint("control.connect")
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('Control channel deadline expired')
            try:
                connection = connect_local(self.socket_path, min(self._SYNC_ATTEMPT_SEC,remaining))
            except (TimeoutError,ConnectionError):
                time.sleep(min(.015,max(0,deadline-time.monotonic())))
                continue
            except OSError as error:
                raise OperationError("qga_unavailable", "control.connect", node="@appliance",
                                     message="Cannot connect to QEMU Guest Agent. Check that the Appliance is running and its QGA endpoint is accessible.") from error
            with connection as sock:
                reader = SocketLineReader(sock, min(deadline,time.monotonic()+self._SYNC_ATTEMPT_SEC))
                sync_id = random.getrandbits(63)
                payload = json.dumps({"execute": "guest-sync-delimited", "arguments": {"id": sync_id}})
                try:
                    sock.sendall(b"\xff" + (payload + "\n").encode("utf-8"))
                    reader.sync_marker()
                    while True:
                        checkpoint('control.sync')
                        if time.monotonic()>=reader.deadline:raise TimeoutError('Control channel deadline expired')
                        try:
                            response = json.loads(reader.readline(sync=True))
                        except (ValueError, UnicodeError):
                            continue
                        if isinstance(response, dict) and type(response.get("return")) is int and response["return"] == sync_id:
                            break
                except (TimeoutError,ConnectionError):
                    pass
                else:
                    # Only synchronization is retried. Exceptions after yield
                    # must reach the caller without replaying any QGA command.
                    reader.deadline=deadline
                    yield sock, reader
                    return
            time.sleep(min(.015,max(0,deadline-time.monotonic())))

    def wait_until_ready(self, timeout_sec: float) -> None:
        deadline = time.monotonic() + budget(timeout_sec, "control.connect")
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                with self._connect_synced(min(2.0, remaining)):
                    return
            except OperationError as error:
                if error.code != "qga_unavailable":
                    raise
            except (TimeoutError, ConnectionError):
                pass
            time.sleep(max(0, min(.5, deadline - time.monotonic())))
        raise OperationError("qga_unavailable", "control.connect", node="@appliance",
                             message="Appliance started, but QEMU Guest Agent did not become ready. Check the guest agent service and run egw heal again.")

    @staticmethod
    def _request(sock, reader, command: str, arguments: dict | None = None):
        payload = {"execute": command}
        if arguments is not None:
            payload["arguments"] = arguments
        checkpoint("qga." + command)
        remaining=reader.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('Control channel deadline expired')
        sock.settimeout(budget(remaining,'qga.'+command))
        if command == "guest-exec":
            mark_dispatched()
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        response = json.loads(reader.readline())
        if not isinstance(response, dict) or "return" not in response:
            raise QgaCommandError(command, response)
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
        request_data=getattr(script,"request_data",None)
        prefix='EGW_QGA:'+secrets.token_hex(16)+'\n'
        source=("$ProgressPreference='SilentlyContinue';\n"
                "[Console]::Out.WriteLine('"+prefix.rstrip('\n')+"');[Console]::Out.Flush();\n")
        preamble="[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);"
        if request_data:preamble+="$RequestData=[Console]::In.ReadLine()|ConvertFrom-Json;"
        # Parse the caller's source only after publishing the marker, so a
        # syntax error is still an identifiable result with its real stderr.
        # An invoked scriptblock resets $? on return. Preserve the caller's
        # final failure inside that block before it returns to the bootstrap.
        tail="+[char]10+'if(-not $?){exit 1}'"
        encoded_source=base64.b64encode(script.encode('utf-8')).decode('ascii')
        command=(source+(preamble+'\n' if request_data else '')+
                 "& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded_source+"'))"+tail+"))")
        encoded_cmd=base64.b64encode(command.encode('utf-16le')).decode('ascii')
        data=(json.dumps(request_data)+'\n').encode() if request_data else b''
        # Windows CreateProcess limits the complete command line to 32767 UTF-16
        # characters. Keep argv bounded; QGA can carry the source through stdin.
        if len(encoded_cmd)>24000:
            bootstrap=source+preamble+"& ([scriptblock]::Create([Console]::In.ReadToEnd()"+tail+"))"
            encoded_cmd=base64.b64encode(bootstrap.encode('utf-16le')).decode('ascii')
            data+=script.encode('utf-8')
        return self.exec_guest('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',encoded_cmd],
                               input_data=data or None,timeout_sec=timeout_sec,_stdout_prefix=prefix)

    @contextmanager
    def _exec_state(self, deadline):
        while not self._exec_state_lock.acquire(timeout=max(0, min(.05, deadline-time.monotonic()))):
            checkpoint('qga.exec_state')
            if time.monotonic() >= deadline:
                raise TimeoutError('Timed out waiting for QGA process observation')
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError('Timed out waiting for QGA process observation')
            yield
        finally:
            self._exec_state_lock.release()

    def _reap_unreaped(self, deadline):
        """One bounded observation per orphan; never wait for or restart it.

        The caller holds the process registry lock through the next launch, so
        maintenance cannot consume the result of a concurrently registered PID.
        """
        pending=sorted(self._unreaped_pids-self._active_pids)
        if not pending:return
        start=self._reap_cursor%len(pending)
        self._reap_cursor=start+8
        pending=(pending[start:]+pending[:start])[:8]
        try:
            with self._connect_synced(min(.25,max(.001,deadline-time.monotonic()))) as (sock,reader):
                for pid in pending:
                    try:
                        self._request(sock,reader,'guest-exec-status',{'pid':pid})
                    except QgaCommandError as error:
                        # QGA uses GenericError for both a missing PID and other
                        # failures. Retain the record unless absence is explicit.
                        detail=error.response.get('error') if isinstance(error.response,dict) else None
                        if not isinstance(detail,dict):continue
                        description=detail.get('desc')
                        if not isinstance(description,str):continue
                        description=description.strip()
                        missing=re.fullmatch(r'PID ([0-9]{1,20}|lld) does not exist',description)
                        # Windows builds can emit the literal format token lld.
                        # A numeric error must refer to the PID being observed.
                        absent=(description in ('PID does not exist',"Parameter 'pid' expects invalid pid") or
                                (missing and (missing[1]=='lld' or int(missing[1])==pid)))
                        if detail.get('class') in ('GenericError','InvalidParameterValue') and absent:
                            self._unreaped_pids.discard(pid)
                        continue
                    # Retain the PID until QGA confirms absence: more than one
                    # orphan can have the same recycled Windows identifier.
        except (TimeoutError,ConnectionError):
            pass

    def exec_guest(self,path: str,arguments=(),*,input_data: bytes | None=None,timeout_sec: float=120.0,
                   _stdout_prefix: str | None=None) -> ExecResult:
        if not isinstance(arguments,(list,tuple)) or not isinstance(path,str) or not path or '\0' in path or any(not isinstance(item,str) or '\0' in item for item in arguments):
            raise ValueError('Invalid guest command')
        timeout_sec=budget(timeout_sec,'qga.exec');started=time.monotonic();deadline=started+timeout_sec
        request={'path':path,'arg':list(arguments),'capture-output':True}
        if input_data is not None:request['input-data']=base64.b64encode(input_data).decode('ascii')
        with self._exec_state(deadline):
            self._reap_unreaped(deadline)
            remaining=deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('QGA execution budget expired before launch')
            with self._connect_synced(min(30.0,remaining)) as (sock,reader):
                result=self._request(sock,reader,'guest-exec',request)
                pid=result['pid']
            if pid in self._active_pids or (pid in self._unreaped_pids and _stdout_prefix is None):
                self._unreaped_pids.add(pid)
                raise OperationError('qga_pid_collision','qga.exec',node='@appliance',indeterminate=True,
                                     message='QGA reused an unresolved process ID; command result cannot be identified. No command was replayed.')
            self._active_pids.add(pid)
        try:
            return self._wait_guest(pid,started,deadline,timeout_sec,_stdout_prefix)
        except BaseException:
            with self._exec_state_lock:self._unreaped_pids.add(pid)
            raise
        finally:
            with self._exec_state_lock:self._active_pids.discard(pid)

    def _wait_guest(self,pid,started,deadline,timeout_sec,stdout_prefix):
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
                stdout=decode('out-data')
                if stdout_prefix is not None:
                    # guest-exec-status removes the oldest matching PID. A
                    # timed-out predecessor can therefore exit before our new
                    # process. Consume it, then observe this PID again; never
                    # replay guest-exec or return an unbound exit code/output.
                    if not stdout.startswith(stdout_prefix):continue
                    stdout=stdout[len(stdout_prefix):]
                return ExecResult(
                    int(status.get("exitcode", 128 + int(status.get("signal", 0)))),
                    stdout, decode("err-data"),
                    int((time.monotonic() - started) * 1000),
                )
        raise TimeoutError(f"QGA guest-exec timed out after {timeout_sec}s; guest process may still be running")

    def write_bytes(self, data: bytes, guest_path: str) -> None:
        import io
        self._write_stream(io.BytesIO(data), guest_path)

    def read_bytes(self, guest_path: str, *, timeout_sec: float = 30.0) -> bytes:
        import io
        stream = io.BytesIO()
        self._read_stream(stream, guest_path, timeout_sec=timeout_sec)
        return stream.getvalue()

    @contextmanager
    def read_session(self, timeout_sec: float = 5.0):
        """Bounded read-only snapshot group with one QGA synchronization.

        File handles still close after each read. The control lock is held only
        for this short group, never while waiting for remote command execution.
        """
        with self._connect_synced(timeout_sec) as (sock, reader):
            def read(path, *, truncate_after_read=False):
                if truncate_after_read:
                    raise ValueError("Snapshot sessions are read-only")
                try:
                    with self._guest_file(sock, reader, path, "rb") as handle:
                        snapshot = bytearray()
                        while True:
                            count = min(self.CHUNK_SIZE, self.CHUNK_SIZE-len(snapshot)+1)
                            result = self._request(sock, reader, "guest-file-read", {"handle": handle, "count": count})
                            data = base64.b64decode(result.get("buf-b64", ""), validate=True)
                            if type(result.get("count")) is not int or len(data) != result["count"] or len(data) > count:
                                raise OSError("Invalid snapshot read count")
                            snapshot.extend(data)
                            if len(snapshot) > self.CHUNK_SIZE:
                                raise ValueError("Worker snapshot exceeds size limit")
                            if result.get("eof"):
                                return bytes(snapshot) or None
                            # Windows agents may acknowledge a short read without
                            # EOF; consume the following read, without a new sync.
                            if not data:
                                raise OSError("Snapshot read made no progress")
                except QgaCommandError as error:
                    if error.command == "guest-file-open" and any(
                        token in str(error).lower() for token in ("no such file", "cannot find", "not found")
                    ):
                        return None
                    raise
            yield read

    def _stream_read_on_connection(self, sock, reader, path, offset, count):
        from enclave_gateway.transports.stream_frames import MAX_FRAME
        if type(offset) is not int or offset < 0 or not 1 <= count <= MAX_FRAME:
            raise ValueError("Invalid stream read range")
        output = bytearray()
        with self._guest_file(sock, reader, path, "rb") as handle:
            if offset:
                self._request(sock, reader, "guest-file-seek", {"handle": handle, "offset": offset, "whence": 0})
            while len(output) < count:
                chunk = min(self.CHUNK_SIZE, count - len(output))
                result = self._request(sock, reader, "guest-file-read", {"handle": handle, "count": chunk})
                data = base64.b64decode(result.get("buf-b64", ""), validate=True)
                if type(result.get("count")) is not int or len(data) != result["count"] or len(data) > chunk:
                    raise OSError("Invalid stream read count")
                output.extend(data)
                if not data or result.get("eof") or len(data) < chunk:
                    break
        return bytes(output)

    def stream_read(self, path: str, offset: int, count: int = 65536, *, timeout_sec=30.0) -> bytes:
        with self._connect_synced(timeout_sec) as (sock, reader):
            return self._stream_read_on_connection(sock, reader, path, offset, count)

    def stream_read_committed(self, path, offset, validate, *, count=65536, timeout_sec=30.0):
        """Read, validate, then erase acknowledged spans without another sync.

        The callback performs no control-channel IO. Empty/incomplete and legacy
        delivery markers return no spans. After validation only pending erasure
        is retried; the validator and the worker request are never replayed.
        """
        pending=[]
        try:
            with self._connect_synced(timeout_sec) as (sock, reader):
                data=self._stream_read_on_connection(sock, reader, path, offset, count)
                spans=validate(data)
                if spans:
                    pending=self._validate_stream_spans(spans)
                    # The short observation budget ends at validation. Erasure
                    # has its own bounded budget within the operation deadline.
                    if reader is not None:reader.deadline=time.monotonic()+budget(5,'vfs.erase')
                    with timed('vfs.erase'):self._erase_stream_on_connection(sock,reader,pending)
        except Exception as error:
            if not pending:raise
            if isinstance(error,OperationError) and error.code in ('cancelled','deadline_exceeded'):raise
            if not (isinstance(error,(TimeoutError,ConnectionError)) or
                    isinstance(error,QgaCommandError) and error.command=='guest-file-open'):
                raise OperationError('worker_result_cleanup_failed','vfs.erase',indeterminate=True) from error
        if pending:
            # An unrelated reader may briefly prevent write-open. Release the
            # channel and retry only remaining zeroing, never response parsing.
            try:
                with timed('vfs.erase'):self.stream_erase_many(pending)
            except Exception as error:
                if isinstance(error,OperationError) and error.code in ('cancelled','deadline_exceeded'):raise
                raise OperationError('worker_result_cleanup_failed','vfs.erase',indeterminate=True) from error
        return data

    def stream_slot_lock(self, path, timeout_sec):
        lock = Path(str(self.socket_path.resolve()) + ".stream-upload.lock")
        return _file_lock(lock, timeout_sec)

    def stream_fill_slot(self, path, data):
        from enclave_gateway.transports.stream_frames import upload_slot_data
        data = upload_slot_data(data)
        with self._connect_synced() as (sock, reader):
            marker = self._stream_read_on_connection(sock, reader, path, 0, 1)
            if marker != b"\0":
                raise OperationError("upload_slot_unavailable", "vfs.publish",
                                     message="The upload slot holds an unacknowledged block. Reconcile it and restart the worker.")
            with self._guest_file(sock, reader, path, "r+b") as handle:
                for start in range(0, len(data), self.CHUNK_SIZE):
                    chunk = data[start:start+self.CHUNK_SIZE]
                    result = self._request(sock, reader, "guest-file-write",
                                           {"handle": handle, "buf-b64": base64.b64encode(chunk).decode()})
                    if result.get("count") != len(chunk):
                        raise OSError("Short upload slot write")
                self._request(sock, reader, "guest-file-flush", {"handle": handle})

    def stream_append(self, path: str, data: bytes, *, limit: int | None = None) -> int:
        from enclave_gateway.transports.stream_frames import MAX_FRAME, MAX_STREAM, request_block
        limit = MAX_STREAM if limit is None else limit
        if type(limit) is not int or not 1 <= limit <= MAX_STREAM:
            raise ValueError("Invalid stream capacity")
        if not 0 < len(data) <= MAX_FRAME:
            raise ValueError("Invalid stream frame size")
        # Canonical endpoint lock serializes producers across profiles and client
        # instances. Hold it through flush/close, not merely one buffered fwrite.
        lock = Path(str(self.socket_path.resolve()) + ".stream-producer.lock")
        with _file_lock(lock), self._connect_synced() as (sock, reader):
            with self._guest_file(sock, reader, path, "r+b") as handle:
                result = self._request(sock, reader, "guest-file-seek", {"handle": handle, "offset": 0, "whence": 2})
                position, data = request_block(data, int(result["position"]), limit)
                for start in range(0, len(data), self.CHUNK_SIZE):
                    chunk = data[start:start+self.CHUNK_SIZE]
                    result = self._request(sock, reader, "guest-file-write", {"handle": handle, "buf-b64": base64.b64encode(chunk).decode()})
                    # Never retry a partial publication. Caller must reconcile it;
                    # a later complete frame is independently delimited and hashed.
                    if result.get("count") != len(chunk):
                        raise OSError("Short stream publication; command outcome is indeterminate")
                self._request(sock, reader, "guest-file-flush", {"handle": handle})
                return position

    @staticmethod
    def _validate_stream_spans(spans):
        from enclave_gateway.transports.stream_frames import MAX_FRAME, MAX_STREAM
        spans=list(spans)
        if not 1 <= len(spans) <= 2:raise ValueError("Expected one or two stream spans")
        for path, offset, count in spans:
            if type(offset) is not int or type(count) is not int or offset < 0 or not 0 < count <= MAX_FRAME or offset+count > MAX_STREAM:
                raise ValueError("Invalid stream erasure range")
        return spans

    def _erase_stream_on_connection(self,sock,reader,remaining):
        while remaining:
            path,offset,count=remaining[0]
            with self._guest_file(sock,reader,path,"r+b") as handle:
                if offset:self._request(sock,reader,"guest-file-seek",{"handle":handle,"offset":offset,"whence":0})
                left=count
                while left:
                    chunk=bytes(min(left,self.CHUNK_SIZE))
                    result=self._request(sock,reader,"guest-file-write",{"handle":handle,"buf-b64":base64.b64encode(chunk).decode()})
                    wrote=result.get('count')
                    if type(wrote) is not int or not 0<wrote<=len(chunk):raise OSError('Stream erasure made no progress')
                    left-=wrote
                self._request(sock,reader,'guest-file-flush',{'handle':handle})
            remaining.pop(0)

    def stream_erase(self, path: str, offset: int, count: int) -> None:
        self.stream_erase_many([(path,offset,count)])

    def stream_erase_many(self, spans) -> None:
        remaining=self._validate_stream_spans(spans)
        deadline=time.monotonic()+budget(5,'vfs.stream_erase')
        while remaining:
            try:
                left=deadline-time.monotonic()
                if left<=0:raise TimeoutError('Stream erasure deadline expired')
                with self._connect_synced(min(3,left)) as(sock,reader):self._erase_stream_on_connection(sock,reader,remaining)
            except (TimeoutError,ConnectionError,QgaCommandError) as error:
                if isinstance(error,QgaCommandError) and error.command!='guest-file-open':raise
                if time.monotonic()>=deadline:raise
                checkpoint('vfs.stream_erase');time.sleep(.005)

    def publish_bytes(self, data: bytes, guest_path: str) -> None:
        from enclave_gateway.security.quoting import ps_quote
        tmp_path = guest_path + ".tmp"
        self.write_bytes(data, tmp_path)
        script=f"$ErrorActionPreference='Stop'; Move-Item -LiteralPath {ps_quote(tmp_path)} -Destination {ps_quote(guest_path)} -Force\n"
        # Failure of this advisory index must never replay an already published request.
        script+="$hintTarget="+ps_quote(guest_path)+r'''
$name=[IO.Path]::GetFileName($hintTarget)
if($name -match '^(req|cancel)_[A-Za-z0-9_-]{1,128}\.json$'){
 $hintLock=$null;$hintTmp=$null
 try{
  $root=[IO.Path]::GetDirectoryName($hintTarget);$index=Join-Path $root 'request_index.json'
  $timer=[Diagnostics.Stopwatch]::StartNew()
  while(-not $hintLock -and $timer.ElapsedMilliseconds -lt 500){
   try{$hintLock=[IO.File]::Open((Join-Path $root '.request-index.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{Start-Sleep -Milliseconds 5}
  }
  if($hintLock){
   $files=@()
   if([IO.File]::Exists($index) -and ([IO.FileInfo]$index).Length -le 65536){
    try{$old=[IO.File]::ReadAllText($index)|ConvertFrom-Json;$files=@($old.files|Where-Object {$_ -is [string] -and $_ -match '^(req|cancel)_[A-Za-z0-9_-]{1,128}\.json$' -and $_ -cne $name}|Select-Object -Last 127)}catch{}
   }
   $files+=,$name;$token=[Guid]::NewGuid().ToString('N');$hintTmp=$index+'.'+$token+'.tmp'
   [IO.File]::WriteAllText($hintTmp,(@{revision=1;token=$token;files=@($files)}|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
   if([IO.File]::Exists($index)){[IO.File]::Replace($hintTmp,$index,[NullString]::Value)}else{[IO.File]::Move($hintTmp,$index)}
  }
 }catch{}finally{if($hintLock){$hintLock.Dispose()};if($hintTmp -and [IO.File]::Exists($hintTmp)){try{[IO.File]::Delete($hintTmp)}catch{}}}
}
'''
        result = self.exec_powershell(script)
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

    def try_read_bytes(self, guest_path: str, *, truncate_after_read: bool = False, timeout_sec: float = 30.0) -> bytes | None:
        # Publication uses rename; never consume or truncate an incomplete envelope.
        # Missing files are normal while polling. Other QGA failures remain visible.
        try:
            data = self.read_bytes(guest_path,timeout_sec=timeout_sec)
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

    def exec_guest(self, path, arguments=(), *, input_data=None, timeout_sec=120.0):
        if os.name != 'nt' or not Path(path).is_absolute():
            raise ValueError('Native guest execution requires an absolute Windows application path')
        started=time.monotonic()
        mark_dispatched()
        result=subprocess.run([path,*arguments],input=input_data,capture_output=True,timeout=budget(timeout_sec,'direct.native'))
        return ExecResult(result.returncode,result.stdout.decode('utf-8','replace').strip(),
                          result.stderr.decode('utf-8','replace').strip(),int((time.monotonic()-started)*1000))

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        started = time.monotonic()
        shell_cmd = (
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
            if os.name == "nt"
            else ["sh", "-c", 'eval "$(cat)"']
        )
        request_data=getattr(script,"request_data",None)
        request_input=script if os.name!='nt' else None
        if request_data and os.name!='nt':
            raise ValueError("PowerShell request data requires a Windows control channel")
        if os.name=='nt':
            bootstrap='[Console]::InputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'
            shell_cmd=shell_cmd[:-2]+['-Command',bootstrap]
            request_input=script
            if request_data:
                shell_cmd[-1]="[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);$RequestData=[Console]::In.ReadLine()|ConvertFrom-Json; & ([scriptblock]::Create([Console]::In.ReadToEnd()))"
                request_input=json.dumps(request_data)+"\n"+script
        if os.name=='nt' and self.use_native_runtime:
            from enclave_gateway.security.native import verified_runtime
            helper=verified_runtime(self.runtime_helper_path,self.trusted_signers,self.require_signed)
            shell_cmd[0]=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
            request_input=json.dumps({'command':shell_cmd,'stdin_b64':base64.b64encode(request_input.encode()).decode(),'timeout_ms':max(1,int(budget(timeout_sec)*1000))})
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

    def stream_read(self, path: str, offset: int, count: int = 65536) -> bytes:
        from enclave_gateway.transports.stream_frames import MAX_FRAME
        if type(offset) is not int or offset < 0 or not 1 <= count <= MAX_FRAME:
            raise ValueError("Invalid stream read range")
        from enclave_gateway.control.published import read_shared
        try:
            # CRT fopen may expose sharing violations as EACCES without a
            # winerror. The shared Win32 reader preserves codes 32/33 versus 5.
            return read_shared(self._map_path(path), offset=offset, count=count)
        except FileNotFoundError:
            return b""
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) in (32, 33):
                return b""
            raise

    def stream_slot_lock(self, path, timeout_sec):
        return _file_lock(Path(str(self._map_path(path).resolve()) + ".producer.lock"), timeout_sec)

    def stream_fill_slot(self, path, data):
        from enclave_gateway.transports.stream_frames import upload_slot_data
        data = upload_slot_data(data)
        with self._map_path(path).open("r+b", buffering=0) as stream:
            if stream.read(1) != b"\0":
                raise OperationError("upload_slot_unavailable", "vfs.publish",
                                     message="The upload slot holds an unacknowledged block. Reconcile it and restart the worker.")
            stream.seek(0)
            if stream.write(data) != len(data):
                raise OSError("Short upload slot write")

    def stream_append(self, path: str, data: bytes, *, limit: int | None = None) -> int:
        from enclave_gateway.transports.stream_frames import MAX_FRAME, MAX_STREAM, request_block
        limit = MAX_STREAM if limit is None else limit
        if type(limit) is not int or not 1 <= limit <= MAX_STREAM:
            raise ValueError("Invalid stream capacity")
        if not 0 < len(data) <= MAX_FRAME:
            raise ValueError("Invalid stream frame size")
        target = self._map_path(path)
        with _file_lock(Path(str(target.resolve()) + ".producer.lock")):
            with target.open("r+b", buffering=0) as stream:
                position, data = request_block(data, stream.seek(0, 2), limit)
                if stream.write(data) != len(data):
                    raise OSError("Short stream publication; command outcome is indeterminate")
                return position

    def stream_erase(self, path: str, offset: int, count: int) -> None:
        from enclave_gateway.transports.stream_frames import MAX_FRAME, MAX_STREAM
        if type(offset) is not int or type(count) is not int or offset < 0 or not 0 < count <= MAX_FRAME or offset+count > MAX_STREAM:
            raise ValueError("Invalid stream erasure range")
        with self._map_path(path).open("r+b", buffering=0) as stream:
            stream.seek(offset)
            remaining = count
            while remaining:
                wrote = stream.write(bytes(min(remaining, 65536)))
                if not wrote:
                    raise OSError("Stream erasure made no progress")
                remaining -= wrote

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
        from enclave_gateway.control.published import publish_queue_hint
        publish_queue_hint(target)

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

    def read_file_snapshot(self, guest_path: str) -> tuple[bytes, float]:
        from enclave_gateway.control.published import open_shared
        try:
            with open_shared(self._map_path(guest_path)) as stream:
                return stream.read(65537), os.fstat(stream.fileno()).st_mtime
        except FileNotFoundError:
            return b'', 0.0

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
