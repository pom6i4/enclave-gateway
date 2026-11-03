"""Read published spool files without blocking Windows atomic replacement."""
from __future__ import annotations
import os
from pathlib import Path


def read_shared(path: Path, *, offset: int = 0, count: int = -1) -> bytes:
    if os.name != 'nt':
        with path.open('rb') as stream:
            if offset:stream.seek(offset)
            return stream.read(count)
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(descriptor, 'rb') as stream:
        if offset:stream.seek(offset)
        return stream.read(count)


def try_read_published(path: Path) -> bytes | None:
    try:
        return read_shared(path) or None
    except FileNotFoundError:
        return None
    except OSError as error:
        # A publisher may briefly hold an exclusive sharing lock. The caller's
        # monotonic dispatch deadline bounds polling; actual ACL denial propagates.
        if os.name == 'nt' and getattr(error, 'winerror', None) in (32, 33):
            return None
        raise


def publish_queue_hint(target: Path):
    """Best-effort bounded index; request files remain authoritative."""
    import json
    import re
    import tempfile
    import uuid
    if not re.fullmatch(r'(req|cancel)_[A-Za-z0-9_-]{1,128}\.json',target.name):return
    from enclave_gateway.control.qga_client import _file_lock
    index=target.parent/'request_index.json';temporary=None
    try:
        with _file_lock(target.parent/'.request-index.lock',timeout_sec=.5):
            try:
                raw=read_shared(index)
                data=json.loads(raw) if len(raw)<=65536 else {}
                names=data.get('files',[]) if isinstance(data,dict) else []
                if not isinstance(names,list):names=[]
            except (OSError,ValueError,TypeError):names=[]
            names=[name for name in names if isinstance(name,str) and re.fullmatch(r'(req|cancel)_[A-Za-z0-9_-]{1,128}\.json',name) and name!=target.name][-127:]
            names.append(target.name)
            with tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as stream:
                temporary=Path(stream.name)
                stream.write(json.dumps({'revision':1,'token':uuid.uuid4().hex,'files':names}).encode())
            temporary.replace(index)
    except (OSError,ValueError,TimeoutError):pass
    finally:
        if temporary:
            try:temporary.unlink(missing_ok=True)
            except OSError:pass
