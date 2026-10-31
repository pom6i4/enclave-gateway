"""Read published spool files without blocking Windows atomic replacement."""
from __future__ import annotations
import os
from pathlib import Path


def read_shared(path: Path) -> bytes:
    if os.name != 'nt':
        return path.read_bytes()
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
        return stream.read()


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
