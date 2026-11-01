"""Connect private QEMU Unix endpoints, including native Windows Winsock."""
from __future__ import annotations
import os
import select
import socket


def connect_local(path, timeout):
    value=os.fsencode(path)
    if not value or b'\0' in value or len(value)>=108:
        raise ValueError('Invalid local control endpoint path')
    if os.name!='nt':
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout);sock.connect(os.fsdecode(path));return sock
        except BaseException:
            sock.close();raise
    # CPython Windows builds do not expose sockaddr_un address conversion.
    # Winsock supports AF_UNIX on Windows 10 1803 and newer. Only connect uses
    # the native ABI; all IO, deadlines and ownership remain Python sockets.
    import ctypes
    class Address(ctypes.Structure):
        _fields_=[('family',ctypes.c_ushort),('path',ctypes.c_char*108)]
    api=ctypes.WinDLL('ws2_32',use_last_error=True)
    api.connect.argtypes=[ctypes.c_size_t,ctypes.c_void_p,ctypes.c_int]
    api.connect.restype=ctypes.c_int
    api.WSAGetLastError.restype=ctypes.c_int
    sock=socket.socket(1,socket.SOCK_STREAM)
    try:
        sock.setblocking(False);address=Address(1,value)
        if api.connect(sock.fileno(),ctypes.byref(address),ctypes.sizeof(address)):
            error=api.WSAGetLastError()
            if error not in (10035,10036,10037):raise ctypes.WinError(error)
            _,write,failed=select.select([], [sock], [sock],timeout)
            if not write and not failed:raise TimeoutError('Local control connection timed out')
            error=sock.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
            if error:raise ctypes.WinError(error)
        sock.settimeout(timeout);return sock
    except BaseException:
        sock.close();raise
