"""Protect new private state directories with a non-inherited Windows DACL."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
from pathlib import Path


def protect_directory(path: Path):
    from enclave_gateway.security.isolation import process_identity,process_privileged
    advapi=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    ptr=ctypes.c_void_p
    kernel.LocalFree.argtypes=[ptr]
    advapi.GetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,ctypes.c_int,wintypes.DWORD,ctypes.POINTER(ptr),ptr,ptr,ptr,ctypes.POINTER(ptr)]
    advapi.GetNamedSecurityInfoW.restype=wintypes.DWORD
    advapi.ConvertSidToStringSidW.argtypes=[ptr,ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ptr),ptr]
    advapi.GetSecurityDescriptorDacl.argtypes=[ptr,ctypes.POINTER(wintypes.BOOL),ctypes.POINTER(ptr),ctypes.POINTER(wintypes.BOOL)]
    advapi.SetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,ctypes.c_int,wintypes.DWORD,ptr,ptr,ptr,ptr]
    advapi.SetNamedSecurityInfoW.restype=wintypes.DWORD
    for parent in (path,*path.parents):
        if parent.lstat().st_file_attributes&0x400:raise PermissionError('Private state cannot traverse a reparse point')
    sid=process_identity().removeprefix('sid:');owner=ptr();descriptor=ptr();text=wintypes.LPWSTR()
    code=advapi.GetNamedSecurityInfoW(str(path),1,1,ctypes.byref(owner),None,None,None,ctypes.byref(descriptor))
    if code:raise ctypes.WinError(code)
    try:
        if not advapi.ConvertSidToStringSidW(owner,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
        current_owner=text.value
        if current_owner not in (sid,'S-1-5-18') and not (current_owner=='S-1-5-32-544' and process_privileged()):
            raise PermissionError('Private state directory belongs to another account')
    finally:
        if text:kernel.LocalFree(ctypes.cast(text,ptr))
        if descriptor:kernel.LocalFree(descriptor)
    protected=ptr();present=wintypes.BOOL();defaulted=wintypes.BOOL();dacl=ptr()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;OICI;FA;;;'+sid+')(A;OICI;FA;;;SY)',1,ctypes.byref(protected),None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.GetSecurityDescriptorDacl(protected,ctypes.byref(present),ctypes.byref(dacl),ctypes.byref(defaulted)):raise ctypes.WinError(ctypes.get_last_error())
        if not present.value or not dacl.value:raise PermissionError('Private DACL could not be constructed')
        code=advapi.SetNamedSecurityInfoW(str(path),1,0x80000004,None,None,dacl,None)
        if code:raise ctypes.WinError(code)
    finally:kernel.LocalFree(protected)
