"""Actual Windows sharing violations must not masquerade as ACL acceptance."""
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from enclave_gateway.control.published import read_shared, try_read_published


@unittest.skipUnless(os.name == 'nt', 'Windows sharing API fixture')
class PublishedSpoolTests(unittest.TestCase):
    def test_exclusive_publisher_retries_but_access_denial_propagates(self):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'response.json'
            path.write_bytes(b'complete')
            handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            try:
                self.assertIsNone(try_read_published(path))
            finally:
                kernel.CloseHandle(handle)
            self.assertEqual(read_shared(path), b'complete')
            self.assertIsNone(try_read_published(Path(temp) / 'absent'))
            with self.assertRaises(PermissionError):
                try_read_published(Path(temp))
