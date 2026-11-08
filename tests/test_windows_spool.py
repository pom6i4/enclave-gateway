"""Actual Windows sharing violations must not masquerade as ACL acceptance."""
import os
import json
import stat
from contextlib import contextmanager
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from enclave_gateway.control.published import read_shared, try_read_published
from enclave_gateway.control.qga_client import DirectHostControlChannel
from enclave_gateway.spool_cleanup import cleanup_script


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


@unittest.skipUnless(os.name == 'nt', 'Actual local Windows file disposition and sharing')
class RetiredStreamCleanupTests(unittest.TestCase):
    current = 'a' * 32
    retired = 'b' * 32

    def prepare(self, root):
        spool = root / 'spool'
        spool.mkdir()
        (spool / '.worker-session').touch()
        (spool / 'worker_storage.json').write_text('{"protocol":2}')
        (spool / 'ipc_descriptor.json').write_text(json.dumps({
            'revision': 3, 'block_bytes': 4096, 'instance': self.current,
            'worker_sha256': 'c' * 64}))
        return spool

    def clean(self, spool, code=0, **profile):
        # Match the existing clean.appliance budget; do not hide slow cleanup.
        result = DirectHostControlChannel(use_native_runtime=False).exec_powershell(cleanup_script(str(spool), **profile), timeout_sec=15)
        self.assertEqual(result.exit_code, code, result.stderr)
        self.assertTrue(result.stdout.startswith('APPLIANCE_CLEAN_OK:'), result.stdout)
        return json.loads(result.stdout.split(':', 1)[1])

    def test_operator_prunes_only_scrubbed_files_under_a_stopped_lease(self):
        with TemporaryDirectory() as temp:
            spool = self.prepare(Path(temp))
            state = {'status': 'running', 'instance_id': self.current,
                     'execution_profile': 'structured_only', 'structured_backend': 'operator',
                     'spool_protocol': 'stream'}
            (spool / 'worker_structured_storage.json').write_text(
                json.dumps({'revision': 1, 'owner_sha256': 'c' * 64}))
            heartbeat = spool / 'worker_state.json'
            heartbeat.write_text(json.dumps(state))
            request = spool / f'ipc_req_{self.retired}.bin'
            request.write_bytes(bytes(4096))
            upload = spool / f'ipc_upload_{self.retired}.bin'
            upload.write_bytes(bytes(1048576 + 4096))
            response = spool / f'ipc_res_{self.retired}_0.bin'
            response.write_bytes(b'\x00pending reply')
            profile = {'execution_profile': 'structured_only', 'structured_backend': 'operator'}
            self.assertFalse(self.clean(spool, **profile)['stopped_worker_verified'])
            state['status'] = 'stopped'
            heartbeat.write_text(json.dumps(state))
            with self.exclusive(upload):
                result = self.clean(spool, **profile)
                self.assertEqual(result['stream_removed'], 1)
                self.assertEqual(result['stream_deferred'], 1)
            self.assertEqual(self.clean(spool, **profile)['stream_removed'], 1)
            self.assertFalse(request.exists() or upload.exists())
            self.assertEqual(response.read_bytes(), b'\x00pending reply')

    @contextmanager
    def exclusive(self, path):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            yield
        finally:
            kernel.CloseHandle(handle)

    def test_local_pruning_deletes_backlog_and_retains_outcomes_current_instance_and_journal(self):
        with TemporaryDirectory() as temp:
            spool = self.prepare(Path(temp))
            expected = 0
            for generation in range(4):
                instance = format(generation, '032x')
                for ticket in range(32):
                    (spool / ('ipc_res_' + instance + '_' + str(ticket) + '.bin')).touch()
                    expected += 1
                for slot in 'ab':
                    (spool / ('worker_pulse_' + instance + '_' + slot + '.json')).write_text('{}')
                    expected += 1
            retained = {
                'ipc_res_' + self.retired + '_16383.bin': b'retained-outcome',
                'ipc_res_' + self.current + '_0.bin': b'',
                'worker_pulse_' + self.current + '_a.json': b'{"status":"stopped"}',
                'ipc_req_' + self.retired + '.bin': b'reconcile-request',
                'ipc_res_' + self.retired + '_16384.bin': b'',
                'ipc_res_' + self.retired + '_000000.bin': b'',
                'unrelated.tmp': b'retained',
            }
            for name, data in retained.items():
                (spool / name).write_bytes(data)
            journal = spool / '.transactions'
            journal.mkdir()
            (journal / 'tx_once.json').write_bytes(b'{"state":"completed"}')
            result = self.clean(spool)
            self.assertTrue(result['stopped_worker_verified'])
            self.assertEqual(result['stream_cleanup'], 'complete')
            self.assertEqual(result['stream_removed'], expected)
            self.assertEqual(result['errors'], 0)
            self.assertFalse(list(spool.glob('ipc_res_' + '0' * 32 + '_*.bin')))
            for name, data in retained.items():
                self.assertEqual((spool / name).read_bytes(), data, name)
            self.assertEqual((journal / 'tx_once.json').read_bytes(), b'{"state":"completed"}')
            self.assertEqual((spool / 'worker_storage.json').read_text(), '{"protocol":2}')

    def test_live_worker_or_locked_candidate_is_deferred_then_pruned_after_close(self):
        with TemporaryDirectory() as temp:
            spool = self.prepare(Path(temp))
            candidate = spool / ('ipc_res_' + self.retired + '_0.bin')
            candidate.touch()
            with self.exclusive(spool / '.worker-session'):
                result = self.clean(spool)
                self.assertFalse(result['stopped_worker_verified'])
                self.assertEqual(result['stream_removed'], 0)
                self.assertTrue(candidate.exists())
            with self.exclusive(candidate):
                result = self.clean(spool)
                self.assertEqual(result['stream_deferred'], 1)
                self.assertEqual(result['errors'], 0)
                self.assertTrue(candidate.exists())
            self.assertEqual(self.clean(spool)['stream_removed'], 1)
            self.assertFalse(candidate.exists())

    def test_missing_or_invalid_descriptor_preserves_retired_files(self):
        for value in (None, {}, {'revision': '3', 'block_bytes': 4096, 'instance': self.current,
                                  'worker_sha256': 'c' * 64}):
            with self.subTest(value=value), TemporaryDirectory() as temp:
                spool = self.prepare(Path(temp))
                descriptor = spool / 'ipc_descriptor.json'
                if value is None:
                    descriptor.unlink()
                else:
                    descriptor.write_text(json.dumps(value))
                candidate = spool / ('ipc_res_' + self.retired + '_0.bin')
                candidate.touch()
                result = self.clean(spool, code=0 if value is None else 1)
                self.assertEqual(result['stream_removed'], 0)
                self.assertTrue(candidate.exists())

    def test_hardlinks_are_preserved_and_redirected_cleanup_is_rejected(self):
        with TemporaryDirectory() as temp:
            spool = self.prepare(Path(temp))
            candidate = spool / ('ipc_res_' + self.retired + '_0.bin')
            candidate.touch()
            alias = Path(temp) / 'outside-alias'
            os.link(candidate, alias)
            self.assertEqual(self.clean(spool)['stream_removed'], 0)
            self.assertTrue(candidate.exists())
            self.assertTrue(alias.exists())
        result = DirectHostControlChannel(use_native_runtime=False).exec_powershell(cleanup_script(r'\\tsclient\C\not-a-lab'), timeout_sec=20)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('local Appliance spool', result.stderr)

    def test_reparse_endpoint_is_preserved_without_deleting_its_target(self):
        with TemporaryDirectory() as temp:
            spool = self.prepare(Path(temp))
            outside = Path(temp) / 'outside'
            outside.touch()
            candidate = spool / ('ipc_res_' + self.retired + '_0.bin')
            try:
                os.symlink(outside, candidate)
            except OSError as error:
                if error.winerror == 1314:
                    self.skipTest('Windows symlink privilege unavailable')
                raise
            self.assertEqual(self.clean(spool)['stream_removed'], 0)
            self.assertTrue(candidate.is_symlink())
            self.assertTrue(outside.exists())

    def test_template_markers_and_quotes_in_a_spool_path_remain_literal_data(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "STREAM_HELPER_SPOOL_O'Hare"
            root.mkdir()
            spool = self.prepare(root)
            candidate = spool / ('ipc_res_' + self.retired + '_0.bin')
            candidate.touch()
            self.assertEqual(self.clean(spool)['stream_removed'], 1)
            self.assertFalse(candidate.exists())

    def test_readonly_delete_failure_is_reported_without_losing_the_file(self):
        with TemporaryDirectory() as temp:
            spool = self.prepare(Path(temp))
            candidate = spool / ('ipc_res_' + self.retired + '_0.bin')
            candidate.touch()
            os.chmod(candidate, stat.S_IREAD)
            try:
                result = self.clean(spool, code=1)
                self.assertEqual(result['stream_cleanup'], 'failed')
                self.assertGreater(result['errors'], 0)
                self.assertTrue(result['stream_error_codes'])
                self.assertTrue(candidate.exists())
            finally:
                if candidate.exists():
                    os.chmod(candidate, stat.S_IREAD | stat.S_IWRITE)
            self.assertEqual(self.clean(spool)['stream_removed'], 1)
