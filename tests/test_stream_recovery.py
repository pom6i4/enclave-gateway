"""Actual bootstrap supervision, typed handle faults and journal-preserving restart."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from enclave_gateway.config import BastionSpec
from enclave_gateway.control.qga_client import DirectHostControlChannel
from enclave_gateway.operations.context import OperationError
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / 'src/enclave_gateway/agents'


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'), 'Real PowerShell recovery fixture is opt-in')
class StreamRecoveryTests(unittest.TestCase):
    @contextmanager
    def worker(self, code=6, cancellation=None):
        with tempfile.TemporaryDirectory(prefix='egw-recovery-') as name:
            root = Path(name).resolve()
            spool = root / 'spool'
            spool.mkdir()
            fault = root / 'revoke-handle'
            stop = root / 'stop'
            worker = root / 'worker.ps1'
            source = (AGENTS / 'bastion_worker.ps1').read_text()
            needle = '$count=$file.Read($bytes,0,$bytes.Length)'
            self.assertEqual(source.count(needle), 1)
            # Confine deterministic ERROR_INVALID_HANDLE/ACCESS_DENIED injection
            # to a private reviewed test copy; the product exposes no fault hook.
            quoted = str(fault).replace("'", "''")
            injection = "if([IO.File]::Exists('" + quoted + "')){[IO.File]::Delete('" + quoted + "');throw [IO.IOException]::new('Fixture redirected handle revoked'," + str(0x80070000 + code - 2**32) + ")};"
            if cancellation:
                token = ",([Threading.CancellationToken]::new($true))" if cancellation == 'token' else ''
                injection = "if([IO.File]::Exists('" + quoted + "')){[IO.File]::Delete('" + quoted + "');throw [OperationCanceledException]::new('Fixture redirected I/O aborted'" + token + ")};"
            worker.write_text(source.replace(needle, injection + needle))
            class Channel(DirectHostControlChannel):
                def _map_path(self, path):
                    return Path(str(path).replace('\\', os.sep))
            transport = RdpVfsTransport(Channel(), BastionSpec(appliance_spool_dir=str(spool),
                                        bastion_spool_dir=str(spool), spool_protocol='stream'))
            # This isolated fixture deliberately executes an unsigned private
            # copy. Select only process RemoteSigned; domain policy still wins.
            command = [os.environ['EGW_TEST_POWERSHELL'], '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File',
                       str(AGENTS / 'bastion_bootstrap.ps1'), '-Mode', 'Standard', '-WorkerPath', str(worker),
                       '-SourceSpool', str(spool), '-StateRoot', str(root / 'state'),
                       '-SpoolProtocol', 'Stream', '-HeartbeatIntervalMs', '250',
                       '-MigrateLegacyState', '-StopFile', str(stop)]
            with (root / 'bootstrap.log').open('wb') as log:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                try:
                    self.ready(root, process)
                    yield root, process, transport, fault
                except BaseException:
                    evidence = Path(tempfile.mkdtemp(prefix='egw-recovery-failure-')) / 'evidence'
                    shutil.copytree(root, evidence)
                    print('Recovery fixture evidence retained:', evidence)
                    raise
                finally:
                    stop.touch()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        self.fail('Owned bootstrap did not stop; ' + (root / 'bootstrap.log').read_text(errors='replace'))

    def ready(self, root, process, previous=None):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            self.assertIsNone(process.poll(), (root / 'bootstrap.log').read_text(errors='replace'))
            try:
                descriptor = json.loads((root / 'spool/ipc_descriptor.json').read_text())
                state = json.loads((root / 'spool/worker_state.json').read_text(encoding='utf-8-sig'))
                if (state.get('status') == 'running' and state.get('instance_id') == descriptor['instance']
                        and descriptor['instance'] != previous):
                    return descriptor['instance']
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(.02)
        self.fail('No fresh recovered descriptor; ' + (root / 'bootstrap.log').read_text(errors='replace'))

    def recovering(self, root, process):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.assertIsNone(process.poll(), (root / 'bootstrap.log').read_text(errors='replace'))
            if 'STREAM_RECOVERING' in (root / 'bootstrap.log').read_text(errors='replace'):
                return
            time.sleep(.01)
        self.fail('Supervisor did not observe the revoked handle')

    def test_recovery_preserves_completed_and_inflight_identities_and_nonempty_responses(self):
        with self.worker() as (root, process, transport, fault):
            spool = root / 'spool'
            first = json.loads((spool / 'ipc_descriptor.json').read_text())['instance']
            binding = (spool / 'worker_storage.json').read_bytes()
            side_effect = root / 'effect'
            script = "[IO.File]::AppendAllText('" + str(side_effect).replace("'", "''") + "','once')"
            envelope = {'tx_id': 'tx_completed', 'op': 'exec', 'timeout_ms': 8000,
                        'payload_b64': base64.b64encode(script.encode()).decode()}
            self.assertEqual(transport._dispatch_envelope(envelope, timeout_sec=8).exit_code, 0)
            retained = spool / ('ipc_res_' + first + '_16383.bin')
            retained.write_bytes(b'preserved-completed-outcome')
            unused = spool / ('ipc_res_' + first + '_16382.bin')
            unused.touch()
            marker = root / 'inflight'
            active = "[IO.File]::AppendAllText('" + str(marker).replace("'", "''") + "','once');Start-Sleep -Seconds 30"
            pending = {'tx_id': 'tx_inflight', 'op': 'exec', 'timeout_ms': 6000,
                       'payload_b64': base64.b64encode(active.encode()).decode()}
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(transport._dispatch_envelope, pending, timeout_sec=6)
                deadline = time.monotonic() + 3
                while not marker.exists():
                    if time.monotonic() > deadline:
                        self.fail('In-flight command did not start')
                    time.sleep(.01)
                fault.touch()
                second = self.ready(root, process, first)
                with self.assertRaises(OperationError) as error:
                    future.result(timeout=8)
                self.assertTrue(error.exception.indeterminate)
            self.assertEqual((spool / 'worker_storage.json').read_bytes(), binding)
            self.assertEqual(retained.read_bytes(), b'preserved-completed-outcome')
            # Retention never runs over the redirected filesystem during
            # recovery. Explicit Appliance-local clean owns these old files.
            self.assertTrue(unused.exists())
            self.assertTrue(list(spool.glob('worker_pulse_' + first + '_*.json')))
            self.assertTrue((spool / ('ipc_req_' + first + '.bin')).exists())
            for request in (envelope, pending):
                result = transport._dispatch_envelope(request, timeout_sec=8)
                self.assertEqual(result.exit_code, 125)
                if request is envelope:
                    self.assertIn('Existing transaction', result.stderr)
                else:
                    self.assertTrue('Existing transaction' in result.stderr or result.stderr == 'Cancelled before dispatch', result.stderr)
            self.assertEqual(side_effect.read_text(), 'once')
            self.assertEqual(marker.read_text(), 'once')
            self.assertEqual(transport.exec_bastion("Write-Output 'AFTER_RECONNECT'", timeout_sec=8).stdout, 'AFTER_RECONNECT')
            # Another loss recovers again; stop acknowledgement ends supervision.
            fault.touch()
            third = self.ready(root, process, second)
            self.assertNotEqual(third, second)
            self.assertEqual(transport.exec_bastion("Write-Output 'SECOND_RECOVERY'", timeout_sec=8).stdout, 'SECOND_RECOVERY')
            self.assertEqual(transport.exec_bastion('', op='stop', timeout_sec=8).stdout, 'WORKER_STOP_ACCEPTED')
            self.assertEqual(process.wait(timeout=10), 0)
            time.sleep(.2)
            self.assertEqual(json.loads((spool / 'ipc_descriptor.json').read_text())['instance'], third)

    def test_changed_or_missing_storage_and_changed_worker_are_fatal(self):
        for change in ('binding', 'missing-binding', 'missing-journal', 'worker'):
            with self.subTest(change=change), self.worker() as (root, process, transport, fault):
                fault.touch()
                self.recovering(root, process)
                if change in ('binding', 'missing-binding', 'missing-journal'):
                    binding = root / 'spool/worker_storage.json'
                    data = json.loads(binding.read_text())
                    if change == 'binding':
                        data['storage_id'] = '0' * 32
                        binding.write_text(json.dumps(data))
                    elif change == 'missing-binding':
                        binding.unlink()
                    else:
                        (root / 'state' / data['storage_id'] / 'storage.json').unlink()
                    message = 'WORKER_JOURNAL_MISSING' if change == 'missing-journal' else 'WORKER_JOURNAL_IDENTITY_MISMATCH'
                else:
                    worker = root / 'worker.ps1'
                    worker.write_text(worker.read_text() + '\n# Changed private fixture bytes\n')
                    message = 'Worker bytes changed during supervision'
                self.assertNotEqual(process.wait(timeout=10), 0)
                self.assertIn(message, (root / 'bootstrap.log').read_text(errors='replace'))

    def test_unrecognized_io_failure_never_enters_recovery(self):
        with self.worker(code=5) as (root, process, transport, fault):
            fault.touch()
            self.assertNotEqual(process.wait(timeout=10), 0)
            self.assertNotIn('STREAM_RECOVERING', (root / 'bootstrap.log').read_text(errors='replace'))

    def test_native_read_abort_recovers_but_explicit_token_cancellation_is_fatal(self):
        with self.worker(cancellation='native') as (root, process, transport, fault):
            first = json.loads((root / 'spool/ipc_descriptor.json').read_text())['instance']
            fault.touch()
            self.ready(root, process, first)
            self.assertEqual(transport.exec_bastion("Write-Output 'READ_ABORT_RECOVERED'", timeout_sec=8).stdout,
                             'READ_ABORT_RECOVERED')
            self.assertIn('win32_code=995', (root / 'bootstrap.log').read_text(errors='replace'))
        with self.worker(cancellation='token') as (root, process, transport, fault):
            fault.touch()
            self.assertNotEqual(process.wait(timeout=10), 0)
            self.assertNotIn('STREAM_RECOVERING', (root / 'bootstrap.log').read_text(errors='replace'))

    def test_ready_and_execution_do_not_prune_a_backlog_of_retired_endpoints(self):
        with self.worker() as (root, process, transport, fault):
            spool = root / 'spool'
            first = json.loads((spool / 'ipc_descriptor.json').read_text())['instance']
            retained = {}
            for generation in range(4):
                instance = format(generation, '032x')
                for ticket in range(32):
                    content = b'nonempty-outcome' if ticket % 3 == 0 else b''
                    retained['ipc_res_' + instance + '_' + str(ticket) + '.bin'] = content
                retained['worker_pulse_' + instance + '_a.json'] = b'{"status":"stopped"}'
                retained['worker_pulse_' + instance + '_b.json'] = b'{"status":"stopped"}'
                retained['ipc_req_' + instance + '.bin'] = b'reconcile-request'
            for name, data in retained.items():
                (spool / name).write_bytes(data)
            fault.touch()
            second = self.ready(root, process, first)  # Original 20-second gate.
            self.assertNotEqual(first, second)
            self.assertEqual(transport.exec_bastion("Write-Output 'BACKLOG_READY'", timeout_sec=8).stdout,
                             'BACKLOG_READY')
            for name, data in retained.items():
                self.assertEqual((spool / name).read_bytes(), data, name)

    def test_duplicate_supervisor_is_rejected_even_during_backoff(self):
        with self.worker() as (root, process, transport, fault):
            fault.touch()
            self.recovering(root, process)
            duplicate = subprocess.run(process.args, capture_output=True, timeout=10)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn(b'WORKER_ALREADY_RUNNING', duplicate.stderr)
            self.assertNotIn(b'STREAM_RECOVERING', duplicate.stdout)

    @unittest.skipIf(os.name == 'nt', 'Open-directory rename fixture uses POSIX; Windows requires revoked network handles')
    def test_disappearing_spool_waits_without_creating_a_replacement(self):
        with self.worker() as (root, process, transport, fault):
            spool = root / 'spool'
            first = json.loads((spool / 'ipc_descriptor.json').read_text())['instance']
            binding = (spool / 'worker_storage.json').read_bytes()
            offline = root / 'offline-spool'
            spool.rename(offline)
            self.recovering(root, process)
            time.sleep(1.1)
            self.assertFalse(spool.exists(), 'Supervisor must not create an empty replacement spool')
            offline.rename(spool)
            self.ready(root, process, first)
            self.assertEqual((spool / 'worker_storage.json').read_bytes(), binding)
            self.assertEqual(transport.exec_bastion("Write-Output 'SPOOL_RETURNED'", timeout_sec=8).stdout, 'SPOOL_RETURNED')
