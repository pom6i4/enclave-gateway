"""Bound shutdown, clock repair and copy-session checks on slow RDPDR paths."""
import json
import hashlib
from contextlib import nullcontext
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.config import BastionSpec, EnclaveConfig, TargetNodeSpec
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.operations.context import OperationContext, OperationError, activate, budget
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
from enclave_gateway.transports.structured import StructuredSshExecutor
from enclave_gateway.worker_channel import _structured_worker_state, wait_for_stopped_worker


class CopySessionTests(unittest.TestCase):
    def test_copy_can_require_fresh_attestation_despite_an_outer_context_cache(self):
        evidence = dict(verified=True, instance_id='a' * 32, loaded_sha256='b' * 64)
        transport = RdpVfsTransport(Mock(), BastionSpec())
        transport.attestation_guard = Mock(return_value={**evidence, 'nonce': 'fresh'})
        context = OperationContext('fixture', 'app01', 'local', time.monotonic()+5)
        context.worker_evidence = evidence
        with activate(context):
            fresh = transport._verify_dispatch('ssh_copy', force=True)
        self.assertEqual(fresh['nonce'], 'fresh')
        transport.attestation_guard.assert_called_once()

    def test_slot_upload_time_reduces_the_budget_before_request_publication(self):
        info = dict(revision=3, block_bytes=4096, instance='a'*32, worker_sha256='b'*64)
        payload = b'block'
        digest = hashlib.sha256(payload).hexdigest()
        for deadline, published in ((145, True), (110, False)):
            with self.subTest(deadline=deadline):
                clock = [100]
                control = Mock()
                control.try_read_bytes.return_value = json.dumps(info).encode()
                control.stream_slot_lock.return_value = nullcontext()
                def fill_slot(*args):
                    clock[0] = 112

                control.stream_fill_slot.side_effect = fill_slot
                spec = BastionSpec(execution_profile='structured_only', structured_backend='operator',
                                   spool_protocol='stream', worker_policy_sha256='c'*64)
                transport = RdpVfsTransport(control, spec)
                transport._exchange_stream = Mock(return_value=ExecResult(0, 'PART:'+digest, '', 0))
                envelope = dict(op='ssh_copy', tx_id='fixture', timeout_ms=45000,
                                copy_action='push_part', copy_length=len(payload), sha256=digest)
                with patch('time.monotonic', side_effect=lambda: clock[0]):
                    if published:
                        transport._dispatch_stream(envelope, None, deadline, 100, attachment=payload)
                        self.assertEqual(transport._exchange_stream.call_args.args[3]['timeout_ms'],33000)
                    else:
                        with self.assertRaises(OperationError):
                            transport._dispatch_stream(envelope, None, deadline, 100, attachment=payload)
                        transport._exchange_stream.assert_not_called()

    def test_copy_checks_are_periodic_bounded_and_discarded_after_the_copy(self):
        clock = [100.0]
        evidence = dict(verified=True, instance_id='a' * 32, loaded_sha256='b' * 64)
        transport = RdpVfsTransport(Mock(), BastionSpec(heartbeat_max_age_sec=45))
        transport.attestation_guard = Mock(return_value=evidence)
        reads = []

        def readiness():
            reads.append(clock[0])
            return {'_heartbeat_expires_unix': 1000 + clock[0] + 45}

        with patch('time.monotonic', side_effect=lambda: clock[0]), patch('time.time', side_effect=lambda: 1000 + clock[0]):
            with transport.chunked_copy_session(evidence):
                for elapsed in (0, 5, 14, 15, 29, 30, 46):
                    clock[0] = 100 + elapsed
                    transport._check_readiness(readiness)
                    self.assertEqual(transport._verify_dispatch('ssh_copy'), evidence)
                self.assertEqual(reads, [100, 115, 130, 146])
                self.assertEqual(transport.attestation_guard.call_count, 1)
            transport._check_readiness(readiness)
            self.assertEqual(reads[-2:], [146, 146])

    def test_absolute_heartbeat_expiry_forces_a_read_before_the_periodic_interval(self):
        clock = [100.0]
        transport = RdpVfsTransport(Mock(), BastionSpec(heartbeat_max_age_sec=5))
        guard = Mock(side_effect=lambda: {'_heartbeat_expires_unix': clock[0] + 5})
        with patch('time.monotonic', side_effect=lambda: clock[0]), patch('time.time', side_effect=lambda: clock[0]):
            with transport.chunked_copy_session({}):
                transport._check_readiness(guard)
                clock[0] += 4
                transport._check_readiness(guard)
                self.assertEqual(guard.call_count, 1)
                clock[0] += 1
                transport._check_readiness(guard)
                self.assertEqual(guard.call_count, 2)

    def test_re_attestation_and_replies_cannot_switch_worker_during_a_copy(self):
        evidence = dict(verified=True, instance_id='a' * 32, loaded_sha256='b' * 64)
        other = {**evidence, 'instance_id': 'c' * 32}
        transport = RdpVfsTransport(Mock(), BastionSpec())
        transport.attestation_guard = Mock(return_value=other)
        with patch('time.monotonic', return_value=100):
            with transport.chunked_copy_session(evidence):
                with patch('time.monotonic', return_value=131), self.assertRaises(OperationError):
                    transport._verify_dispatch('ssh_copy')
                with self.assertRaises(OperationError):
                    transport._verify_dispatch('ssh_copy')
            with transport.chunked_copy_session(evidence), self.assertRaises(OperationError):
                transport._parse_worker_response(json.dumps(dict(worker_instance=other['instance_id'],
                                                                 worker_sha256=other['loaded_sha256'])), 0, 'fixture', evidence)

    def test_copy_step_preserves_total_deadline_and_cancellation(self):
        transport = Mock()
        transport.request.side_effect = lambda *args, **kwargs: ExecResult(0, str(budget(100)), '', 0)
        executor = StructuredSshExecutor(transport, Mock(), BastionSpec())
        node = TargetNodeSpec('app01', '10.0.0.10')
        operation = OperationContext('fixture', 'app01', 'local', time.monotonic() + 3)
        with activate(operation):
            remaining = executor._copy_step(node, '/tmp/artifact', 120, False, 'push_part', 'fixture', step_timeout=45)
            self.assertLessEqual(float(remaining), 3)
            operation.cancel()
            with self.assertRaises(OperationError):
                executor._copy_step(node, '/tmp/artifact', 120, False, 'push_part', 'fixture', step_timeout=45)
        transport.request.assert_called_once()


class HealAndShutdownTests(unittest.TestCase):
    def test_successful_qga_clock_sync_disables_the_delayed_set_date_fallback(self):
        from test_field_reliability import engine_at

        config = EnclaveConfig.from_dict(dict(bastion=dict(enabled=False), security=dict(mode='standard')))
        for synced, expected in ((True, 0), (False, 1794000000123)):
            with self.subTest(synced=synced), tempfile.TemporaryDirectory() as directory:
                control = Mock()
                control.sync_guest_clock.return_value = synced
                control.exec_powershell.return_value = ExecResult(0, 'APPLIANCE_INIT_OK', '', 0)
                engine = engine_at(Path(directory), control, config)
                engine._direct_posix = False
                with patch('time.time_ns', return_value=1794000000123456789):
                    self.assertEqual(engine.heal().exit_code, 0)
                script = control.exec_powershell.call_args.args[0]
                self.assertIn(f'-HostEpochUtcMs {expected}', script)
                self.assertEqual([call[0] for call in control.mock_calls], ['sync_guest_clock', 'exec_powershell'])

    def test_stop_waits_after_acknowledgement_and_never_republishes_stop(self):
        from test_field_reliability import engine_at
        from test_operator_ssh import operator_configuration

        config = EnclaveConfig.from_dict(operator_configuration('b' * 64, 'c' * 64))
        with tempfile.TemporaryDirectory() as directory:
            control = Mock()
            control.exec_powershell.side_effect = [ExecResult(0, 'False', '', 0), ExecResult(0, 'True', '', 0)]
            engine = engine_at(Path(directory), control, config)
            engine.rdp_vfs.exec_bastion = Mock(return_value=ExecResult(0, 'WORKER_STOP_ACCEPTED', '', 0))
            self.assertEqual(engine.stop_worker(timeout_sec=3).stdout, 'WORKER_STOP_ACCEPTED')
            engine.rdp_vfs.exec_bastion.assert_called_once()
            self.assertEqual(control.exec_powershell.call_count, 2)
            script = control.exec_powershell.call_args.args[0]
            self.assertIn('[IO.FileShare]::Delete', script)
            self.assertIn('[IO.FileShare]::None', script)
            self.assertIn("$state.status -ceq 'stopped'", script)

    def test_stop_timeout_reports_pending_without_claiming_shutdown(self):
        control = Mock()
        control.exec_powershell.return_value = ExecResult(0, 'False', '', 0)
        with self.assertRaises(OperationError) as error:
            wait_for_stopped_worker(control, BastionSpec(), 0.02, 'b' * 64)
        self.assertEqual(error.exception.code, 'worker_stop_pending')
        self.assertTrue(error.exception.indeterminate)


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'), 'Requires PowerShell')
class PowerShellShutdownTests(unittest.TestCase):
    def test_stopped_telemetry_requires_a_released_lease(self):
        from test_operational_ux import LocalPowerShellControl

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = dict(status='stopped', execution_profile='structured_only', structured_backend='operator',
                         spool_protocol='stream', worker_sha256='b' * 64, instance_id='a' * 32)
            (root / 'worker_state.json').write_text(json.dumps(state))
            (root / '.worker-session').touch()

            class HeldLeaseControl(LocalPowerShellControl):
                held = True

                def exec_powershell(self, script, timeout_sec=60):
                    if self.held:
                        script = "$fixtureLease=[IO.File]::Open('" + str(root / '.worker-session').replace("'", "''") + "','Open','ReadWrite','None')\n" + script
                    return super().exec_powershell(script, timeout_sec)

            control = HeldLeaseControl(os.environ['EGW_TEST_POWERSHELL'])
            spec = BastionSpec(appliance_spool_dir=str(root))
            with self.assertRaises(OperationError) as error:
                wait_for_stopped_worker(control, spec, 1, 'b' * 64)
            self.assertEqual(error.exception.code, 'worker_stop_pending')
            control.held = False
            wait_for_stopped_worker(control, spec, 3, 'B' * 64)

    def test_readiness_reader_allows_replacement_while_it_is_open(self):
        from test_operational_ux import LocalPowerShellControl

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / 'worker_state.json'
            path.write_text(json.dumps(dict(status='running', execution_profile='structured_only', spool_protocol='files')))
            base = LocalPowerShellControl(os.environ['EGW_TEST_POWERSHELL'])

            class ReplacingControl:
                def exec_powershell(self, script, timeout_sec):
                    # Replace under the exact handle opened by the QGA snapshot.
                    script = script.replace('    try{\n        if($file.Length', "    try{\n        $temp=$p+'.next';[IO.File]::WriteAllText($temp,'{}');[IO.File]::Replace($temp,$p,[NullString]::Value)\n        if($file.Length")
                    return base.exec_powershell(script, timeout_sec)

            state = _structured_worker_state(ReplacingControl(), str(path), BastionSpec(execution_profile='structured_only', worker_policy_sha256='c' * 64))
            self.assertTrue(state['running'])
            self.assertEqual(path.read_text(), '{}')
