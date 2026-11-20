"""Clock repair must sample after waiting and verify the observed offset."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import ExecResult, QgaClient
from enclave_gateway.operations.context import OperationError
from test_field_reliability import engine_at


class QgaClockTests(unittest.TestCase):
    def test_set_time_samples_after_lock_and_sync_but_preserves_explicit_epoch(self):
        for explicit in (None, 1700000000123456789):
            with self.subTest(explicit=explicit):
                clock = [1700000000000000000]
                client = QgaClient('unused')

                @contextmanager
                def connected(timeout):
                    clock[0] += 7_000_000_000
                    yield None, None

                client._connect_synced = connected
                client._request = Mock(return_value={})
                with patch('time.time_ns', side_effect=lambda: clock[0]):
                    self.assertTrue(client.sync_guest_clock(explicit))
                expected = clock[0] if explicit is None else explicit
                client._request.assert_called_once_with(None, None, 'guest-set-time', {'time': expected})

    def measure(self, *, offset_ns=0, elapsed_ns=200_000_000, wall_step_ns=0, value=None):
        clock = [1700000000000000000]
        mono = [100_000_000_000]
        client = QgaClient('unused')

        @contextmanager
        def connected(timeout):
            clock[0] += 7_000_000_000
            mono[0] += 7_000_000_000
            yield None, None

        def request(sock, reader, command):
            self.assertEqual(command, 'guest-get-time')
            guest_ns = clock[0] + elapsed_ns//2 + offset_ns
            clock[0] += elapsed_ns + wall_step_ns
            mono[0] += elapsed_ns
            return guest_ns if value is None else value

        client._connect_synced = connected
        client._request = Mock(side_effect=request)
        with patch('time.time_ns', side_effect=lambda: clock[0]), patch('time.monotonic_ns', side_effect=lambda: mono[0]):
            result = client.guest_clock_status()
        client._request.assert_called_once_with(None, None, 'guest-get-time')
        return result

    def test_clock_read_brackets_the_sample_without_lock_wait(self):
        status = self.measure()
        self.assertTrue(status['verified'])
        self.assertEqual(status['offset_ms'], 0)
        self.assertEqual(status['offset_lower_ms'], -100)
        self.assertEqual(status['offset_upper_ms'], 100)
        self.assertEqual(status['rtt_ms'], 200)
        self.assertEqual(status['uncertainty_ms'], 100)

    def test_drift_uncertainty_and_host_clock_steps_cannot_certify_sync(self):
        for options in (
            dict(offset_ns=-17_000_000_000),
            dict(offset_ns=2_000_000_000),
            dict(elapsed_ns=5_000_000_000),
            dict(wall_step_ns=3_000_000_000),
            dict(wall_step_ns=-3_000_000_000),
        ):
            with self.subTest(options=options):
                self.assertFalse(self.measure(**options)['verified'])
        for invalid in (True, 0, -1, '1700000000000000000', 2**63):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.measure(value=invalid)

    def test_heal_requires_post_repair_clock_evidence_and_retains_failed_result(self):
        config = EnclaveConfig.from_dict(dict(bastion=dict(enabled=False), security=dict(mode='standard')))
        for observed in (
            dict(verified=True, offset_ms=0, uncertainty_ms=100),
            dict(verified=False, offset_ms=-17000, uncertainty_ms=100),
            TimeoutError('private control details'),
        ):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as directory:
                control = QgaClient(Path(directory)/'unused')
                control.sync_guest_clock = Mock(return_value=True)
                control.exec_powershell = Mock(return_value=ExecResult(0, 'APPLIANCE_INIT_OK', '', 0))
                control.guest_clock_status = Mock(side_effect=observed) if isinstance(observed, Exception) else Mock(return_value=observed)
                engine = engine_at(Path(directory), control, config)
                engine._direct_posix = False
                engine.hypervisor.is_running = Mock(return_value=(True, 'running'))
                calls = Mock()
                calls.attach_mock(control.sync_guest_clock, 'set')
                calls.attach_mock(control.exec_powershell, 'repair')
                calls.attach_mock(control.guest_clock_status, 'measure')
                result = engine.heal(tx_id='clock_repair')
                verified = isinstance(observed, dict) and observed['verified']
                self.assertEqual(result.exit_code, 0 if verified else 1)
                self.assertIn('APPLIANCE_CLOCK_CHECK:', result.stdout)
                self.assertNotIn('private control details', result.stdout+result.stderr)
                self.assertEqual([c[0] for c in calls.mock_calls], ['set', 'repair', 'measure'])
                self.assertEqual(engine.heal(tx_id='clock_repair'), result)
                control.sync_guest_clock.assert_called_once()
                control.exec_powershell.assert_called_once()
                control.guest_clock_status.assert_called_once()
                self.assertEqual(engine.transaction_status('clock_repair')['state'], 'completed' if verified else 'failed')

    def test_cancelled_clock_observation_is_not_replaced_with_a_success_result(self):
        config = EnclaveConfig.from_dict(dict(bastion=dict(enabled=False)))
        with tempfile.TemporaryDirectory() as directory:
            control = QgaClient(Path(directory)/'unused')
            control.sync_guest_clock = Mock(return_value=True)
            control.exec_powershell = Mock(return_value=ExecResult(0, '', '', 0))
            control.guest_clock_status = Mock(side_effect=OperationError('cancelled', 'qga.guest-get-time', indeterminate=True))
            engine = engine_at(Path(directory), control, config)
            engine._direct_posix = False
            engine.hypervisor.is_running = Mock(return_value=(True, 'running'))
            with self.assertRaises(OperationError) as raised:
                engine.heal()
            self.assertEqual(raised.exception.code, 'cancelled')


if __name__ == '__main__':
    unittest.main()
