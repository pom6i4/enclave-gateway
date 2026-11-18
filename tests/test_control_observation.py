"""Distinguish a failed control observation from an absent worker heartbeat."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.worker_channel import _structured_worker_state
from test_field_reliability import engine_at
from test_operator_ssh import operator_configuration


class ControlObservationTests(unittest.TestCase):
    def engine(self, root):
        engine=engine_at(root,Mock(),EnclaveConfig.from_dict(operator_configuration('b'*64,'c'*64)))
        engine._direct_posix=False
        engine.hypervisor.is_running=Mock(return_value=(True,123))
        engine.control.exec_powershell=Mock(return_value=ExecResult(0,'{}','',0))
        return engine

    def test_status_retains_control_timeout_but_absent_heartbeat_has_no_probe_error(self):
        with tempfile.TemporaryDirectory() as directory:
            engine=self.engine(Path(directory))
            with patch('enclave_gateway.worker_channel._structured_worker_state',side_effect=TimeoutError('QGA busy')):
                state=engine.status()['bastion']
            self.assertFalse(state['worker_healthy'])
            self.assertIsNone(state['worker_state'])
            self.assertEqual(state['control_probe_error']['cause'],'timeout')
            with patch('enclave_gateway.worker_channel._structured_worker_state',return_value={}):
                missing=engine.status()['bastion']
            self.assertFalse(missing['worker_healthy'])
            self.assertNotIn('control_probe_error',missing)

    def test_doctor_uses_larger_observation_budget_and_reports_control_cause_for_skipped_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            engine=self.engine(Path(directory))
            engine.exec_node=Mock()
            with patch('enclave_gateway.worker_channel._structured_worker_state',side_effect=TimeoutError('QGA busy')) as probe:
                result=engine.doctor(probe_targets=True)
            self.assertEqual(probe.call_args.kwargs['timeout_sec'],15)
            ipc=next(row for row in result['checks'] if row['check']=='bastion_rdp_vfs_ipc')
            self.assertEqual(ipc['code'],'control_probe_error')
            self.assertNotIn('No fresh worker heartbeat',ipc['detail'])
            target=next(row for row in result['checks'] if row['check'].startswith('target_ssh:'))
            self.assertEqual(target['code'],'control_probe_error')
            self.assertNotIn('known_hosts',target['detail'])
            engine.exec_node.assert_not_called()

    def test_snapshot_retries_only_observation_and_rejects_failed_command(self):
        from enclave_gateway.operations.context import OperationError
        from enclave_gateway.config import BastionSpec
        spec=BastionSpec()
        control=Mock()
        snapshot=json.dumps({'state':json.dumps({'status':'running'}),'stamp_ms':1000000})
        control.exec_powershell.side_effect=[TimeoutError('busy'),ExecResult(0,snapshot,'',0)]
        result=_structured_worker_state(control,'C:/spool/worker_state.json',spec,timeout_sec=15)
        self.assertTrue(result['running'])
        self.assertEqual([call.kwargs['timeout_sec'] for call in control.exec_powershell.call_args_list],[15,15])
        control.exec_powershell.side_effect=None
        control.exec_powershell.return_value=ExecResult(1,'','failure',0)
        with self.assertRaises(OperationError) as error:
            _structured_worker_state(control,'C:/spool/worker_state.json',spec)
        self.assertEqual(error.exception.code,'control_probe_error')
