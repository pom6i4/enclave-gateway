"""Recover status observation without replaying an uncertain guest command."""
import base64
import contextlib
import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock

from enclave_gateway.control.qga_client import QgaClient


class QgaPollingTests(unittest.TestCase):
    def test_explicit_file_budget_reaches_one_connection_without_replay(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input';p.write_bytes(b'fixture');client=QgaClient('unused')
            with patch.object(client,'_write_stream',side_effect=TimeoutError('uncertain')) as write:
                with self.assertRaises(TimeoutError):client.write_file(p,'C:/lab/input',timeout_sec=600)
                self.assertEqual(write.call_count,1);self.assertEqual(write.call_args.kwargs,{'timeout_sec':600})
            with patch.object(client,'_read_stream',side_effect=TimeoutError('interrupted')) as read:
                target=Path(d)/'old';target.write_bytes(b'old')
                with self.assertRaises(TimeoutError):client.read_file('C:/lab/input',target,timeout_sec=600)
                self.assertEqual(target.read_bytes(),b'old');self.assertEqual(read.call_args.kwargs,{'timeout_sec':600})

    def client(self, responses):
        client=QgaClient('unused')
        @contextlib.contextmanager
        def connected(*args):
            yield None,None
        client._connect_synced=connected
        client._request=Mock(side_effect=responses)
        return client

    def test_transient_status_failure_reuses_acknowledged_process(self):
        client=self.client([{'pid':17},TimeoutError('sync'),ConnectionResetError('closed'),
                            {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'once').decode()}])
        result=client.exec_powershell('payload',timeout_sec=1)
        self.assertEqual(result.stdout,'once')
        commands=[call.args[2] for call in client._request.call_args_list]
        self.assertEqual(commands,['guest-exec']+['guest-exec-status']*3)
        self.assertTrue(all(call.args[3]=={'pid':17} for call in client._request.call_args_list[1:]))

    def test_lost_dispatch_ack_and_access_denial_are_not_retried(self):
        for responses,error,count in [([TimeoutError('ack lost')],TimeoutError,1),
                                      ([{'pid':17},PermissionError('ACL')],PermissionError,2)]:
            with self.subTest(error=error):
                client=self.client(responses)
                with self.assertRaises(error):client.exec_powershell('payload',timeout_sec=1)
                self.assertEqual(client._request.call_count,count)

    def test_status_retries_keep_original_deadline(self):
        def response(sock,reader,command,arguments):
            if command=='guest-exec':return {'pid':17}
            raise TimeoutError('still unavailable')
        client=self.client(response)
        with self.assertRaisesRegex(TimeoutError,'guest process may still be running'):
            client.exec_powershell('payload',timeout_sec=0.05)
        self.assertEqual(sum(call.args[2]=='guest-exec' for call in client._request.call_args_list),1)
