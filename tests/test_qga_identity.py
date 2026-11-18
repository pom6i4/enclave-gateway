"""Bind PowerShell observations to invocations when Windows recycles a QGA PID."""
import base64
import contextlib
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.control.qga_client import QgaClient, QgaCommandError
from enclave_gateway.operations.context import OperationError


def exited(stdout='', code=0, stderr=''):
    return dict(exited=True, exitcode=code, **{'out-data':base64.b64encode(stdout.encode()).decode(),
                                             'err-data':base64.b64encode(stderr.encode()).decode()})


class QgaIdentityTests(unittest.TestCase):
    def client(self, responses):
        client=QgaClient('unused')
        @contextlib.contextmanager
        def connection(*args):yield None,None
        client._connect_synced=connection
        client._request=Mock(side_effect=responses)
        return client

    def test_recycled_pid_discards_old_output_and_exit_code_without_relaunch(self):
        prefix='EGW_QGA:'+'a'*32+'\n'
        stale=exited('EGW_QGA:'+'b'*32+'\n{"status":"starting"}', 19)
        client=self.client([{'pid':17},stale,exited('noise\n'+prefix+'wrong'),
                            {'exited':False},exited(prefix+'current\n',7)])
        with patch('enclave_gateway.control.qga_client.secrets.token_hex',return_value='a'*32):
            result=client.exec_powershell('exit 7',timeout_sec=2)
        self.assertEqual((result.stdout,result.exit_code),('current\n',7))
        calls=client._request.call_args_list
        self.assertEqual([call.args[2] for call in calls],['guest-exec']+['guest-exec-status']*4)
        self.assertTrue(all(call.args[3]=={'pid':17} for call in calls[1:]))

    def test_unmatched_result_expires_and_never_returns_old_success(self):
        def respond(sock,reader,command,args):
            return {'pid':17} if command=='guest-exec' else exited('old success')
        client=self.client(respond)
        with self.assertRaises(TimeoutError):client.exec_powershell('payload',timeout_sec=.05)
        self.assertEqual(client._unreaped_pids,{17})
        self.assertEqual(sum(c.args[2]=='guest-exec' for c in client._request.call_args_list),1)

    def test_next_launch_reaps_completed_orphans_and_does_not_wait_for_running_ones(self):
        missing=QgaCommandError('guest-exec-status',{'error':{'class':'GenericError','desc':'PID does not exist'}})
        client=self.client([exited('old'),{'exited':False},missing,{'pid':30},exited('current')])
        client._unreaped_pids.update((17,18,19))
        result=client.exec_guest('fixture.exe',timeout_sec=1)
        self.assertEqual(result.stdout,'current')
        self.assertIn(17,client._unreaped_pids)
        self.assertIn(18,client._unreaped_pids)
        self.assertNotIn(19,client._unreaped_pids)
        calls=client._request.call_args_list
        self.assertEqual([c.args[2] for c in calls],['guest-exec-status']*3+['guest-exec','guest-exec-status'])

    def test_raw_command_cannot_accept_a_known_unresolved_pid(self):
        client=self.client([{'exited':False},{'pid':17}])
        client._unreaped_pids.add(17)
        with self.assertRaises(OperationError) as error:client.exec_guest('fixture.exe',timeout_sec=1)
        self.assertEqual(error.exception.code,'qga_pid_collision')
        self.assertTrue(error.exception.indeterminate)
        self.assertEqual(client._request.call_count,2)

    def test_orphan_poll_failure_does_not_replay_or_prevent_new_launch(self):
        client=self.client([TimeoutError('busy'),{'pid':30},exited('current')])
        client._unreaped_pids.add(17)
        self.assertEqual(client.exec_guest('fixture.exe',timeout_sec=1).stdout,'current')
        self.assertIn(17,client._unreaped_pids)

    def test_orphan_maintenance_rotates_without_consuming_active_results(self):
        client=self.client(lambda *args:{'exited':False})
        client._unreaped_pids.update(range(1,11))
        client._active_pids.add(10)
        for _ in range(2):
            with client._exec_state(time.monotonic()+1):client._reap_unreaped(time.monotonic()+1)
        pids=[c.args[3]['pid'] for c in client._request.call_args_list]
        self.assertEqual(pids[:8],list(range(1,9)))
        self.assertIn(9,pids[8:])
        self.assertNotIn(10,pids)

    def test_maintenance_cannot_extend_the_launch_deadline(self):
        client=self.client([])
        clock=[100.0]
        def expired(deadline):clock[0]=102.0
        client._reap_unreaped=expired
        with patch('time.monotonic',side_effect=lambda:clock[0]),self.assertRaises(TimeoutError):
            client.exec_guest('fixture.exe',timeout_sec=1)
        client._request.assert_not_called()

    def test_launch_drains_multiple_records_of_a_recycled_pid(self):
        prefix='EGW_QGA:'+'a'*32+'\n'
        missing=QgaCommandError('guest-exec-status',{'error':{'desc':'PID does not exist'}})
        client=self.client([exited('first orphan'),{'pid':17},exited('second orphan'),
                            exited(prefix+'current'),missing,{'pid':18},exited('next')])
        client._unreaped_pids.add(17)
        with patch('enclave_gateway.control.qga_client.secrets.token_hex',return_value='a'*32):
            self.assertEqual(client.exec_powershell('payload',timeout_sec=2).stdout,'current')
        self.assertEqual(client.exec_guest('fixture.exe',timeout_sec=1).stdout,'next')
        self.assertFalse(client._unreaped_pids)

    @unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Requires real PowerShell')
    def test_real_interpreter_marker_and_large_stdin_source_preserve_output_and_exit(self):
        from enclave_gateway.operations.request import PowerShellRequest
        for script, expected, code in [('[Console]::Write("empty-line-free");exit 7','empty-line-free',7),
                                        ('# empty output','',0),
                                        ('if (','',1),
                                        ('Write-Error "fixture failure"','',1),
                                        (PowerShellRequest('[Console]::Write($RequestData.value);\n#'+'x'*13000,
                                                           {'value':'fixture-text'}),'fixture-text',0)]:
            with self.subTest(code=code,output=expected):
                def respond(sock,reader,command,args):
                    if command=='guest-exec':
                        result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],*args['arg']],
                            input=base64.b64decode(args.get('input-data','')),capture_output=True,timeout=15)
                        statuses.append(exited(result.stdout.decode().replace('\r\n','\n'),result.returncode,result.stderr.decode()))
                        return {'pid':17}
                    return statuses.pop(0)
                statuses=[exited('unrelated old result',99)]
                client=self.client(respond)
                result=client.exec_powershell(script,timeout_sec=20)
                self.assertEqual((result.exit_code,result.stdout),(code,expected))
                if code and not expected:self.assertTrue(result.stderr)
