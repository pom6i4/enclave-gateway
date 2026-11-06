"""Fresh worker evidence, OS backend boundaries and owned command cancellation."""
import base64
import hashlib
import json
import os
import subprocess
import secrets
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from enclave_gateway.security.attestation import verify
from enclave_gateway.operations.context import OperationError
from enclave_gateway.transports.owned_ssh import script

ROOT=Path(__file__).resolve().parents[1]


class AttestationTests(unittest.TestCase):
    def test_signature_stage_cap_cannot_extend_operation_deadline(self):
        from enclave_gateway.security.native import verified_runtime
        from enclave_gateway.operations.context import OperationContext,activate
        from unittest.mock import Mock
        with TemporaryDirectory() as temporary:
            helper=Path(temporary)/'runtime.exe';helper.write_bytes(b'fixture')
            with patch.dict(os.environ,{'SystemRoot':r'C:\Windows'}),patch('enclave_gateway.security.native.subprocess.run',return_value=Mock(returncode=0)) as execute:
                verified_runtime(str(helper),['A'*40])
                self.assertEqual(execute.call_args.kwargs['timeout'],15)
                context=OperationContext('fixture','@appliance','fixture',time.monotonic()+0.5)
                with activate(context):verified_runtime(str(helper),['A'*40],verification_timeout_sec=120)
                self.assertGreater(execute.call_args.kwargs['timeout'],0)
                self.assertLessEqual(execute.call_args.kwargs['timeout'],0.5)
                for value in (0,121,float('inf'),float('nan')):
                    with self.assertRaises(ValueError):verified_runtime(str(helper),verification_timeout_sec=value)

    def test_fresh_release_account_and_execution_identity(self):
        nonce='a'*64
        evidence={'protocol_revision':1,'version':'0.3.0','loaded_signature_status':'Valid','loaded_signer':'D'*40,'runtime_signature_status':'Valid','runtime_signer':'D'*40,'nonce':nonce,'instance_id':'b'*32,'loaded_sha256':'c'*64,'current_sha256':'c'*64,
                  'runtime_loaded_sha256':'e'*64,'runtime_current_sha256':'e'*64,'signature_status':'Valid','signer':'D'*40,'sid':'S-1-5-21-1000-1000-1000-1001','execution_model':'owned-process-job'}
        options={'expected_sha256':'c'*64,'trusted_signers':['D'*40],'expected_account':'S-1-5-21-1000-1000-1000-1001','require_process_isolation':True,'expected_runtime_sha256':'e'*64}
        self.assertTrue(verify(evidence,nonce,**options)['verified'])
        for key,value in [('nonce','wrong'),('loaded_sha256','e'*64),('current_sha256','e'*64),('signer','untrusted'),('sid','other'),('execution_model','runspace-lab')]:
            with self.subTest(key=key),self.assertRaises(OperationError): verify({**evidence,key:value},nonce,**options)
    def test_operation_verifies_once_and_rejects_instance_change(self):
        from enclave_gateway.config import BastionSpec
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        from enclave_gateway.operations.context import OperationContext,activate
        from unittest.mock import Mock
        transport=RdpVfsTransport(Mock(),BastionSpec())
        evidence={'verified':True,'instance_id':'a'*32,'loaded_sha256':'b'*64}
        transport.attestation_guard=Mock(return_value=evidence)
        context=OperationContext('root','@bastion','fixture',time.monotonic()+3)
        response={'tx_id':'phase','exit_code':0,'stdout_b64':'','stderr_b64':'','worker_instance':'a'*32,'worker_sha256':'b'*64}
        with activate(context):
            self.assertEqual(transport._verify_dispatch('exec'),evidence)
            transport._verify_dispatch('exec')
            self.assertEqual(transport.attestation_guard.call_count,1)
            self.assertEqual(transport._parse_worker_response(json.dumps(response),0,'phase',evidence).exit_code,0)
            with self.assertRaises(OperationError): transport._parse_worker_response(json.dumps({**response,'worker_instance':'c'*32}),0,'phase',evidence)
            with self.assertRaises(OperationError): transport._verify_dispatch('exec')


@unittest.skipIf(os.name=='nt','POSIX supervisor/UID fixture')
class IsolationTests(unittest.TestCase):
    @unittest.skipIf(os.name=='nt','POSIX stdin supervisor fixture')
    def test_large_owned_script_preserves_empty_command_stdin(self):
        from enclave_gateway.agents.owned_command import execute
        import base64,secrets
        script='#'+'x'*300000+'\nprintf start; cat; printf "\\nтест\\n"'
        with patch.object(os,'waitid',None,create=True):
            result=execute({'token':secrets.token_hex(32),'script':script,'timeout_sec':5})
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(base64.b64decode(result['stdout_b64']).decode(),'start\nтест\n')
        self.assertTrue(result['owned_tree_stopped'])

    def test_cancel_half_close_race_still_requires_exact_acknowledgement(self):
        import errno
        from enclave_gateway.agents import owned_command
        token='a'*64
        with patch.object(owned_command,'endpoint',return_value=Path('/tmp/fixture.sock')),patch.object(owned_command.socket,'socket') as factory:
            client=factory.return_value.__enter__.return_value
            client.shutdown.side_effect=OSError(errno.ENOTCONN,'peer already closed')
            for acknowledgement,accepted in ((b'accepted',True),(b'',False),(b'rejected',False)):
                client.recv.return_value=acknowledgement
                self.assertEqual(owned_command.cancel(token)['cancel_requested'],accepted)
            client.sendall.assert_called_with(token.encode())
            client.shutdown.side_effect=OSError(errno.EPERM,'unexpected failure')
            with self.assertRaises(OSError):owned_command.cancel(token)

    def test_owned_remote_supervisor_cancels_descendants(self):
        token=secrets.token_hex(32)
        process=subprocess.Popen(['sh','-c',script({'action':'exec','token':token,'script':'sleep 30 & wait','timeout_sec':10})],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        from enclave_gateway.agents.owned_command import endpoint,cancel
        deadline=time.monotonic()+3
        while not endpoint(token).exists():
            if time.monotonic()>deadline: self.fail('Supervisor did not start')
            time.sleep(0.01)
        self.assertTrue(cancel(token)['cancel_requested'])
        output,error=process.communicate(timeout=3)
        self.assertEqual(process.returncode,0,error)
        result=json.loads(output)
        self.assertTrue(result['owned_tree_stopped']); self.assertTrue(result['cancelled'])
        self.assertFalse(endpoint(token).exists())

    def test_supervisor_preserves_exit_status_and_binary_output(self):
        payload={'action':'exec','token':secrets.token_hex(32),'script':"printf 'fixture'; exit 7",'timeout_sec':3}
        process=subprocess.run(['sh','-c',script(payload)],capture_output=True,text=True,timeout=5)
        result=json.loads(process.stdout)
        self.assertEqual(result['exit_code'],7)
        self.assertEqual(base64.b64decode(result['stdout_b64']),b'fixture')

    @unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
    def test_large_ssh_script_uses_stdin_and_executes_unicode(self):
        from enclave_gateway.config import TargetNodeSpec
        from enclave_gateway.transports.ssh_hop import build_powershell_ssh_hop_script
        with TemporaryDirectory() as temp:
            root=Path(temp); fake=root/'ssh.exe'
            fake.write_text('#!'+sys.executable+"\nimport subprocess,sys\ndata=sys.stdin.buffer.read()\nassert len(data)>100000\nr=subprocess.run(['sh','-c',sys.argv[-1]],input=data,capture_output=True)\nsys.stdout.buffer.write(r.stdout);sys.stderr.buffer.write(r.stderr);sys.exit(r.returncode)\n")
            fake.chmod(0o700)
            script=build_powershell_ssh_hop_script(TargetNodeSpec('fixture','127.0.0.1',user='fixture'),"#"+'x'*100000+"\nprintf 'тест-готово'\n")
            file=root/'script.ps1';file.write_text('$RequestData=[Console]::In.ReadLine()|ConvertFrom-Json;\n'+script)
            environment={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH']}
            result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-File',str(file)],input=json.dumps(script.request_data)+'\n',capture_output=True,text=True,env=environment,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'тест-готово')

    def test_backend_process_handshake_and_credential_environment(self):
        from enclave_gateway.security.isolation import Backend,process_identity
        with TemporaryDirectory() as temp:
            root=Path(temp); config=root/'config.json'; policy=root/'policy.json'
            config.write_text(json.dumps({'appliance':{'hypervisor':'direct'},'bastion':{'enabled':False}}))
            policy.write_text(json.dumps({'principals':{'fixture':{'tools':['node_exec','enclave_transaction'],'nodes':['@appliance'],'allow_arbitrary_exec':True}}}))
            spec={'identity':process_identity(),'config':str(config),'policy':str(policy),'environment':{'PYTHONPATH':str(ROOT/'src')}}
            with self.assertRaises(ValueError): Backend('fixture',spec)
            with patch.dict(os.environ,{'BROKER_ONLY_SECRET':'must-not-inherit'}):
                backend=Backend('fixture',spec,allow_same_user_for_tests=True)
            try:
                response=backend.handle({'jsonrpc':'2.0','id':11,'method':'tools/call','params':{'name':'node_exec','arguments':{'node':'@appliance','script':'printf "%s" "${BROKER_ONLY_SECRET-unset}"','tx_id':'backend-fixture'}}})
                self.assertEqual(response['id'],11)
                self.assertIn('unset',json.dumps(response))
                self.assertNotIn('must-not-inherit',json.dumps(response))
                self.assertNotEqual(backend.process.pid,os.getpid())
                self.assertTrue((root/'state/audit.transactions.sqlite3').exists())
                cancelled=backend.handle({'jsonrpc':'2.0','id':12,'method':'tools/call','params':{'name':'node_exec','arguments':{'node':'@appliance','script':'sleep 20','tx_id':'backend-cancel'}}},cancel_requested=lambda:True)
                self.assertEqual(cancelled['error']['data']['code'],'cancelled')
            finally: backend.close()
