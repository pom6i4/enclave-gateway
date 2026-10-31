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
            file=root/'script.ps1';file.write_text(script)
            environment={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH']}
            result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-File',str(file)],capture_output=True,text=True,env=environment,timeout=20)
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
