"""Declarative dispatch and foreground worker execution with a private fake SSH.

The portable fixture replaces Windows identity/signature adapters in a private
copy only. It never qualifies Windows publisher trust, RDP or any EDR product.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock

from enclave_gateway.config import EnclaveConfig, BastionSpec
from enclave_gateway.control.qga_client import DirectHostControlChannel
from enclave_gateway.onboarding import agent_bundle
from enclave_gateway.transports.structured import StructuredTransport,StructuredSshExecutor
from enclave_gateway.transports.rdp_vfs import generate_tx_id

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'src/enclave_gateway/agents/bastion_structured.ps1'


def configuration(**changes):
    raw={'security':{'mode':'standard','require_signed_agents':True,'worker_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                     'trusted_signers':['A'*40],'enforce_worker_attestation':True},
         'bastion':{'execution_profile':'structured_only','worker_policy_sha256':'b'*64},
         'targets':{'app01':{'host':'10.0.20.11','user':'deploy'}}}
    for section,value in changes.items():raw[section].update(value)
    return EnclaveConfig.from_dict(raw)


class StructuredContractTests(unittest.TestCase):
    def test_structured_readiness_uses_file_timestamp_and_fails_closed(self):
        from enclave_gateway.operations.context import OperationError
        from enclave_gateway.worker_channel import require_running_worker
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            spool=root/'spool';spool.mkdir()
            path=spool/'worker_state.json'
            state={'status':'running','execution_profile':'structured_only',
                   'spool_protocol':'files','last_heartbeat_utc':'2000-01-01T00:00:00Z'}
            path.write_text(json.dumps(state))
            channel=DirectHostControlChannel(root)
            spec=BastionSpec(appliance_spool_dir='C:\\spool',execution_profile='structured_only',
                             worker_policy_sha256='b'*64)
            self.assertTrue(require_running_worker(channel,spec)['running'])
            expired=time.time()-spec.heartbeat_max_age_sec-1
            os.utime(path,(expired,expired))
            with self.assertRaises(OperationError) as raised:
                require_running_worker(channel,spec)
            self.assertEqual(raised.exception.code,'session_pending_worker')
            path.write_text(json.dumps({**state,'status':'stopped'}))
            with self.assertRaises(OperationError):
                require_running_worker(channel,spec)

    def test_structured_appliance_snapshot_does_not_mark_target_dispatched(self):
        from enclave_gateway.control.qga_client import ExecResult
        from enclave_gateway.operations.context import OperationContext,activate,mark_dispatched
        from enclave_gateway.worker_channel import require_running_worker
        state={'status':'running','execution_profile':'structured_only','spool_protocol':'files'}
        def read_state(script, timeout_sec):
            self.assertIn('GetLastWriteTimeUtc',script)
            self.assertLessEqual(timeout_sec,1)
            mark_dispatched()
            return ExecResult(0,json.dumps({'state':json.dumps(state),'stamp_ms':time.time_ns()//1000000}),'',0)
        control=Mock()
        control.exec_powershell.side_effect=read_state
        operation=OperationContext('test_readiness','@bastion','local',time.monotonic()+1)
        with activate(operation):
            self.assertTrue(require_running_worker(control,configuration().bastion)['running'])
            self.assertFalse(operation.dispatched)
            mark_dispatched()
            self.assertTrue(operation.dispatched)

    def test_direct_probe_waits_for_complete_reply(self):
        from enclave_gateway.control.qga_client import QgaCommandError
        control=Mock(supports_direct_spool_ipc=True)
        transport=StructuredTransport(control,configuration().bastion)
        transport.readiness_guard=lambda: {'probe_direct_reply':True}
        def complete():
            envelope=json.loads(control.publish_bytes.call_args.args[0])
            self.assertIs(envelope['probe_direct_reply'],True)
            return json.dumps({'tx_id':envelope['tx_id'],'exit_code':0,
                               'stdout_b64':'VkZTX1BPTkc=','stderr_b64':''}).encode()
        replies=iter((QgaCommandError('guest-file-open',{'error':'fixture busy'}),b'{'))
        def read(*args,**kwargs):
            item=next(replies,None)
            if isinstance(item,Exception):
                raise item
            return complete() if item is None else item
        control.try_read_bytes.side_effect=read
        self.assertEqual(transport.ping(1).stdout,'VFS_PONG')
        self.assertEqual(control.try_read_bytes.call_count,3)

    def test_profile_requires_independent_policy_and_cannot_fallback(self):
        cfg=configuration()
        files,hashes,identity,command=agent_bundle(cfg)
        self.assertEqual(set(files),{'bastion_structured.ps1'})
        for absent in ('LOCALAPPDATA','egw-runtime','RegisterAutostart','RegisterStartup','Set-ExecutionPolicy'):
            self.assertNotIn(absent,command)
        for options in ({'persist_autostart':True},{'execution_policy':'RemoteSigned'},{'migrate_legacy_state':True}):
            with self.assertRaises(ValueError):agent_bundle(cfg,**options)
        for changes in ({'bastion':{'spool_protocol':'stream'}},{'security':{'require_signed_agents':False}},
                        {'security':{'enforce_worker_attestation':False}},{'bastion':{'worker_policy_sha256':''}}):
            with self.assertRaises(ValueError):configuration(**changes)
        transport=StructuredTransport(Mock(),cfg.bastion)
        transport._dispatch_envelope=Mock(side_effect=AssertionError('Forbidden request must not be published'))
        with self.assertRaises(Exception):transport.exec_bastion('Write-Output forbidden')
        with self.assertRaises(Exception):transport.mux_open('10.0.20.11',22)
        with self.assertRaises(Exception):transport.push_file(Path('unused'),r'C:\unapproved')
        with self.assertRaises(Exception):transport.pull_file(r'C:\unapproved',Path('unused'))
        with self.assertRaises(Exception):transport.exec_bastion('',op='stop',extra_fields={'unregister_autostart':True})

    def test_source_has_no_dynamic_interpreter_or_persistence(self):
        source=SOURCE.read_text()
        for pattern in ('ScriptBlock','AddScript','CreateRunspace','Invoke-Expression',
                        'TcpClient','LOCALAPPDATA','CurrentVersion\\Run','Register-ScheduledTask','egw-runtime'):
            self.assertNotIn(pattern.lower(),source.lower())
        self.assertEqual(source.count('FromBase64String'), 1)  # Sealed stream data only.
        self.assertIn("'StrictHostKeyChecking=yes'",source)
        self.assertIn("'ProxyCommand=none'",source)
        self.assertIn("'PermitLocalCommand=no'",source)


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL') and os.name!='nt','Portable interpreter fixture requires PowerShell and POSIX')
class StructuredRuntimeTests(unittest.TestCase):
    @contextmanager
    def worker(self, *, allow_exec=True, allow_transfer=True, target_delay_ms=0):
        with tempfile.TemporaryDirectory(prefix='egw-structured-') as temporary:
            root=Path(temporary).resolve();spool=root/'spool';spool.mkdir();stop=root/'stop'
            fake=root/'ssh.exe'
            fake.write_text('#!'+sys.executable+"\nimport subprocess,sys\nfrom pathlib import Path\nwith Path(__file__).with_name('ssh-invocations.log').open('ab') as log: log.write(b'started\\n')\np=subprocess.run(['sh','-c',sys.argv[-1]],stdin=sys.stdin.buffer,stdout=sys.stdout.buffer,stderr=sys.stderr.buffer)\nsys.exit(p.returncode)\n")
            fake.chmod(0o700)
            (root/'key').write_text('synthetic-key-path-only');(root/'known_hosts').write_text('synthetic-host-path-only')
            policy={'revision':1,'owner_sid':'S-1-5-21-1000','targets':{'app01':{'host':'127.0.0.1','port':22,'user':'fixture',
                    'key_path':str(root/'key'),'known_hosts_path':str(root/'known_hosts'),'allow_exec':allow_exec,'allow_transfer':allow_transfer,'allow_sudo':False}}}
            policy_path=root/'policy.json';policy_path.write_text(json.dumps(policy))
            source=SOURCE.read_text().replace("if($env:OS -ne 'Windows_NT')","if($false)")
            source=source.replace('            }catch{\n                $state=',
                                  '            }catch{\n                Write-Warning ($_.Exception.ToString()+" line="+$_.InvocationInfo.ScriptLineNumber)\n                $state=')
            source=source.replace("$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value","$sid='S-1-5-21-1000'")
            a=source.index('function Assert-Signature(');b=source.index('function Operator-Remaining',a)
            source=source[:a]+"function Assert-Signature {return @{Status='Valid';SignerCertificate=@{Thumbprint='"+'A'*40+"'}}}\n"+source[b:]
            a=source.index('    $acl=Get-Acl');b=source.index('    $policy=[IO.File]',a);source=source[:a]+source[b:]
            a=source.index('    $ssh=[IO.Path]');b=source.index('\n',a);source=source[:a]+"    $ssh='"+str(fake).replace("'","''")+"'"+source[b:]
            if target_delay_ms:
                source=source.replace('    function Target($Request){',
                    f'    function Target($Request){{\n        Start-Sleep -Milliseconds {target_delay_ms}')
            worker=root/'worker.ps1';worker.write_text(source)
            class Channel(DirectHostControlChannel):
                supports_direct_spool_ipc=True
                def _map_path(self,path):return Path(str(path).replace('\\',os.sep))
            channel=Channel()
            # The product configuration requires real approved script signatures.
            # This fixture replaces only those platform adapters in a private copy.
            spec=BastionSpec(appliance_spool_dir=str(spool),bastion_spool_dir=str(spool),execution_profile='structured_only',worker_policy_sha256=hashlib.sha256(policy_path.read_bytes()).hexdigest())
            transport=StructuredTransport(channel,spec)
            executor=StructuredSshExecutor(transport,channel,spec)
            transport.readiness_guard=lambda:__import__('enclave_gateway.worker_channel',fromlist=['require_running_worker']).require_running_worker(channel,spec)
            log=root/'worker.log'
            with log.open('wb') as output:
                process=subprocess.Popen([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-NonInteractive','-File',str(worker),
                     '-SpoolDir',str(spool),'-PolicyPath',str(policy_path),'-PolicySha256',spec.worker_policy_sha256,'-StopFile',str(stop)],stdout=output,stderr=output)
                try:
                    until=time.monotonic()+15
                    while not (spool/'worker_state.json').exists():
                        if process.poll() is not None or time.monotonic()>until:self.fail(log.read_text(errors='replace'))
                        time.sleep(.02)
                    yield root,transport,executor,process
                except BaseException:
                    evidence=Path(tempfile.mkdtemp(prefix='egw-structured-failure-'))
                    shutil.copytree(root,evidence/'evidence')
                    print('Failed structured fixture retained at',evidence)
                    raise
                finally:
                    stop.touch()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5);self.fail('Foreground worker failed to stop')

    def test_exec_binary_transfers_replay_denial_and_unknown_operation(self):
        with self.worker() as (root,transport,executor,process):
            from enclave_gateway.config import TargetNodeSpec
            node=TargetNodeSpec('app01','127.0.0.1',user='fixture')
            from enclave_gateway.security.attestation import verify
            nonce='c'*64;evidence=transport.attest(nonce)
            verification=dict(expected_sha256=evidence['loaded_sha256'],trusted_signers=['A'*40],
                              expected_execution_profile='structured_only',expected_policy_sha256=transport.spec.worker_policy_sha256)
            self.assertTrue(verify(evidence,nonce,**verification)['verified'])
            for changed in ({'execution_profile':'legacy'},{'policy_sha256':'d'*64}):
                with self.assertRaises(Exception):verify({**evidence,**changed},nonce,**verification)
            result=executor.exec_node(node,"printf 'привет'; printf 'err' >&2; exit 7",timeout_sec=10)
            self.assertEqual((result.exit_code,result.stdout,result.stderr),(7,'привет','err'))
            marker=root/'executed'
            request={'tx_id':generate_tx_id(),'op':'ssh_exec','timeout_ms':10000,'target':'app01','expected_host':node.host,'expected_port':node.port,'expected_user':node.user,'command':"printf once >> '"+str(marker)+"'"}
            first=transport._dispatch_envelope(request,10)
            self.assertEqual(first.exit_code,0,first.stderr)
            replay=transport._dispatch_envelope(request,10)
            self.assertNotEqual(replay.exit_code,0)
            self.assertEqual(marker.read_text(),'once')
            invalid=transport.request('exec',10,command='Write-Output forbidden')
            self.assertNotEqual(invalid.exit_code,0)
            absent=transport.request('ssh_exec',10,target='unapproved',command='true')
            self.assertNotEqual(absent.exit_code,0)
            mismatch=transport.request('ssh_exec',10,target='app01',expected_host='10.0.20.12',expected_port=22,expected_user='fixture',command='true')
            self.assertNotEqual(mismatch.exit_code,0)
            data=bytes(range(256))*400
            source=root/'input.bin';source.write_bytes(data);destination=root/"remote ' quoted.bin"
            expected=hashlib.sha256(data).hexdigest()
            self.assertEqual(executor.push_file_to_node(node,source,str(destination),timeout_sec=15),expected)
            self.assertEqual(destination.read_bytes(),data)
            self.assertEqual(executor.pull_file_from_node(node,str(destination),root/'download.bin',timeout_sec=15),expected)
            self.assertEqual((root/'download.bin').read_bytes(),data)
            # The worker enforces its deadline even with a longer Host wait.
            timeout={'tx_id':generate_tx_id(),'op':'ssh_exec','timeout_ms':120,'target':'app01',
                     'expected_host':node.host,'expected_port':node.port,'expected_user':node.user,'command':'sleep 1'}
            interrupted=transport._dispatch_envelope(timeout,10)
            self.assertNotEqual(interrupted.exit_code,0)
            record=json.loads((root/'spool/.structured-transactions'/(timeout['tx_id']+'.json')).read_text())
            self.assertEqual(record['state'],'indeterminate')
            self.assertEqual(transport.ping(10).stdout,'VFS_PONG')
            self.assertEqual(transport.exec_bastion('',op='stop',timeout_sec=10).stdout,'WORKER_STOP_ACCEPTED')
            self.assertEqual(process.wait(timeout=10),0)
            from enclave_gateway.spool_cleanup import cleanup_script
            script=cleanup_script(str(root/'spool'),execution_profile='structured_only')
            encoded=base64.b64encode(script.encode('utf-16le')).decode()
            cleaned=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-EncodedCommand',encoded],capture_output=True,text=True,timeout=10)
            self.assertEqual(cleaned.returncode,0,cleaned.stderr)
            details=json.loads(cleaned.stdout.split('APPLIANCE_CLEAN_OK:',1)[1])
            self.assertTrue(details['stopped_worker_verified'])
            self.assertTrue((root/'spool/.structured-transactions'/(timeout['tx_id']+'.json')).exists())

    def test_policy_denials_and_cancelled_requests_never_launch_ssh(self):
        with self.worker(allow_exec=False,allow_transfer=False) as (root,transport,executor,process):
            identity=dict(target='app01',expected_host='127.0.0.1',expected_port=22,expected_user='fixture')
            for fields in ({'command':'touch '+str(root/'forbidden')},
                           {'command':'true','as_root':True},
                           {'command':'true','as_root':'true'}):
                denied=transport.request('ssh_exec',10,**identity,**fields)
                self.assertNotEqual(denied.exit_code,0)
            denied=transport.request('ssh_push',10,**identity,transfer_id='a'*32,remote_path='/tmp/unused',sha256='b'*64)
            self.assertNotEqual(denied.exit_code,0)
            for fields in ({'expires_unix_ms':1}, {'expected_worker_instance':'a'*32}):
                envelope={'tx_id':generate_tx_id(),'op':'ssh_exec','timeout_ms':10000,**identity,'command':'true',**fields}
                self.assertNotEqual(transport._dispatch_envelope(envelope,10).exit_code,0)
            self.assertFalse((root/'ssh-invocations.log').exists())
            self.assertFalse((root/'forbidden').exists())
            self.assertEqual(transport.ping(10).stdout,'VFS_PONG')

    def test_interrupted_transaction_cannot_replay_after_worker_restart(self):
        with self.worker() as (root,transport,executor,process):
            marker=root/'effect'
            request={'tx_id':generate_tx_id(),'op':'ssh_exec','timeout_ms':10000,'target':'app01',
                     'expected_host':'127.0.0.1','expected_port':22,'expected_user':'fixture',
                     'command':"printf once >> '"+str(marker)+"'; sleep 10"}
            # Establish the side effect before interrupting. A 500 ms startup
            # assumption could cancel a cold synthetic SSH before it ran at all.
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending=pool.submit(transport._dispatch_envelope,request,10)
                deadline=time.monotonic()+5
                while not marker.exists() or marker.read_text()!='once':
                    if pending.done() or time.monotonic()>deadline:
                        self.fail('Synthetic SSH did not establish the side effect before cancellation')
                    time.sleep(.01)
                (root/'spool'/('cancel_'+request['tx_id']+'.json')).write_text(json.dumps({'tx_id':request['tx_id']}))
                response=pending.result(timeout=3)
            self.assertNotEqual(response.exit_code,0)
            self.assertEqual(marker.read_text(),'once')
            journal=root/'spool/.structured-transactions'/(request['tx_id']+'.json')
            before=journal.read_bytes()
            self.assertEqual(json.loads(before)['state'],'indeterminate')
            old_instance=json.loads((root/'spool/worker_state.json').read_text())['instance_id']
            self.assertEqual(transport.exec_bastion('',op='stop',timeout_sec=10).exit_code,0)
            self.assertEqual(process.wait(timeout=10),0)
            with (root/'restarted.log').open('wb') as log:
                restarted=subprocess.Popen(process.args,stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+15
                    while True:
                        state=json.loads((root/'spool/worker_state.json').read_text())
                        if state['status']=='running' and state['instance_id']!=old_instance:break
                        if restarted.poll() is not None or time.monotonic()>deadline:self.fail((root/'restarted.log').read_text())
                        time.sleep(.02)
                    replay=transport._dispatch_envelope(dict(request),10)
                    self.assertNotEqual(replay.exit_code,0)
                    self.assertEqual(marker.read_text(),'once')
                    self.assertEqual(journal.read_bytes(),before)
                    self.assertEqual(transport.ping(10).stdout,'VFS_PONG')
                    self.assertEqual(transport.exec_bastion('',op='stop',timeout_sec=10).exit_code,0)
                    self.assertEqual(restarted.wait(timeout=10),0)
                finally:
                    if restarted.poll() is None:restarted.kill();restarted.wait(timeout=5)

    def test_expired_deadline_during_policy_checks_does_not_launch_ssh(self):
        with self.worker(target_delay_ms=300) as (root,transport,_,_):
            request={'tx_id':generate_tx_id(),'op':'ssh_exec','timeout_ms':150,
                     'target':'app01','expected_host':'127.0.0.1','expected_port':22,
                     'expected_user':'fixture','command':'true'}
            response=transport._dispatch_envelope(request,10)
            self.assertNotEqual(response.exit_code,0)
            self.assertFalse((root/'ssh-invocations.log').exists())
            journal=root/'spool/.structured-transactions'/(request['tx_id']+'.json')
            self.assertEqual(json.loads(journal.read_bytes())['state'],'failed')

    def test_probes_do_not_write_ledger_and_cannot_dispatch_ssh(self):
        with self.worker() as (root,transport,_,_):
            self.assertEqual(transport.attest('c'*64)['nonce'],'c'*64)
            self.assertEqual(transport.ping(10).stdout,'VFS_PONG')
            request={'tx_id':'probe_'+generate_tx_id(),'op':'ssh_exec','timeout_ms':10000,
                     'target':'app01','expected_host':'127.0.0.1','expected_port':22,
                     'expected_user':'fixture','command':'true'}
            response=transport._dispatch_envelope(request,10)
            self.assertNotEqual(response.exit_code,0)
            self.assertFalse((root/'ssh-invocations.log').exists())
            self.assertEqual(list((root/'spool/.structured-transactions').iterdir()),[])
