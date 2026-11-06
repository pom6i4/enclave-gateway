"""Declarative dispatch and foreground worker execution with a private fake SSH.

The portable fixture replaces Windows identity/signature adapters in a private
copy only. It never qualifies Windows publisher trust, RDP or any EDR product.
"""
import base64
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
        for pattern in ('FromBase64String','ScriptBlock','AddScript','CreateRunspace','Invoke-Expression',
                        'TcpClient','LOCALAPPDATA','CurrentVersion\\Run','Register-ScheduledTask','egw-runtime'):
            self.assertNotIn(pattern.lower(),source.lower())
        self.assertIn("'StrictHostKeyChecking=yes'",source)
        self.assertIn("'ProxyCommand=none'",source)
        self.assertIn("'PermitLocalCommand=no'",source)


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL') and os.name!='nt','Portable interpreter fixture requires PowerShell and POSIX')
class StructuredRuntimeTests(unittest.TestCase):
    @contextmanager
    def worker(self):
        with tempfile.TemporaryDirectory(prefix='egw-structured-') as temporary:
            root=Path(temporary).resolve();spool=root/'spool';spool.mkdir();stop=root/'stop'
            fake=root/'ssh.exe'
            fake.write_text('#!'+sys.executable+"\nimport subprocess,sys\np=subprocess.run(['sh','-c',sys.argv[-1]],stdin=sys.stdin.buffer,stdout=sys.stdout.buffer,stderr=sys.stderr.buffer)\nsys.exit(p.returncode)\n")
            fake.chmod(0o700)
            (root/'key').write_text('synthetic-key-path-only');(root/'known_hosts').write_text('synthetic-host-path-only')
            policy={'revision':1,'owner_sid':'S-1-5-21-1000','targets':{'app01':{'host':'127.0.0.1','port':22,'user':'fixture',
                    'key_path':str(root/'key'),'known_hosts_path':str(root/'known_hosts'),'allow_exec':True,'allow_transfer':True,'allow_sudo':False}}}
            policy_path=root/'policy.json';policy_path.write_text(json.dumps(policy))
            source=SOURCE.read_text().replace("if($env:OS -ne 'Windows_NT')","if($false)")
            source=source.replace('            }catch{\n                $state=',
                                  '            }catch{\n                Write-Warning ($_.Exception.ToString()+" line="+$_.InvocationInfo.ScriptLineNumber)\n                $state=')
            source=source.replace("$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value","$sid='S-1-5-21-1000'")
            a=source.index('function Assert-Signature(');b=source.index('Assert-PlainPath $PSCommandPath',a)
            source=source[:a]+"function Assert-Signature {return @{Status='Valid';SignerCertificate=@{Thumbprint='"+'A'*40+"'}}}\n"+source[b:]
            a=source.index('    $acl=Get-Acl');b=source.index('    $policy=[IO.File]',a);source=source[:a]+source[b:]
            a=source.index('    $ssh=[IO.Path]');b=source.index('\n',a);source=source[:a]+"    $ssh='"+str(fake).replace("'","''")+"'"+source[b:]
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
