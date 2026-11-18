"""Observe shared worker metadata without blocking publication or reconnecting."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

SUPERVISOR=Path(__file__).resolve().parents[1]/'src/enclave_gateway/agents/session_supervisor.ps1'
POWERSHELL=os.environ.get('EGW_TEST_POWERSHELL') or (shutil.which('powershell.exe') if os.name=='nt' else None)


@unittest.skipUnless(POWERSHELL,'Requires PowerShell; Windows uses the system interpreter')
class SupervisorObservationTests(unittest.TestCase):
    def prepare(self, root):
        state=dict(status='running',instance_id='a'*32,worker_sha256='b'*64,
                   spool_protocol='stream',execution_profile='structured_only',structured_backend='operator')
        descriptor=dict(revision=3,block_bytes=4096,instance=state['instance_id'],worker_sha256=state['worker_sha256'])
        (root/'worker_state.json').write_text(json.dumps(state))
        (root/'ipc_descriptor.json').write_text(json.dumps(descriptor))
        return state,descriptor

    def observe(self, root, setup='', connected=True):
        # Only network inventory is synthetic. All metadata I/O and the complete
        # ObserveOnly supervisor run use the actual interpreter and filesystem.
        source="param($Supervisor,$Spool)\n"
        source+="function Get-NetTCPConnection { "+("@{State='Established'}" if connected else '')+" }\n"
        source+="function Get-CimInstance { throw 'ObserveOnly must not reconnect' }\n"
        source+="function Start-ScheduledTask { throw 'ObserveOnly must not start tasks' }\n"
        source+=setup+"\n& $Supervisor -SpoolDir $Spool -SpoolProtocol Stream -ObserveOnly\n"
        wrapper=root/'observe.ps1';wrapper.write_text(source,encoding='utf-8')
        result=subprocess.run([POWERSHELL,'-NoProfile','-NonInteractive','-File',str(wrapper),str(SUPERVISOR),str(root)],
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        return result.stdout.strip()

    def test_live_operator_state_is_read_with_writers_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.prepare(root)
            setup=r'''
$share=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
$stateWriter=[IO.File]::Open((Join-Path $Spool 'worker_state.json'),'Open','ReadWrite',$share)
$descriptorWriter=[IO.File]::Open((Join-Path $Spool 'ipc_descriptor.json'),'Open','ReadWrite',$share)
'''
            self.assertEqual(self.observe(root,setup),'SESSION_ACTIVE')
            self.assertEqual(self.observe(root,connected=False).split(':')[0],'SESSION_PENDING_OPERATOR')

    def test_transient_exclusive_writer_is_retried_and_handles_are_released(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.prepare(root)
            # Release only at the first backoff, proving the initial read failed.
            setup=r'''
$global:fixtureBusy=[IO.File]::Open((Join-Path $Spool 'worker_state.json'),'Open','ReadWrite','None')
function global:Start-Sleep {
 param([int]$Milliseconds)
 if($Milliseconds -ne 100){throw 'Unexpected observation backoff'}
 $global:fixtureBusy.Dispose()
 Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds $Milliseconds
 foreach($name in @('worker_state.json','ipc_descriptor.json')){
  $probe=[IO.File]::Open((Join-Path $Spool $name),'Open','ReadWrite','None');$probe.Dispose()
 }
}
'''
            self.assertEqual(self.observe(root,setup),'SESSION_ACTIVE')

    def test_partial_state_publication_is_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state,_=self.prepare(root)
            original=(root/'worker_state.json').read_text()
            (root/'worker_state.json').write_text('{')
            (root/'complete.json').write_text(original)
            setup=r'''
function global:Start-Sleep {
 param([int]$Milliseconds)
 [IO.File]::WriteAllText((Join-Path $Spool 'worker_state.json'),[IO.File]::ReadAllText((Join-Path $Spool 'complete.json')))
}
'''
            self.assertEqual(self.observe(root,setup),'SESSION_ACTIVE')

    def test_invalid_or_stale_metadata_never_reports_active(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state,descriptor=self.prepare(root)
            for case in ('stopped','stale','future','different-instance','different-hash','invalid-descriptor','oversized'):
                with self.subTest(case=case):
                    self.prepare(root)
                    path=root/'worker_state.json'
                    if case=='stopped':path.write_text(json.dumps({**state,'status':'stopped'}))
                    elif case=='stale':os.utime(path,(1,1))
                    elif case=='future':os.utime(path,(time.time()+60,time.time()+60))
                    elif case=='different-instance':path.write_text(json.dumps({**state,'instance_id':'c'*32}))
                    elif case=='different-hash':path.write_text(json.dumps({**state,'worker_sha256':'d'*64}))
                    elif case=='invalid-descriptor':(root/'ipc_descriptor.json').write_text('{')
                    elif case=='oversized':path.write_text(' '*65537)
                    self.assertTrue(self.observe(root).startswith('SESSION_PENDING_OPERATOR'))

    def test_fresh_stopped_pulse_overrides_running_fallback_with_writer_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state,_=self.prepare(root)
            setup=r'''
$path=Join-Path $Spool ('worker_pulse_'+('a'*32)+'_a.json')
[IO.File]::WriteAllText($path,(@{status='stopped';instance_id=('a'*32);worker_sha256=('b'*64);spool_protocol='stream';last_heartbeat_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress))
$pulseWriter=[IO.File]::Open($path,'Open','ReadWrite',([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
'''
            self.assertTrue(self.observe(root,setup).startswith('SESSION_PENDING_OPERATOR'))
