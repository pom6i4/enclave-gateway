"""Existing machine integrations must be rejected before payload replacement."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.provision.builder import ProvisionOptions,ApplianceProvisioner

ROOT=Path(__file__).resolve().parents[1]


def invoke_harness(harness,path):
    harness=harness.replace('$PSCommandPath',"'"+str(path).replace("'","''")+"'")
    path.write_text(harness,encoding='utf-8-sig')
    literal="'"+str(path).replace("'","''")+"'"
    loader='& ([scriptblock]::Create([IO.File]::ReadAllText('+literal+')))'
    encoded=base64.b64encode(loader.encode('utf-16le')).decode()
    return subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-EncodedCommand',encoded],capture_output=True,timeout=60)


class CompletionModeTests(unittest.TestCase):
    def test_explicit_completion_policy_roundtrip_and_invalid_mode(self):
        with self.assertRaises(ValueError):ProvisionOptions(completion_mode='unknown')
        with tempfile.TemporaryDirectory() as folder:
            for mode in ('StartupTask','SetupComplete'):
                path=Path(folder)/mode
                ApplianceProvisioner(EnclaveConfig()).prepare_bundle(path,ProvisionOptions(completion_mode=mode))
                self.assertEqual(json.loads((path/'provision-media.json').read_text())['completion_mode'],mode)

    @unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
    def test_conflicting_task_and_hook_do_not_replace_staged_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            quote=lambda value:"'"+str(value).replace("'","''")+"'"
            for mode in ('StartupTask','SetupComplete'):
                path=root/mode;path.mkdir();hooks=path/'hooks';hooks.mkdir();(hooks/'SetupComplete.cmd').write_text('existing hook')
                source=(ROOT/'src/enclave_gateway/agents/machine_prepare.ps1').read_text()
                source=source.replace("$install='C:\\EnclaveGateway'",'$install='+quote(path))
                source=source.replace("$scripts=Join-Path $env:SystemRoot 'Setup\\Scripts'",'$scripts='+quote(hooks))
                source=source.replace('$PSScriptRoot',quote(path))
                harness=r'''
$ErrorActionPreference='Stop';$script:copies=0
function Get-ItemProperty {param($Path);return @{SystemSetupInProgress=1;OOBEInProgress=1}}
function Get-ScheduledTask {[CmdletBinding()]param($TaskName);return [pscustomobject]@{Actions=@([pscustomobject]@{Execute='different';Arguments='different'});Principal=[pscustomobject]@{UserId='different'}}}
function Copy-Item {[CmdletBinding()]param($LiteralPath,$Destination,[switch]$Force);$script:copies++;throw 'Copy ran before conflict validation'}
$failure='';try {& {SOURCE} -Architecture x86_64 -CompletionMode MODE} catch {$failure=$_.Exception.Message}
if($script:copies -ne 0 -or $failure -notlike 'Existing *requires explicit integration'){throw ('Conflict preservation failed: '+$failure)}
'''.replace('SOURCE',source).replace('MODE',quote(mode))
                value=invoke_harness(harness,path/'harness.ps1')
                self.assertEqual(value.returncode,0,(value.stdout+value.stderr).decode('utf-8','replace'))
                self.assertEqual((hooks/'SetupComplete.cmd').read_text(),'existing hook')

    @unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
    def test_completed_generation_cleans_task_before_ready_without_reinstall(self):
        with tempfile.TemporaryDirectory() as folder:
            for case in ('delete-failure','success','already-removed'):
                root=Path(folder)/case;root.mkdir()
                policy={'revision':1,'guest_agent_sha256':'a'*64,'completion_mode':'StartupTask'}
                (root/'provision-media.json').write_text(json.dumps(policy))
                prior={'revision':1,'status':'machine_ready','architecture':'x86_64','approved_sha256':'a'*64,'qga_mode':'msi-native','media_verification':'sha256-pin'}
                before=json.dumps(prior);(root/'provision-machine.json').write_text(before)
                quote=lambda value:"'"+str(value).replace("'","''")+"'"
                source=(ROOT/'src/enclave_gateway/agents/machine_prepare.ps1').read_text().replace("$install='C:\\EnclaveGateway'",'$install='+quote(root)).replace('$PSScriptRoot',quote(root))
                harness=r'''
$case=CASE;$root=ROOT;$script:taskExists=($case -ne 'already-removed');$script:deletions=0
function Get-ItemProperty {param($Path);return @{SystemSetupInProgress=0;OOBEInProgress=0;SetupType=0}}
function Get-Service {[CmdletBinding()]param($Name);return [pscustomobject]@{Status='Running'}}
function Get-PSDrive {[CmdletBinding()]param($PSProvider);throw 'Completed preparation must not reinstall from media'}
function Get-ScheduledTask {
 [CmdletBinding()]param($TaskName)
 if(-not $script:taskExists){return}
 $expected="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$root\machine_prepare.ps1`" -Architecture x86_64 -CompleteSetup -WaitForSetup"
 return [pscustomobject]@{Actions=@([pscustomobject]@{Execute="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe";Arguments=$expected});Principal=[pscustomobject]@{UserId='SYSTEM'}}
}
function Unregister-ScheduledTask {
 [CmdletBinding(SupportsShouldProcess=$true)]param($TaskName)
 $script:deletions++
 if($case -eq 'delete-failure'){throw 'Simulated deletion failure'}
 $script:taskExists=$false
}
$failed=$false;try{& {SOURCE} -Architecture x86_64 -CompleteSetup -WaitForSetup}catch{$failed=$true;if($case -ne 'delete-failure'){throw}}
$m=Get-Content (Join-Path $root 'provision-machine.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($case -eq 'delete-failure'){
 if(-not $failed -or $m.revision -ne 1){throw 'Readiness published before deletion completed'}
}else{
 if($failed -or $script:taskExists -or $m.revision -ne 2 -or -not $m.completion_task_removed){throw 'Completed generation did not finalize'}
}
'''.replace('CASE',quote(case)).replace('ROOT',quote(root)).replace('SOURCE',source)
                result=invoke_harness(harness,root/'harness.ps1')
                self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode('utf-8','replace'))
                if case=='delete-failure':self.assertEqual((root/'provision-machine.json').read_text(),before)

    @unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
    def test_actual_kill_after_task_deletion_recovers_without_media(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            quote=lambda value:"'"+str(value).replace("'","''")+"'"
            (root/'provision-media.json').write_text(json.dumps({'revision':1,'guest_agent_sha256':'a'*64,'completion_mode':'StartupTask'}))
            (root/'provision-machine.json').write_text(json.dumps({'revision':1,'status':'machine_ready','architecture':'x86_64','approved_sha256':'a'*64,'qga_mode':'msi-native','media_verification':'sha256-pin'}))
            (root/'task').touch()
            source=(ROOT/'src/enclave_gateway/agents/machine_prepare.ps1').read_text().replace("$install='C:\\EnclaveGateway'",'$install='+quote(root)).replace('$PSScriptRoot',quote(root))
            harness=r"""
$ErrorActionPreference='Stop';$root=ROOT
function Get-ItemProperty {param($Path);return @{SystemSetupInProgress=0;OOBEInProgress=0;SetupType=0}}
function Get-Service {[CmdletBinding()]param($Name);return [pscustomobject]@{Status='Running'}}
function Get-PSDrive {[CmdletBinding()]param($PSProvider);throw 'Recovery entered the MSI/media path'}
function Get-ScheduledTask {
 [CmdletBinding()]param($TaskName)
 if(-not (Test-Path (Join-Path $root 'task'))){return}
 $expected="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$root\machine_prepare.ps1`" -Architecture x86_64 -CompleteSetup -WaitForSetup"
 [pscustomobject]@{Actions=@([pscustomobject]@{Execute="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe";Arguments=$expected});Principal=[pscustomobject]@{UserId='SYSTEM'}}
}
function Unregister-ScheduledTask {
 [CmdletBinding(SupportsShouldProcess=$true)]param($TaskName)
 Remove-Item (Join-Path $root 'task')
 # Model the first-ever publication gap, with no previous readiness record.
 Remove-Item (Join-Path $root 'provision-machine.json')
 [IO.File]::WriteAllText((Join-Path $root 'deleted'),'barrier')
 Start-Sleep -Seconds 180
}
& {SOURCE} -Architecture x86_64 -CompleteSetup -RecoverOnly:([bool]$env:EGW_RECOVER_FIXTURE)
""".replace('ROOT',quote(root)).replace('SOURCE',source)
            path=root/'harness.ps1';harness=harness.replace('$PSCommandPath',quote(path));path.write_text(harness,encoding='utf-8-sig')
            loader='& ([scriptblock]::Create([IO.File]::ReadAllText('+quote(path)+')))'
            command=[os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-EncodedCommand',base64.b64encode(loader.encode('utf-16le')).decode()]
            with subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as process:
                try:
                    deadline=time.monotonic()+30
                    while not (root/'deleted').exists():
                        if process.poll() is not None or time.monotonic()>deadline:
                            raise AssertionError(process.communicate(timeout=2))
                        time.sleep(.02)
                    process.kill();process.communicate(timeout=5)
                finally:
                    if process.poll() is None:process.kill();process.communicate(timeout=5)
            self.assertFalse((root/'provision-machine.json').exists())
            self.assertEqual(json.loads((root/'machine-prepared.json').read_text())['status'],'prepared')
            result=subprocess.run(command,env={**os.environ,'EGW_RECOVER_FIXTURE':'1'},capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode('utf-8','replace'))
            self.assertEqual(json.loads((root/'provision-machine.json').read_text())['revision'],2)
            self.assertFalse((root/'task').exists())
            self.assertFalse(list(root.glob('.machine-*')))
