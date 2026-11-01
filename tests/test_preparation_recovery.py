"""Controller recovery executes the real PowerShell bootstrap in a scoped fixture."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.provision.recovery import recover_machine

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
class ControllerRecoveryTests(unittest.TestCase):
    def test_matching_generation_and_fail_closed_source_journal_process_guards(self):
        with tempfile.TemporaryDirectory() as folder:
            for case in ('success','changed-source','missing-journal','active-preparation','wrong-generation'):
                with self.subTest(case=case):
                    root=Path(folder)/case;root.mkdir()
                    quote=lambda value:"'"+str(value).replace("'","''")+"'"
                    source=ROOT/'src/enclave_gateway/agents/machine_prepare.ps1'
                    entry=root/'machine_prepare.ps1'
                    entry.write_text(source.read_text().replace("$install='C:\\EnclaveGateway'",'$install='+quote(root)),encoding='utf-8-sig')
                    expected=hashlib.sha256(entry.read_bytes()).hexdigest()
                    (root/'provision-media.json').write_text(json.dumps({'revision':1,'guest_agent_sha256':'a'*64,'completion_mode':'StartupTask'}))
                    prepared={'revision':1,'status':'prepared','architecture':'x86_64','qga_mode':'msi-native','media_verification':'sha256-pin',
                              'approved_sha256':'a'*64,'completion_mode':'StartupTask','script_sha256':expected}
                    if case=='wrong-generation':prepared['architecture']='arm64'
                    if case!='missing-journal':(root/'machine-prepared.json').write_text(json.dumps(prepared))
                    if case=='changed-source':entry.write_bytes(entry.read_bytes()+b'\n# changed fixture source\n')
                    class Agent:
                        def exec_powershell(self,script,timeout_sec):
                            # Keep the production checks, changing only the fixed
                            # administrative path and its source identity to the
                            # private fixture's otherwise identical entry point.
                            script=script.replace("$root='C:\\EnclaveGateway'",'$root='+quote(root)).replace(hashlib.sha256(source.read_bytes()).hexdigest(),expected)
                            harness=r'''
$ErrorActionPreference='Stop';$InformationPreference='SilentlyContinue'
function Get-CimInstance {[CmdletBinding()]param($ClassName,$Filter);ACTIVE}
function Get-ItemProperty {param($Path);return @{SystemSetupInProgress=0;OOBEInProgress=0;SetupType=0}}
function Get-Service {[CmdletBinding()]param($Name);return [pscustomobject]@{Status='Running'}}
function Get-ScheduledTask {[CmdletBinding()]param($TaskName);return}
function Get-PSDrive {[CmdletBinding()]param($PSProvider);throw 'Controller recovery attempted MSI/media enumeration'}
SCRIPT
'''.replace('ACTIVE',r'''return [pscustomobject]@{ProcessId=2147483647;CommandLine='powershell.exe -File "C:\EnclaveGateway\machine_prepare.ps1" -CompleteSetup'}''' if case=='active-preparation' else 'return').replace('SCRIPT',script)
                            path=root/'controller-harness.ps1';path.write_text(harness,encoding='utf-8-sig')
                            # The per-process test policy permits its unsigned
                            # temporary file without changing machine policy.
                            result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,text=True,timeout=60)
                            return ExecResult(result.returncode,result.stdout,result.stderr,0)
                    if case=='success':
                        value=recover_machine(Agent(),'x86_64');self.assertEqual(value['status'],'machine_ready')
                        self.assertTrue(value['completion_task_removed'])
                    else:
                        with self.assertRaises(RuntimeError):recover_machine(Agent(),'x86_64')
                        self.assertFalse((root/'provision-machine.json').exists())
