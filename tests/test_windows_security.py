"""Cold security readback must retain the full readiness check and fail closed."""
import importlib.util
import base64
import json
import os
from pathlib import Path
import subprocess
import unittest

from enclave_gateway.control.qga_client import ExecResult

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('disposable_windows',ROOT/'scripts/qualification/disposable_windows.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class SecurityReadbackTests(unittest.TestCase):
    def agent(self,value=None,error=None):
        class Agent:
            calls=[]
            def exec_powershell(self,script,timeout_sec):
                self.calls.append((script,timeout_sec))
                if error:raise error
                return ExecResult(0,json.dumps(value),'',0)
        return Agent()

    def test_one_attempt_retains_120_second_budget(self):
        value={'query_revision':2,'attempts':1,'secure_boot':True,'tpm_present':True,'tpm_ready':True}
        agent=self.agent(value)
        self.assertEqual(fixture.verify_guest_security(agent,secure_boot=True,tpm=True),value)
        self.assertEqual(len(agent.calls),1);self.assertEqual(agent.calls[0][1],120)
        timeout=TimeoutError('fixture cold timeout');agent=self.agent(error=timeout)
        with self.assertRaises(TimeoutError) as raised:fixture.verify_guest_security(agent,secure_boot=True,tpm=True)
        self.assertIs(raised.exception,timeout);self.assertEqual(len(agent.calls),1)

    def test_false_missing_and_malformed_evidence_is_not_accepted(self):
        value={'query_revision':2,'attempts':1,'secure_boot':True,'tpm_present':True,'tpm_ready':True}
        for key,bad in [('secure_boot',False),('secure_boot','True'),('tpm_present',False),('tpm_ready',False),('tpm_ready',1),('attempts',2),('attempts',True),('query_revision',True)]:
            with self.subTest(key=key,bad=bad),self.assertRaises(RuntimeError):
                fixture.verify_guest_security(self.agent({**value,key:bad}),secure_boot=True,tpm=True)
        for malformed in ({},[],None):
            with self.subTest(malformed=malformed),self.assertRaises(RuntimeError):fixture.verify_guest_security(self.agent(malformed),secure_boot=True,tpm=True)

    @unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
    def test_runtime_checks_full_readiness_and_provider_errors(self):
        # Execute the actual query against a synthetic CIM provider. Activation
        # and ownership are deliberately false: only IsReady is authoritative.
        harness=r'''
$case=CASE
function Get-Tpm {throw 'Broad TPM inventory must not be invoked'}
function Confirm-SecureBootUEFI {[CmdletBinding()]param();return ($case -ne 'secure-boot-disabled')}
function Get-CimInstance {
 [CmdletBinding()]param($Namespace,$ClassName)
 if($Namespace -ne 'root/CIMV2/Security/MicrosoftTpm' -or $ClassName -ne 'Win32_Tpm'){throw 'Wrong provider'}
 if($case -eq 'missing'){return}
 $device=[pscustomobject]@{ManufacturerId=[uint32]0x49424d00;IsActivated_InitialValue=$false;IsOwned_InitialValue=$false}
 if($case -eq 'duplicate'){$device};$device
}
function Invoke-CimMethod {
 [CmdletBinding()]param($InputObject,$MethodName)
 if($MethodName -ne 'IsReady'){throw 'Wrong readiness method'}
 if($case -eq 'provider-failure'){return [pscustomobject]@{ReturnValue=[uint32]1;IsReady=$true}}
 if($case -eq 'invalid'){return [pscustomobject]@{ReturnValue=[uint32]0;IsReady='True'}}
 return [pscustomobject]@{ReturnValue=[uint32]0;IsReady=($case -ne 'not-ready')}
}
QUERY
'''
        class Agent:
            def __init__(self,case):self.case=case
            def exec_powershell(self,script,timeout_sec):
                source=harness.replace('CASE',"'"+self.case+"'").replace('QUERY',script)
                # Match QGA's in-memory command entry point. The fixture does
                # not alter AllSigned policy or trust an unsigned script file.
                encoded=base64.b64encode(source.encode('utf-16le')).decode('ascii')
                timeout=float(os.environ.get('EGW_TEST_POWERSHELL_TIMEOUT_SEC','30'));assert 30<=timeout<=240
                result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,text=True,timeout=timeout)
                if self.case=='ready' and result.returncode:raise AssertionError(result.stderr)
                return ExecResult(result.returncode,result.stdout,result.stderr,0)
        value=fixture.verify_guest_security(Agent('ready'),secure_boot=True,tpm=True)
        self.assertTrue(value['tpm_ready']);self.assertEqual(value['tpm_manufacturer'],'IBM');self.assertEqual(value['tpm_readiness_source'],'Win32_Tpm.IsReady')
        for case in ('secure-boot-disabled','missing','duplicate','not-ready','provider-failure','invalid'):
            with self.subTest(case=case),self.assertRaises(RuntimeError):fixture.verify_guest_security(Agent(case),secure_boot=True,tpm=True)
