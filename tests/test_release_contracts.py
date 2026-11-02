"""Offline lab/release contracts and opt-in native runtime checks."""
from __future__ import annotations
import base64
import importlib.util
import json
import os
import struct
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from enclave_gateway.config import EnclaveConfig, ProviderSpec
from enclave_gateway.providers.adapters import provider_adapter
from enclave_gateway.transports.rdp_vfs import build_parallel_striped_stage_ps, build_parallel_striped_assemble_ps
from enclave_gateway.transports.ssh_hop import _wrap_with_askpass_ps

ROOT=Path(__file__).resolve().parents[1]


def load_script(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class ReleaseContracts(unittest.TestCase):
    def test_lab_seed_has_no_vendor_key_or_network_dependency(self):
        prepare=load_script("lab_prepare","scripts/qualification/prepare_lab.py").prepare
        with TemporaryDirectory() as root:
            folder=Path(root)/"lab"
            report=prepare(folder,"x86_64")
            config=EnclaveConfig.from_dict(json.loads((folder/"lab.json").read_text()))
            self.assertEqual(report["status"],"prepared_only")
            self.assertFalse(report["guest_started"])
            self.assertEqual(config.provider.type,"custom")
            self.assertEqual(config.provider.dst_key_path,"")
            self.assertEqual(config.provider.installer_path,"")
            self.assertEqual(config.bastion.host,"127.0.0.1")
            self.assertFalse(list(folder.rglob("*.dst")))
            with self.assertRaises(FileExistsError): prepare(folder,"x86_64")

    def test_release_package_uses_allowlist_and_never_claims_signature(self):
        prepare=load_script("release_prepare","scripts/release/prepare_package.py").prepare
        with TemporaryDirectory() as root:
            root=Path(root); helper=root/"fixture.exe"; helper.write_bytes(b"MZfixture")
            (root/"unrelated-secret.txt").write_text("not packaged")
            output=root/"package"; report=prepare(output,helper,helper)
            self.assertEqual(report["status"],"unsigned")
            self.assertFalse(report["qualified_windows"])
            names={row["file"] for row in report["files"]}
            self.assertEqual(names,{"egw-askpass.exe","bastion_worker.ps1","bastion_bootstrap.ps1","appliance_init.ps1","session_supervisor.ps1","verify_windows.ps1","install_windows.ps1","egw-runtime.exe"})
            with self.assertRaises(FileExistsError): prepare(output,helper,helper)

    def test_provider_probe_requires_exact_explicit_qualification(self):
        for name in ("vipnet","kontinent","custom","wireguard","anyconnect","openvpn"):
            adapter=provider_adapter(name)
            self.assertFalse(adapter.capabilities()["automatic_key_import"])
            script=adapter.probe_script(ProviderSpec(type=name))
            self.assertIn("$configurationMatched",script)
            self.assertIn("driver_qualification='not_verified'",script)
            if name == "kontinent":
                self.assertEqual(adapter.status_arguments,())
                self.assertEqual(adapter.binary_candidates,())
            if name == 'vipnet':
                self.assertEqual(adapter.status_arguments,('info',))
                self.assertIn(r'%ProgramFiles%\Mobile\bin\vipnetclient.exe',adapter.binary_candidates)
        with self.assertRaises(ValueError): provider_adapter("unknown")

    @unittest.skipUnless(os.environ.get("EGW_TEST_POWERSHELL"),"PowerShell parser is opt-in")
    def test_real_powershell_parser_accepts_agents_and_generated_templates(self):
        power=os.environ["EGW_TEST_POWERSHELL"]
        with TemporaryDirectory() as root:
            root=Path(root)
            generated=[provider_adapter(name).probe_script(ProviderSpec(type=name)) for name in ("vipnet","kontinent","wireguard","openvpn","anyconnect")]
            generated+=[build_parallel_striped_stage_ps(bastion_src_path="C:/fixture/file",vfs_spool="C:/fixture/spool",tx_id="test",block_size=65536,parallel_streams=2),
                        build_parallel_striped_assemble_ps(bastion_dest_path="C:/fixture/file",vfs_spool="C:/fixture/spool",tx_id="test",block_size=65536,parallel_streams=2,file_size=0,expected_sha256="0"*64,changed_indices=[],compress=True,use_delta=False)]
            from enclave_gateway.providers.lifecycle import powershell
            from enclave_gateway.security.scoped_sync import remote_script
            from enclave_gateway.transports.owned_ssh import windows_script
            from enclave_gateway.config import SecuritySpec,TargetNodeSpec
            from enclave_gateway.transports.ssh_hop import build_powershell_ssh_hop_script
            from types import SimpleNamespace
            generated += [powershell({'executable':r'C:\lab\controller.exe','sha256':'a'*64,'publisher':'CN=Fixture','version':'1.0','architecture':'x86_64','arguments':["quoted ' value"],'success_codes':[0]},SecuritySpec()),
                          remote_script({'root':r'C:\lab','action':'list'},windows=True,helper_path=r'C:\lab\runtime.exe'),
                          windows_script({'action':'exec','token':'a'*64,'script':"Write-Output 'fixture'",'timeout_sec':3},SimpleNamespace(helper_options={'trusted_signers':(),'require_signed':True},runtime_helper_path=r'C:\lab\runtime.exe')),
                          build_powershell_ssh_hop_script(TargetNodeSpec('fixture','127.0.0.1',os='windows',user='fixture'),"Write-Output 'fixture'")]
            for index,script in enumerate(generated): (root/f"generated{index}.ps1").write_text(script)
            files=list((ROOT/"src/enclave_gateway/agents").glob("*.ps1"))+list((ROOT/"scripts").rglob("*.ps1"))+list(root.glob("*.ps1"))
            listing=root/"files.json"; listing.write_text(json.dumps([str(path) for path in files]))
            script="$bad=0; foreach($p in (Get-Content -LiteralPath '"+str(listing).replace("'","''")+"' -Raw | ConvertFrom-Json)) {$errors=$null; [void][Management.Automation.Language.Parser]::ParseFile($p,[ref]$null,[ref]$errors); if($errors.Count) {$errors | Out-String | Write-Output; $bad++}}; exit $bad"
            timeout=float(os.environ.get("EGW_TEST_POWERSHELL_TIMEOUT_SEC", "30"))
            self.assertTrue(30 <= timeout <= 240, "Parser fixture timeout must be within 30..240 seconds")
            result=subprocess.run([power,"-NoProfile","-Command",script],capture_output=True,text=True,timeout=timeout)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


@unittest.skipUnless(os.environ.get("EGW_TEST_DOTNET") and os.environ.get("EGW_TEST_HELPER"),"Native helper build is opt-in")
class NativeHelperTests(unittest.TestCase):
    def invoke(self,encoded,args=()):
        environment={**os.environ,"EGW_ASKPASS_B64":encoded}
        return subprocess.run([os.environ["EGW_TEST_DOTNET"],os.environ["EGW_TEST_HELPER"],*args],env=environment,capture_output=True,timeout=10)

    def test_unicode_literal_and_ignored_prompt(self):
        fixture="fixture ' \" ` $ ; & тест"
        result=self.invoke(base64.b64encode(fixture.encode()).decode(),("untrusted prompt",))
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout.decode().strip(),fixture)
        self.assertEqual(result.stderr,b"")

    def test_invalid_inputs_fail_without_disclosing_input(self):
        for encoded in ("", "!invalid", "A"*32769,base64.b64encode(b"\xff").decode(),base64.b64encode(b"x\ny").decode(),base64.b64encode(b"x\0y").decode()):
            with self.subTest(length=len(encoded)):
                result=self.invoke(encoded)
                self.assertEqual(result.returncode,2)
                self.assertEqual((result.stdout,result.stderr),(b"",b""))
        self.assertEqual(self.invoke("Zml4dHVyZQ==",("one","two")).returncode,2)

    def test_cross_compiled_pe_architectures(self):
        for rid,machine in (("win-x64",0x8664),("win-arm64",0xaa64)):
            for component in ('askpass','runtime'):
                file=ROOT/'build'/(component+'-'+rid)/('egw-'+component+'.exe')
                if not file.exists(): self.skipTest('Cross build missing')
                with file.open('rb') as stream:
                    self.assertEqual(stream.read(2),b'MZ')
                    stream.seek(0x3c); offset=struct.unpack('<I',stream.read(4))[0]
                    stream.seek(offset); self.assertEqual(stream.read(4),b'PE\0\0')
                    self.assertEqual(struct.unpack('<H',stream.read(2))[0],machine)

    @unittest.skipUnless(os.environ.get("EGW_TEST_POWERSHELL"),"PowerShell wrapper runtime is opt-in")
    def test_real_wrapper_restores_process_environment(self):
        helper=str(Path(os.environ["EGW_TEST_HELPER"]).with_suffix(".exe" if os.name=="nt" else ""))
        # Explicit unsigned mode is confined to this synthetic local fixture.
        wrapped=_wrap_with_askpass_ps("& $env:SSH_ASKPASS 'ignored prompt'", "fixture-value", "fixture",helper_path=helper,require_signed=False)
        script="$env:EGW_ASKPASS_B64='prior';\n"+wrapped+"\nif ($env:EGW_ASKPASS_B64 -ne 'prior') {throw 'Environment was not restored'}"
        encoded=base64.b64encode(script.encode("utf-16le")).decode()
        environment={**os.environ,"DOTNET_ROOT":str(Path(os.environ["EGW_TEST_DOTNET"]).parent)}
        result=subprocess.run([os.environ["EGW_TEST_POWERSHELL"],"-NoProfile","-EncodedCommand",encoded],env=environment,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),"fixture-value")


if __name__=="__main__": unittest.main()
