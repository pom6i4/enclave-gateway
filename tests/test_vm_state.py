"""Exercise real qcow2 bundles and recovery after an actual process crash."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from enclave_gateway.config import ApplianceSpec
from enclave_gateway.hypervisor.state import StateStore,inventory


@unittest.skipUnless(shutil.which('qemu-img'),'qemu-img integration fixture')
class VmStateTests(unittest.TestCase):
    def test_long_profile_name_captures_a_complete_pinned_base(self):
        from enclave_gateway.config import EnclaveConfig
        from enclave_gateway.provision.builder import ApplianceProvisioner
        with TemporaryDirectory() as folder:
            root=Path(folder);store=self.fixture(root)
            result=ApplianceProvisioner(EnclaveConfig(appliance=store.spec)).create_cow_profile('p'*64,output_dir=root/'profile',create_disk=True)
            profile=EnclaveConfig.from_dict(json.loads(Path(result['profile_config']).read_text()))
            try:
                base=Path(profile.appliance.profile_base_bundle)
                self.assertEqual(base,base.resolve())
                self.assertLessEqual(len(base.name),80)
                self.assertTrue(profile.appliance.profile_base_manifest_sha256)
                self.assertEqual((base/'nvram').read_bytes(),Path(profile.appliance.efi_vars_path).read_bytes())
                self.assertEqual((base/'tpm/tpm2-00.permall').read_bytes(),Path(profile.appliance.tpm_state_dir,'tpm2-00.permall').read_bytes())
                info=json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(profile.appliance.resolved_disk_path)]))
                self.assertEqual(Path(info['full-backing-filename']).resolve(),(base/'disk').resolve())
            finally:shutil.rmtree(profile.appliance.runtime_dir)

    def fixture(self,root):
        disk=root/'disk.qcow2';subprocess.run(['qemu-img','create','-f','qcow2',str(disk),'8M'],check=True,capture_output=True)
        nvram=root/'vars.fd';nvram.write_bytes(b'original-vars')
        firmware=root/'code.fd';firmware.write_bytes(b'firmware')
        tpm=root/'tpm';tpm.mkdir(mode=0o700);(tpm/'tpm2-00.permall').write_bytes(b'original-tpm')
        spec=ApplianceSpec(arch='arm64',disk_path=str(disk),efi_vars_path=str(nvram),efi_code_path=str(firmware),tpm_state_dir=str(tpm),runtime_dir=str(root/'runtime'))
        return StateStore(spec,firmware)

    def test_restore_all_resources_and_reject_corruption_before_mutation(self):
        with TemporaryDirectory() as folder:
            root=Path(folder);store=self.fixture(root)
            with store.locked():
                store.create('golden')
                (root/'vars.fd').write_bytes(b'changed-vars');(root/'tpm/tpm2-00.permall').write_bytes(b'changed-tpm')
                store.restore('golden')
                self.assertEqual((root/'vars.fd').read_bytes(),b'original-vars')
                self.assertEqual((root/'tpm/tpm2-00.permall').read_bytes(),b'original-tpm')
                before={k:inventory(p) for k,p in store.targets.items()}
                (store.root/'golden/nvram').write_bytes(b'tampered')
                with self.assertRaisesRegex(ValueError,'integrity'):store.restore('golden')
                self.assertEqual(before,{k:inventory(p) for k,p in store.targets.items()})

    def test_crash_between_resource_renames_recovers_previous_generation(self):
        with TemporaryDirectory() as folder:
            root=Path(folder);store=self.fixture(root)
            with store.locked():store.create('golden')
            (root/'vars.fd').write_bytes(b'before-interrupted-restore')
            (root/'tpm/tpm2-00.permall').write_bytes(b'before-tpm')
            before={k:inventory(p) for k,p in store.targets.items()}
            script='''
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[2])
from enclave_gateway.config import ApplianceSpec
from enclave_gateway.hypervisor.state import StateStore
r=Path(sys.argv[1]);s=StateStore(ApplianceSpec(arch='arm64',disk_path=str(r/'disk.qcow2'),efi_vars_path=str(r/'vars.fd'),tpm_state_dir=str(r/'tpm')),r/'code.fd')
replace=os.replace
def crash(source,destination):
 replace(source,destination)
 if Path(destination)==r/'vars.fd':os._exit(73)
os.replace=crash
with s.locked():s.restore('golden')
'''
            environment={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
            child=subprocess.run([sys.executable,'-c',script,str(root),str(Path(__file__).resolve().parents[1]/'src')],env=environment,capture_output=True,timeout=20)
            self.assertEqual(child.returncode,73,child.stderr)
            self.assertTrue(store.pending.exists())
            with store.locked():self.assertTrue(store.recover())
            self.assertFalse(store.pending.exists())
            self.assertEqual(before,{k:inventory(p) for k,p in store.targets.items()})

    def test_firmware_mismatch_and_missing_tpm_are_rejected(self):
        with TemporaryDirectory() as folder:
            root=Path(folder);store=self.fixture(root)
            with store.locked():
                store.create('golden');(root/'code.fd').write_bytes(b'new-firmware')
                with self.assertRaisesRegex(ValueError,'Incompatible'):store.restore('golden')
                with self.assertRaises(ValueError):store.create('../escape')

    def test_enospc_during_staging_keeps_current_generation(self):
        with TemporaryDirectory() as folder:
            root=Path(folder);store=self.fixture(root)
            with store.locked():
                store.create('golden');before={k:inventory(p) for k,p in store.targets.items()}
                import errno
                with patch('enclave_gateway.hypervisor.state.copy_resource',side_effect=OSError(errno.ENOSPC,'fixture disk full')):
                    with self.assertRaises(OSError):store.restore('golden')
                self.assertEqual(before,{k:inventory(p) for k,p in store.targets.items()})
                self.assertFalse(store.pending.exists())

    def test_bundle_flattens_backing_chain(self):
        with TemporaryDirectory() as folder:
            root=Path(folder);store=self.fixture(root);base=root/'backing.qcow2'
            os.replace(root/'disk.qcow2',base)
            subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(base),str(root/'disk.qcow2')],check=True,capture_output=True)
            with store.locked():store.create('golden')
            info=json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(store.root/'golden/disk')]))
            self.assertNotIn('backing-filename',info)
            execute=subprocess.run
            def change_backing(command,**options):
                result=execute(command,**options)
                if command[1]=='convert':
                    with base.open('ab') as stream:stream.write(b'changed-source-generation')
                return result
            with store.locked(),patch('enclave_gateway.hypervisor.state.subprocess.run',side_effect=change_backing):
                with self.assertRaisesRegex(RuntimeError,'state changed'):store.create('changing')
            self.assertFalse((store.root/'changing').exists())
