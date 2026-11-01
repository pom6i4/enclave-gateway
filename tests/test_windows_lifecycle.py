"""Blank-disk and cleanup ownership checks use actual qcow2 metadata."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('windows_lifecycle',ROOT/'scripts/qualification/windows_lifecycle.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class WindowsLifecycleTests(unittest.TestCase):
    @unittest.skipIf(os.name=='nt','Managed software TPM process ownership is POSIX-only')
    def test_tpm_identity_ignores_unrelated_unbalanced_command_lines(self):
        spec=SimpleNamespace(tpm_socket=Path('/tmp/egw-lab/tpm.sock'),tpm_state_dir='/tmp/egw-lab/tpm')
        rows="42 unrelated 'argument swtpm socket\n73 /usr/bin/swtpm socket --tpmstate dir=/tmp/egw-lab/tpm --ctrl type=unixio,path=/tmp/egw-lab/tpm.sock\n"
        with patch.object(fixture.subprocess,'check_output',return_value=rows):
            self.assertEqual(fixture.owned_tpm_pid(spec),73)
        with patch.object(fixture.subprocess,'check_output',return_value=rows+rows):
            with self.assertRaises(RuntimeError):fixture.owned_tpm_pid(spec)

    @unittest.skipUnless(shutil.which('qemu-img') and shutil.which('qemu-io'),'QEMU disk tools are opt-in')
    def test_real_blank_image_and_guest_data_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'seed').mkdir()
            shutil.copyfile(ROOT/'src/enclave_gateway/agents/machine_prepare.ps1',root/'seed/machine_prepare.ps1')
            media=root/'media';media.write_bytes(b'disposable fixture')
            args=argparse.Namespace(windows_iso=media,guest_agent_msi=media,firmware_code=media,firmware_vars=media,
                                    completion_mode='StartupTask',virtio_iso=None,virtio_directory=None)
            disk=root/'disk.qcow2'
            subprocess.run(['qemu-img','create','-f','qcow2',str(disk),'32G'],capture_output=True,check=True)
            proof=fixture.blank_disk(root,args)
            self.assertFalse(proof['guest_data_allocated']);self.assertIsNone(proof['backing_file'])
            subprocess.run(['qemu-io','-f','qcow2','-c','write -P 0x41 0 512',str(disk)],check=True,capture_output=True)
            with self.assertRaises(RuntimeError):fixture.blank_disk(root,args)
            # Previous evidence remains a record of the pre-boot observation.
            self.assertEqual(json.loads((root/'blank-disk-and-source.json').read_text()),proof)

    def test_foreign_network_and_storage_rejected_before_hypervisor_access(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            config={'appliance':{'name':'egw-lab-test','network_restrict':True,'disk_path':str(root/'disk.qcow2'),
                      'efi_vars_path':str(root/'vars.fd')},'provider':{'type':'custom','installer_path':'','dst_key_path':''},'bastion':{'enabled':False}}
            for change in ({'name':'foreign'},{'network_restrict':False},{'disk_path':str(root.parent/'foreign.qcow2')}):
                (root/'config.json').write_text(json.dumps({**config,'appliance':{**config['appliance'],**change}}))
                with patch.object(fixture,'ApplianceHypervisor') as driver:
                    with self.assertRaises(ValueError):fixture.cleanup(root)
                    driver.assert_not_called()
