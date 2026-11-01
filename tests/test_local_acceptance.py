"""Local runner must preserve failures, deadlines and resource ownership."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from enclave_gateway.config import ApplianceSpec,EnclaveConfig
from enclave_gateway.hypervisor.driver import ApplianceHypervisor
from enclave_gateway.provision.builder import ApplianceProvisioner

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('local_acceptance',ROOT/'scripts/qualification/local_acceptance.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class LocalAcceptanceTests(unittest.TestCase):
    def test_failure_stops_plan_and_keeps_original_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);plan=root/'plan.json';out=root/'run'
            plan.write_text(json.dumps({'revision':1,'scope':'isolated-local-qualification','steps':[
                {'name':'fail','argv':['{python}','-c','raise SystemExit(7)']},
                {'name':'never','argv':['{python}','-c',"raise RuntimeError('must not run')"]}]}))
            value=runner.run(plan,out)
            self.assertEqual(value['status'],'failed');self.assertEqual(len(value['steps']),1)
            self.assertEqual(value['steps'][0]['exit_code'],7)
            old=(out/'result.json').read_bytes()
            with self.assertRaises(FileExistsError):runner.run(plan,out)
            self.assertEqual((out/'result.json').read_bytes(),old)

    def test_timeout_reaps_its_process_and_retains_failed_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);plan=root/'plan.json'
            plan.write_text(json.dumps({'revision':1,'scope':'isolated-local-qualification','steps':[
                {'name':'timeout','argv':['{python}','-c','import time;time.sleep(30)'],'timeout_sec':1}]}))
            value=runner.run(plan,root/'run')
            self.assertEqual(value['status'],'failed');self.assertEqual(value['steps'][0]['status'],'timed_out')

    def test_resources_outside_new_run_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);plan=root/'plan.json'
            plan.write_text(json.dumps({'revision':1,'scope':'isolated-local-qualification','steps':[{'argv':['{python}','-V']}],
                                        'managed_vm_configs':[str(root/'unowned.json')]}))
            with self.assertRaises(ValueError):runner.run(plan,root/'run')

    def test_failed_step_cleanup_checks_actual_disk_before_shutdown(self):
        code="""from pathlib import Path
import sys,json
r=Path(sys.argv[1]);(r/'vm.json').write_text(json.dumps({'appliance':{'name':'egw-lab-owned','network_restrict':True,'disk_path':str(r/'disk.qcow2'),'efi_vars_path':str(r/'vars.fd'),'runtime_dir':str(r/'runtime'),'tpm_state_dir':sys.argv[2]},'provider':{'type':'custom','installer_path':'','dst_key_path':''}}))
raise SystemExit(7)
"""
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for matching,tpm_owned in ((False,True),(True,True),(True,False)):
                label=str(matching)+'-'+str(tpm_owned);out=root/label;plan=root/(label+'.json')
                tpm=str(out/'tpm' if tpm_owned else root/'unowned-tpm')
                plan.write_text(json.dumps({'revision':1,'scope':'isolated-local-qualification','managed_vm_configs':['{run_dir}/vm.json'],
                                            'steps':[{'argv':['{python}','-c',code,'{run_dir}',tpm]}]}))
                with patch.object(runner,'ApplianceHypervisor') as factory:
                    h=factory.return_value;h.is_running.return_value=(True,42)
                    h.qmp.execute.return_value={'return':[{'inserted':{'image':{'filename':str(out/'disk.qcow2' if matching else root/'unowned.qcow2')}}}]}
                    result=runner.run(plan,out)
                    self.assertEqual(result['status'],'failed')
                    if matching and tpm_owned:
                        h.stop.assert_called_once();self.assertEqual(result['cleanup'][0]['status'],'stopped')
                    else:
                        h.stop.assert_not_called();h._stop_tpm.assert_not_called();self.assertEqual(result['cleanup'][0]['status'],'failed')

    def test_windows_tpm_rejection_precedes_any_provision_mutation(self):
        with tempfile.TemporaryDirectory() as folder,patch('enclave_gateway.hypervisor.driver.platform.system',return_value='Windows'):
            destination=Path(folder)/'untouched';cfg=EnclaveConfig(appliance=ApplianceSpec(tpm_state_dir=str(Path(folder)/'tpm')))
            with self.assertRaisesRegex(ValueError,'TPM emulator backend'):ApplianceProvisioner(cfg).prepare_bundle(destination,create_disk=True)
            self.assertFalse(destination.exists())
            self.assertFalse(ApplianceHypervisor.tpm_capabilities()['managed_software_tpm'])
