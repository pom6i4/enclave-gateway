"""Extended gates must reject incomplete, stale and altered lab evidence."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/qualification'))
import case_receipt
import extended_acceptance
import generated_security
from lab_artifacts import worker_artifact
from enclave_gateway.hypervisor.state import atomic_json


class ExtendedQualificationTests(unittest.TestCase):
    def test_actual_case_failure_is_retained_and_old_output_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);out=root/'run'
            with self.assertRaises(RuntimeError):case_receipt.run(out,[sys.executable,'-c','raise SystemExit(7)'],[root/'case.json'])
            value=json.loads((out/'result.json').read_text())
            self.assertEqual((value['status'],value['exit_code']),('failed',7))
            with self.assertRaises(FileExistsError):case_receipt.run(out,[sys.executable,'-V'],[root/'case.json'])

    def test_old_reports_are_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p=root/'case.json';p.write_text('{"status":"passed"}')
            with patch.object(case_receipt.subprocess,'Popen') as process:
                with self.assertRaises(FileExistsError):case_receipt.run(root/'run',['unused'],[p])
                process.assert_not_called()

    def test_nested_report_tampering_and_source_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);report=root/'case.json';out=root/'receipt'
            code='from pathlib import Path;Path('+repr(str(report))+').write_text(\'{"status":"passed"}\')'
            case_receipt.run(out,[sys.executable,'-c',code],[report],role='fixture')
            sources=case_receipt.cohort_sources()
            extended_acceptance.verify_receipt(out/'result.json','fixture',sources)
            with self.assertRaises(ValueError):extended_acceptance.verify_receipt(out/'result.json','fixture',{'different':'0'*64})
            (out/'case-0.json').write_text('{"status":"passed","changed":true}')
            with self.assertRaisesRegex(ValueError,'changed'):extended_acceptance.verify_receipt(out/'result.json','fixture',sources)

    def test_reduced_soak_cannot_claim_extended_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);report=root/'soak.json';out=root/'receipt'
            code='from pathlib import Path;Path('+repr(str(report))+').write_text(\'{"status":"passed","scope":"disposable-loopback-long-soak","duration_requested_sec":180,"elapsed_sec":181}\')'
            case_receipt.run(out,[sys.executable,'-c',code],[report],role='long-soak')
            with self.assertRaisesRegex(ValueError,'Two-hour'):extended_acceptance.verify_receipt(out/'result.json','long-soak',case_receipt.cohort_sources())

    def test_failed_extended_step_still_runs_all_cleanup_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);driver=root/'driver.py';driver.write_text('# pinned fixture\n')
            cleanup=[]
            for name in ('first','second'):
                code='from pathlib import Path;import json; p=Path(__import__("sys").argv[1]);p.mkdir(parents=True);(p/"result.json").write_text(json.dumps({"status":"passed","cleanup":"passed"}))'
                cleanup.append({'role':name,'argv':[sys.executable,'-c',code,'{run_dir}/'+name+'/receipt']})
            plan={'revision':1,'scope':'isolated-extended-acceptance','expected_source_tests':160,
                  'inputs_sha256':{str(driver):extended_acceptance.digest(driver)},
                  'steps':[{'role':'fixture','argv':[sys.executable,'-c','raise SystemExit(9)']}],'cleanup':cleanup}
            p=root/'manifest.json';p.write_text(json.dumps(plan))
            with patch.object(extended_acceptance,'REQUIRED',{'fixture'}),self.assertRaises(RuntimeError):extended_acceptance.run(p,root/'run')
            value=json.loads((root/'run/result.json').read_text())
            self.assertEqual(value['status'],'failed');self.assertEqual([s['status'] for s in value['cleanup']],['passed','passed'])
            self.assertEqual(len(value['steps']),1)

    def test_incomplete_profile_is_rejected_before_any_command(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p=root/'manifest.json';p.write_text(json.dumps({'revision':1,'scope':'isolated-extended-acceptance','steps':[]}))
            with patch.object(extended_acceptance.subprocess,'Popen') as process,self.assertRaisesRegex(ValueError,'roles'):extended_acceptance.run(p,root/'out')
            process.assert_not_called()

    def test_counterexample_reduction_replays_and_keeps_cause(self):
        replayed=[]
        def fails(values):replayed.append(list(values));return 'cause' in values
        reduced=generated_security.minimize_sequence(['noise','cause','tail','extra'],fails)
        self.assertEqual(reduced,['cause']);self.assertTrue(replayed)

    def test_seeded_security_models_cover_denial_fragmentation_and_paths(self):
        import random
        rng=random.Random(17)
        generated_security.path_cases(rng,30);generated_security.destination_cases(rng,30);generated_security.proxy_cases(rng,30);generated_security.mux_cases(rng,30)

    def test_external_signature_preserves_source_binding_and_rejects_changed_body(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'worker.ps1';original=(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1').read_bytes()
            p.write_bytes(original+b'\n# SIG # Begin signature block\n# fixture\n# SIG # End signature block\n')
            self.assertEqual(worker_artifact(p),p)
            p.write_bytes(p.read_bytes()+b'Write-Output hidden\n')
            with self.assertRaisesRegex(ValueError,'signature comment'):worker_artifact(p)
            p.write_bytes(b'Write-Output changed\n'+p.read_bytes())
            with self.assertRaises(ValueError):worker_artifact(p)
