"""Lifecycle controllers require explicit approval before any execution."""
import hashlib
import json
import copy
import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock
from enclave_gateway.config import ProviderSpec,SecuritySpec
from enclave_gateway.providers.lifecycle import plan,powershell
from enclave_gateway.operations.context import OperationError
from test_operations import engine_at
from enclave_gateway.control.qga_client import ExecResult


class ProviderLifecycleTests(unittest.TestCase):
    def test_manifest_types_and_architectures_are_exact_before_execution(self):
        with TemporaryDirectory() as root:
            spec=self.fixture(root);path=Path(spec.lifecycle_manifest);valid=json.loads(path.read_text())
            cases=[]
            for key,values in {'revision':[True,False,1.0,'1',None],
                               'provider':[True,{},'vipnet'],
                               'versions':['fixture-v1',{},[],[''],['fixture-v1','fixture-v1'],[1]],
                               'architectures':['x86_64',{},[],['unknown'],['x86_64','x86_64'],[True]],
                               'source':[None,1,[],{},'', ' ', 'source\0'],
                               'actions':[None,[],{}, {'unknown':valid['actions']['connect']} ]}.items():
                for value in values:
                    record=copy.deepcopy(valid);record[key]=value;cases.append(record)
            substring=copy.deepcopy(valid);substring['architectures']='x86_64';substring['actions']['connect'][0]['architecture']='x86';cases.append(substring)
            for key,values in {'executable':[None,1,[],{},'', 'exe\0'],
                               'sha256':[True,[],{},'short'], 'publisher':[None,False,{},'', ' '],
                               'version':[None,True,[],{},'fixture'], 'architecture':[True,[],{},'x86','unknown'],
                               'arguments':[None,'literal',{},[1],['\0'],['--profile={profile_file}']],
                               'success_codes':[None,True,[],[True],[0.0]],
                               'timeout_sec':[None,False,'1',0,-1,86401,float('inf'),float('nan')],
                               'stdin_env':[None,True,[],{},'', 'BAD-NAME']}.items():
                for value in values:
                    record=copy.deepcopy(valid);record['actions']['connect'][0][key]=value;cases.append(record)
            # The selected action cannot hide a malformed unselected procedure.
            inactive=copy.deepcopy(valid);inactive['actions']['install'][0]['architecture']=False;cases.append(inactive)
            cases += [None,True,[],['revision']]
            control=Mock();engine=engine_at(root,control);engine.config.provider=spec
            for index,record in enumerate(cases):
                with self.subTest(case=index):
                    path.write_text(json.dumps(record));spec.lifecycle_manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
                    with self.assertRaises(ValueError):engine.provider_manage('connect')
            control.exec_powershell.assert_not_called()
            for architecture in ('arm64','x86_64','x86'):
                record=copy.deepcopy(valid);record['architectures']=[architecture]
                for steps in record['actions'].values():steps[0]['architecture']=architecture
                path.write_text(json.dumps(record));spec.lifecycle_manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(plan(spec,'connect')['steps'][0]['architecture'],architecture)

    def test_ambiguous_oversized_or_nonfinite_json_is_rejected(self):
        from enclave_gateway.providers.lifecycle import MAX_MANIFEST_BYTES
        with TemporaryDirectory() as root:
            spec=self.fixture(root);path=Path(spec.lifecycle_manifest);valid=path.read_text()
            cases=[valid.replace('"revision": 1','"revision": 1, "revision": 1'),
                   valid.replace('"success_codes": [0, 3010]','"success_codes": [0], "success_codes": [0]'),
                   valid.replace('"revision": 1','"revision": NaN'),
                   '['*2000+']'*2000,' '*MAX_MANIFEST_BYTES+'{}']
            for index,raw in enumerate(cases):
                with self.subTest(case=index):
                    path.write_text(raw);spec.lifecycle_manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
                    with self.assertRaises(ValueError):plan(spec,'connect')

    def test_seeded_malformed_documents_fail_with_value_error_without_dispatch(self):
        with TemporaryDirectory() as root:
            spec=self.fixture(root);path=Path(spec.lifecycle_manifest);valid=json.loads(path.read_text());rng=random.Random(9173)
            for index in range(200):
                record=copy.deepcopy(valid);field=rng.choice(list(record));record[field]=rng.choice([None,True,False,0,1.25,[],{},['']])
                path.write_text(json.dumps(record));spec.lifecycle_manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
                with self.subTest(case=index),self.assertRaises(ValueError):plan(spec,'connect')

    def test_invalid_input_and_artifact_mappings_fail_before_file_reads(self):
        with TemporaryDirectory() as root:
            spec=self.fixture(root)
            for name,values in {'lifecycle_inputs':[None,[],{'unknown':'x'},{'profile_file':None}],
                                'lifecycle_local_artifacts':[None,[],{'profile_file':'x'},{'installer':False}],
                                'lifecycle_artifact_publishers':[None,[],{'unknown':'CN=Fixture'},{'installer':''}]}.items():
                original=getattr(spec,name)
                for value in values:
                    with self.subTest(field=name,value=value):
                        setattr(spec,name,value)
                        with self.assertRaises(ValueError):plan(spec,'connect')
                setattr(spec,name,original)
            for action in (None,[],{},True,'unknown'):
                with self.assertRaises(ValueError):plan(spec,action)

    def test_shipped_example_plans_every_action_without_executing_a_controller(self):
        file=Path(__file__).resolve().parents[1]/'config/provider-lifecycle.example.json'
        inputs={'installer':r'C:\EnclaveGateway\approved\installer.msi','key_file':r'C:\EnclaveGateway\approved\key-container.dst',
                'profile_file':r'C:\EnclaveGateway\approved\profile.conf'}
        spec=ProviderSpec(type='custom',lifecycle_manifest=str(file),lifecycle_manifest_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),lifecycle_inputs=inputs)
        manifest=json.loads(file.read_text())
        self.assertEqual(set(manifest['actions']),{'install','connect','disconnect','import_key'})
        with TemporaryDirectory() as root:
            control=Mock();engine=engine_at(root,control);engine.config.provider=spec
            for action,argument in (('install','installer'),('connect','profile_file'),('disconnect','profile_file'),('import_key','key_file')):
                with self.subTest(action=action):
                    result=plan(spec,action);self.assertEqual(result['provider'],'custom');self.assertFalse(result['automatic_reboot'])
                    self.assertIn(inputs[argument],result['steps'][0]['arguments'])
                    self.assertEqual(plan(spec,action)['approval_digest'],result['approval_digest'])
                    self.assertEqual(engine.provider_manage(action)['status'],'planned')
                    with self.assertRaises(OperationError):engine.provider_manage(action,apply=True,approval_digest='wrong')
            control.exec_powershell.assert_not_called()
            engine.config.provider.lifecycle_manifest_sha256='f'*64
            with self.assertRaisesRegex(ValueError,'changed after approval'):plan(spec,'connect')

    def fixture(self,root):
        file=Path(root)/'recipe.json'
        manifest={'revision':1,'provider':'custom','versions':['fixture-v1'],'architectures':['x86_64'],
                  'source':'https://example.enclave.internal/approved-controller-contract',
                  'actions':{action:[{'executable':r'C:\lab\controller.exe','sha256':'a'*64,'publisher':'CN=Fixture',
                    'version':'fixture-v1','architecture':'x86_64','arguments':[action,'{profile_file}'],
                    'success_codes':[0,3010]}] for action in ('install','connect','disconnect','import_key')}}
        file.write_text(json.dumps(manifest))
        return ProviderSpec(type='custom',lifecycle_manifest=str(file),lifecycle_manifest_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),lifecycle_inputs={'profile_file':r'C:\lab\fixture.conf'})

    def test_all_lifecycle_actions_have_deterministic_approval(self):
        with TemporaryDirectory() as root:
            spec=self.fixture(root)
            for action in ('install','connect','disconnect','import_key'):
                document=plan(spec,action)
                self.assertEqual(plan(spec,action)['approval_digest'],document['approval_digest'])
                script=powershell(document['steps'][0],SecuritySpec())
                self.assertIn('Get-AuthenticodeSignature',script)
                self.assertIn('Provider architecture mismatch',script)
                self.assertNotIn('Invoke-Expression',script)
            spec.lifecycle_inputs['profile_file']=r'C:\lab\changed.conf'
            self.assertNotEqual(plan(spec,'connect')['approval_digest'],document['approval_digest'])

    def test_private_artifact_is_staged_verified_and_cleaned(self):
        with TemporaryDirectory() as root:
            spec=self.fixture(root); artifact=Path(root)/'fixture.bin';artifact.write_bytes(b'synthetic-container-only')
            spec.lifecycle_local_artifacts={'key_file':str(artifact)}
            spec.lifecycle_inputs['key_file']=r'C:\lab\fixture.dst'
            manifest=json.loads(Path(spec.lifecycle_manifest).read_text());manifest['actions']['import_key'][0]['arguments']=['import','{key_file}']
            Path(spec.lifecycle_manifest).write_text(json.dumps(manifest));spec.lifecycle_manifest_sha256=hashlib.sha256(Path(spec.lifecycle_manifest).read_bytes()).hexdigest()
            control=Mock();engine=engine_at(root,control);engine.config.provider=spec
            document=engine.provider_manage('import_key')
            self.assertNotIn('synthetic-container-only',json.dumps(document))
            engine.transfer_file=Mock(return_value={'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()})
            def execute(script,**kwargs):
                return ExecResult(0,'STAGE_REMOVED' if 'STAGE_REMOVED' in script else json.dumps({'exit_code':0,'reboot_required':False}),'',0)
            control.exec_powershell.side_effect=execute
            result=engine.provider_manage('import_key',apply=True,approval_digest=document['approval_digest'])
            self.assertEqual(result['cleanup_pending'],[])
            self.assertEqual(engine.transfer_file.call_count,1)
            staged=engine.transfer_file.call_args.args[3]
            self.assertNotEqual(staged,spec.lifecycle_inputs['key_file']);self.assertTrue(staged.endswith('.dst'))

    def test_missing_or_changed_recipe_is_rejected(self):
        with TemporaryDirectory() as root:
            spec=self.fixture(root)
            Path(spec.lifecycle_manifest).write_text('{}')
            with self.assertRaises(ValueError): plan(spec,'connect')
            with self.assertRaises(ValueError): plan(ProviderSpec(),'import_key')

    def test_plan_has_no_execution_and_apply_requires_matching_digest(self):
        with TemporaryDirectory() as root:
            control=Mock(); engine=engine_at(root,control); engine.config.provider=self.fixture(root)
            document=engine.provider_manage('connect')
            control.exec_powershell.assert_not_called()
            with self.assertRaises(OperationError): engine.provider_manage('connect',apply=True,approval_digest='wrong')
            control.exec_powershell.assert_not_called()
            control.exec_powershell.return_value=ExecResult(0,json.dumps({'exit_code':3010,'reboot_required':True}),'',1)
            result=engine.provider_manage('connect',apply=True,approval_digest=document['approval_digest'])
            self.assertTrue(result['reboot_required']); self.assertFalse(result['reboot_performed'])
            self.assertEqual(control.exec_powershell.call_count,1)
