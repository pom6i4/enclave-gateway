"""A candidate cannot hide changed bytes, extra files or stale platform evidence."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('candidate_assembly',ROOT/'scripts/release/assemble_candidate.py')
candidate=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(candidate)


class CandidateAssemblyTests(unittest.TestCase):
    def fixture(self,root):
        (root/'README.md').write_text('unsigned fixture')
        payload={'README.md':candidate.sha(root/'README.md')}
        (root/'PROVENANCE.json').write_text(json.dumps({'status':'unsigned-candidate','source_commit':'a'*40,'payload_sha256':payload}))
        files=candidate.inventory(root)
        (root/'SHA256SUMS').write_text(''.join(value+'  '+name+'\n' for name,value in sorted(files.items())))

    def reports(self):
        wheel='enclave_gateway-0.2.0-py3-none-any.whl';artifacts={wheel:'a'*64}
        for rid in ('win-x64','win-arm64'):
            for name in ('egw-runtime.exe','egw-askpass.exe'):artifacts[rid+'/'+name]='b'*64
        rows=[]
        for system,machine in [('Linux','arm64'),('Windows','x86_64'),('Windows','arm64')]:
            values={wheel:artifacts[wheel]}
            if system=='Windows':
                rid='win-x64' if machine=='x86_64' else 'win-arm64'
                values.update({k:v for k,v in artifacts.items() if k.startswith(rid+'/')})
            checks={name:True for name in ('wheel_install','cli','isolated_import','native_filesystem','native_cancellation','askpass','sdk_independent','lab_signatures','unsigned_policy_denied','posix_execution','rooted_files','owned_cancellation','mcp_read_only')}
            rows.append({'revision':1,'status':'passed','scope':'release-artifact-acceptance','qualifier_sha256':'c'*64,'platform':{'system':system,'machine':machine},'artifacts':values,'checks':checks})
        return artifacts,rows

    def test_verification_reads_complete_inventory_and_cli_without_side_effects(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);before=candidate.inventory(root)
            self.assertEqual(candidate.verify(root)['status'],'passed')
            result=subprocess.run([sys.executable,str(ROOT/'scripts/release/assemble_candidate.py'),'verify','--candidate',str(root)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout)['status'],'passed')
            self.assertEqual(before,candidate.inventory(root))

    def test_changed_missing_extra_and_duplicate_members_are_rejected(self):
        for change in ('changed','missing','extra','duplicate','escape'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as d:
                root=Path(d);self.fixture(root)
                if change=='changed':(root/'README.md').write_text('changed')
                elif change=='missing':(root/'README.md').unlink()
                elif change=='extra':(root/'unlisted.txt').write_text('extra')
                else:
                    with (root/'SHA256SUMS').open('a') as stream:stream.write(('a'*64+'  ../outside\n') if change=='escape' else (root/'SHA256SUMS').read_text().splitlines()[0]+'\n')
                with self.assertRaises(ValueError):candidate.verify(root)

    def test_linked_candidate_and_changed_input_hash_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);file=root/'README.md';ref={'path':str(file),'sha256':candidate.sha(file)}
            self.assertEqual(candidate._ref(ref),file);file.write_text('new')
            with self.assertRaises(ValueError):candidate._ref(ref)
            target=root/'real.txt';target.write_text('fixture');file.unlink()
            try:file.symlink_to(target)
            except OSError:self.skipTest('Host does not grant symbolic-link creation')
            with self.assertRaises(ValueError):candidate.inventory(root)

    def test_platform_receipts_bind_all_delivered_bytes_and_checks(self):
        artifacts,rows=self.reports();required=['linux:arm64','windows:x86_64','windows:arm64']
        self.assertEqual(len(candidate.acceptance(rows,artifacts,required,'c'*64)),3)
        for field,value in [('qualifier_sha256','d'*64),('status','failed'),('revision',True)]:
            changed=json.loads(json.dumps(rows));changed[0][field]=value
            with self.assertRaises(ValueError):candidate.acceptance(changed,artifacts,required,'c'*64)
        for changed in (rows[:-1],rows+rows[:1]):
            with self.assertRaises(ValueError):candidate.acceptance(changed,artifacts,required,'c'*64)
        changed=json.loads(json.dumps(rows));changed[1]['checks']['sdk_independent']=False
        with self.assertRaises(ValueError):candidate.acceptance(changed,artifacts,required,'c'*64)
        changed=json.loads(json.dumps(rows));changed[0]['artifacts'][next(iter(changed[0]['artifacts']))]='e'*64
        with self.assertRaises(ValueError):candidate.acceptance(changed,artifacts,required,'c'*64)
        with self.assertRaises(ValueError):candidate.acceptance(rows,artifacts,['linux:arm64'],'c'*64)
        qualified=json.loads(json.dumps(rows))
        for row in qualified:
            if row['platform']['system']=='Windows':
                row['native_qualifier_sha256']='f'*64
                row['lab_trust_cleanup']='own key/trust removed; original stores preserved'
        self.assertEqual(len(candidate.acceptance(qualified,artifacts,required,'c'*64,'f'*64)),3)
        with self.assertRaises(ValueError):candidate.acceptance(qualified,artifacts,required,'c'*64,'e'*64)
        qualified[1]['lab_trust_cleanup']='incomplete'
        with self.assertRaises(ValueError):candidate.acceptance(qualified,artifacts,required,'c'*64,'f'*64)

    def test_git_commit_binding_rejects_ignored_and_assume_unchanged_sources(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'docs').mkdir();product=root/'product.py';product.write_text('version=1')
            for name in ('LICENSE','CHANGELOG.md','docs/RELEASING.md'):(root/name).write_text('committed fixture')
            def git(*args):
                return subprocess.check_output(['git','-C',str(root),'-c','user.name=Roman Kuligin','-c','user.email=91665362+pom6i4@users.noreply.github.com','-c','commit.gpgSign=false',*args],stderr=subprocess.DEVNULL)
            git('init','--initial-branch=main');git('add','.');git('commit','-m','Fixture');commit=git('rev-parse','HEAD').decode().strip()
            sources={'product.py':candidate.sha(product)};contents=candidate.committed_inputs(root,commit,sources)
            self.assertEqual(contents['product.py'],b'version=1')
            git('update-index','--assume-unchanged','product.py');product.write_text('version=2')
            self.assertEqual(git('status','--porcelain'),b'')
            with self.assertRaises(ValueError):candidate.committed_inputs(root,commit,{'product.py':candidate.sha(product)})
            product.write_text('version=1');ignored=root/'ignored.py';ignored.write_text('uncommitted')
            (root/'.git/info/exclude').write_text('ignored.py\n')
            self.assertEqual(git('status','--porcelain'),b'')
            with self.assertRaises(ValueError):candidate.committed_inputs(root,commit,{**sources,'ignored.py':candidate.sha(ignored)})

    def test_assembly_rejects_output_inside_source_build_or_cache_without_writes(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);source=base/'source';build=base/'build';cache=base/'cache'
            for path in (source,build,cache):path.mkdir()
            comparison=build/'result.json';comparison.write_text('{}');toolchain=base/'toolchain.json';toolchain.write_text(json.dumps({'nuget_packages':str(cache)}))
            ref=lambda path:{'path':str(path),'sha256':candidate.sha(path)}
            manifest={'revision':1,'source_commit':'a'*40,'comparison':ref(comparison),'toolchain':ref(toolchain),'schemas':[],'acceptance':[],'required_platforms':[],'evidence':[]}
            plan=base/'plan.json';plan.write_text(json.dumps(manifest));before=candidate.inventory(base)
            with patch.object(candidate,'_git',side_effect=lambda root,*args:b'a'*40 if args[0]=='rev-parse' else b''):
                for output in (source/'kit',build/'kit',cache/'kit',Path('relative-kit')):
                    with self.subTest(output=str(output)),self.assertRaises(ValueError):candidate.assemble(plan,output,source)
            self.assertEqual(candidate.inventory(base),before)

    def test_ambiguous_checksum_provenance_and_json_cannot_be_approved(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);doc=json.loads((root/'PROVENANCE.json').read_text());doc['payload_sha256']={};(root/'PROVENANCE.json').write_text(json.dumps(doc))
            files=candidate.inventory(root);files.pop('SHA256SUMS');(root/'SHA256SUMS').write_text(''.join(value+'  '+name+'\n' for name,value in files.items()))
            with self.assertRaises(ValueError):candidate.verify(root)
        for raw in ('{"revision":1,"revision":1}','{"revision":NaN}'):
            with self.assertRaises(ValueError):candidate._json(raw)


class ArtifactReceiptTests(unittest.TestCase):
    def test_failed_receipt_publication_preserves_last_diagnostic(self):
        spec=importlib.util.spec_from_file_location('artifact_acceptance',ROOT/'scripts/qualification/artifact_acceptance.py')
        qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualifier)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=root/'result.json';before={'status':'running','completed':['wheel-install']}
            qualifier.write_receipt(report,before)
            with patch.object(qualifier.os,'replace',side_effect=OSError('simulated disk publication failure')):
                with self.assertRaises(OSError):qualifier.write_receipt(report,{'status':'passed'})
            self.assertEqual(json.loads(report.read_text()),before)
            self.assertEqual({p.name for p in root.iterdir()},{'result.json'})
            qualifier.write_receipt(report,{'status':'failed'})
            self.assertEqual(json.loads(report.read_text())['status'],'failed')

    def test_windows_reader_sharing_conflict_does_not_lose_receipt(self):
        spec=importlib.util.spec_from_file_location('artifact_sharing',ROOT/'scripts/qualification/artifact_acceptance.py')
        qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualifier)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=root/'result.json';qualifier.write_receipt(report,{'status':'running'})
            original=qualifier.os.replace;attempts=[];busy=PermissionError('simulated Windows reader');busy.winerror=32
            def replace(source,target):
                attempts.append(True)
                if len(attempts)==1:raise busy
                return original(source,target)
            with patch.object(qualifier.os,'replace',side_effect=replace),patch.object(qualifier.time,'sleep'):
                qualifier.write_receipt(report,{'status':'passed'})
            self.assertEqual(len(attempts),2);self.assertEqual(json.loads(report.read_text())['status'],'passed')
            self.assertEqual({p.name for p in root.iterdir()},{'result.json'})
            with patch.object(qualifier.os,'replace',side_effect=busy),patch.object(qualifier.time,'monotonic',side_effect=[0,3]):
                with self.assertRaises(PermissionError):qualifier.write_receipt(report,{'status':'must-not-publish'})
            self.assertEqual(json.loads(report.read_text())['status'],'passed')
            self.assertEqual({p.name for p in root.iterdir()},{'result.json'})

    def test_emulated_wrong_architecture_cannot_qualify_native_helpers(self):
        spec=importlib.util.spec_from_file_location('artifact_pe',ROOT/'scripts/qualification/artifact_acceptance.py')
        qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualifier)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'helper.exe';data=bytearray(72);data[:2]=b'MZ';data[60:64]=(64).to_bytes(4,'little');data[64:70]=b'PE\0\0'+(0x8664).to_bytes(2,'little');path.write_bytes(data)
            qualifier.check_pe(path,'x86_64')
            with self.assertRaises(ValueError):qualifier.check_pe(path,'arm64')
            for raw in (b'',b'MZ',b'not-an-executable'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):qualifier.check_pe(path,'x86_64')
