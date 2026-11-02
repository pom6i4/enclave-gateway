"""Reject stale build inputs, wrong helpers and nonreproducible payloads."""
import importlib.util
import hashlib
import base64
import io
import json
import os
import socket
import time
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    p=ROOT/'scripts'/name;spec=importlib.util.spec_from_file_location(p.stem,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

release=load('release/reproducible_build.py');tools=load('qualification/toolchain.py');generated=load('qualification/generated_faults.py')
full=load('qualification/full_acceptance.py')
installed=load('qualification/compare_installed.py')
evidence=load('qualification/evidence.py')


class ReproducibleQualificationTests(unittest.TestCase):
    def test_real_socket_coalescence_and_sync_keep_per_frame_limit(self):
        from enclave_gateway.control.wire import SocketLineReader
        frame=b'{"fixture":"value"}\r\n'
        for data,sync,expected in ((frame+frame,False,2),(b'junk'*100+b'\xff'+frame,True,1),(b'x'*(len(frame)+1),False,0)):
            left,right=socket.socketpair()
            try:
                right.sendall(data);right.shutdown(socket.SHUT_WR)
                reader=SocketLineReader(left,time.monotonic()+2,max_bytes=len(frame))
                if sync:reader.sync_marker()
                if expected:
                    self.assertEqual([reader.readline(sync=sync) for _ in range(expected)],[frame.decode()]*expected)
                    with self.assertRaises(ConnectionError):reader.readline()
                else:
                    with self.assertRaises(ValueError):reader.readline()
                self.assertLessEqual(len(reader.buffer),len(frame)+1)
            finally:left.close();right.close()

    def test_inventory_binds_child_results_and_excludes_root_cycle_and_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);child=root/'step';child.mkdir();(child/'result.json').write_text('{"status":"passed"}');(child/'inventory.json').write_text('{}')
            (root/'result.json').write_text('{}');(root/'inventory.json').write_text('{}');(child/'credentials.json').write_text('fixture')
            before=evidence.report_inventory(root)
            self.assertEqual(set(before),{'step/result.json','step/inventory.json'})
            (child/'result.json').write_text('{"status":"failed"}')
            self.assertNotEqual(before['step/result.json'],evidence.report_inventory(root)['step/result.json'])

    def test_source_change_fails_even_if_all_commands_return_success(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'manifest.json';p.write_text(json.dumps({'revision':1,'scope':'isolated-full-acceptance','toolchain':{'python':{'path':'python'}}}))
            process=SimpleNamespace(returncode=0,pid=123,wait=lambda **_:None,poll=lambda:0)
            with patch.object(full,'cohort_sources',side_effect=[{'s':'before'},{'s':'after'}]),patch.object(full,'preflight',return_value={}),patch.object(full.release,'build'),patch.object(full.subprocess,'Popen',return_value=process):
                with self.assertRaisesRegex(RuntimeError,'cohort changed'):full.run(p,root/'run',host_only=True)
            self.assertEqual(json.loads((root/'run/result.json').read_text())['status'],'failed')

    def test_installed_matrix_normalizes_windows_paths_and_rejects_stale_or_failed_reports(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'input';src.mkdir()
            for name in ('README.md','LICENSE','pyproject.toml'):(src/name).write_text(name)
            (src/'src/enclave_gateway').mkdir(parents=True);(src/'src/enclave_gateway/a.py').write_text('fixture')
            hashes=installed.inputs(src);p=root/'report.json';value={'status':'passed','platform':{'system':'Windows','machine':'AMD64','python':'fixture'},'source_sha256':{n.replace('/','\\'):v for n,v in hashes.items()},'artifacts':{'wheel':'fixture'}}
            p.write_text(json.dumps(value));self.assertEqual(installed.compare([p],root/'ok.json',['windows:x86_64'],src)['status'],'passed')
            value['source_sha256']['README.md']='stale';p.write_text(json.dumps(value))
            with self.assertRaises(ValueError):installed.compare([p],root/'stale.json',root=src)
            value['source_sha256']={};value['status']='failed';p.write_text(json.dumps(value))
            with self.assertRaises(ValueError):installed.compare([p],root/'failed.json',root=src)
            with self.assertRaises(ValueError):installed.normalize({'src\\a.py':'a','src/a.py':'a'})
    def test_runtime_archive_hash_does_not_hide_modified_expanded_cache(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);package=root/'fixture.nupkg';payload=root/'runtimes/win-x64/native/value.dll';payload.parent.mkdir(parents=True);payload.write_bytes(b'approved')
            with zipfile.ZipFile(package,'w') as z:z.write(payload,payload.relative_to(root).as_posix())
            package.with_suffix('.nupkg.sha512').write_text(base64.b64encode(hashlib.sha512(package.read_bytes()).digest()).decode())
            release.verify_package(package)
            payload.write_bytes(b'stale')
            with self.assertRaisesRegex(ValueError,'Expanded runtime'):release.verify_package(package)

    def test_guest_pass_requires_complete_counts_cleanup_and_causal_pki(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);values={'windows-suite.json':{'status':'passed','cleanup':'passed'},'preparation.json':{'status':'passed','checks':['a']*2},'migration.json':{'status':'passed','checks':['a']*9},
              'pki.json':{'status':'passed','checks':['a']*12,'nonce_elapsed_ms':[200]*9,'nonce_deadline_ms':10000,'chain_status':{'revoked':['Revoked'],'ocsp-revoked':['Revoked'],'expired':['NotTimeValid'],'cache':['RevocationStatusUnknown'],'stale':['RevocationStatusUnknown']}}}
            def write():
                for n,v in values.items():(root/n).write_text(json.dumps(v))
            write();full.verify_guest_results(root)
            values['pki.json']['nonce_elapsed_ms'][0]=10000;write()
            with self.assertRaises(ValueError):full.verify_guest_results(root)
            values['pki.json']['nonce_elapsed_ms'][0]=200;values['windows-suite.json']['cleanup']='failed';write()
            with self.assertRaises(RuntimeError):full.verify_guest_results(root)

    def test_full_plan_rejects_unapproved_media_before_tools_or_guest_access(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);media=root/'media';media.write_bytes(b'input')
            manifest={'revision':1,'scope':'isolated-full-acceptance','toolchain':{},'windows':{'windows_iso':str(media)},'media_sha256':{'windows_iso':'0'*64}}
            p=root/'manifest.json';p.write_text(json.dumps(manifest))
            with patch.object(full,'preflight') as preflight,patch.object(full,'owned_hypervisor') as vm:
                with self.assertRaises(ValueError):full.run(p,root/'run')
                preflight.assert_not_called();vm.assert_not_called()
            self.assertEqual(json.loads((root/'run/result.json').read_text())['status'],'failed')

    def test_failed_full_host_step_preserves_failure_and_never_runs_later_steps(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'manifest.json';p.write_text(json.dumps({'revision':1,'scope':'isolated-full-acceptance','toolchain':{'python':{'path':'python'}}}))
            process=SimpleNamespace(returncode=7,pid=123,wait=lambda **_:None,poll=lambda:7)
            with patch.object(full,'preflight',return_value={}),patch.object(full.release,'build'),patch.object(full.subprocess,'Popen',return_value=process),patch.object(full,'owned_hypervisor') as vm:
                with self.assertRaises(RuntimeError):full.run(p,root/'run',host_only=True)
                vm.assert_not_called()
            value=json.loads((root/'run/result.json').read_text())
            self.assertEqual(value['scope'],'host-only');self.assertEqual(value['status'],'failed')
            self.assertEqual([s['name'] for s in value['steps']],['preflight','independent-release-builds','source-tests'])
            self.assertEqual(value['steps'][-1]['status'],'failed')

    def test_export_ignores_old_obj_and_rejects_source_links(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d)/'input';r.mkdir()
            for name in ('README.md','LICENSE','pyproject.toml'):(r/name).write_text(name)
            (r/'native/askpass/obj').mkdir(parents=True);(r/'native/askpass/obj/old.cs').write_text('stale attribute')
            (r/'native/askpass/Program.cs').write_text('source')
            out=Path(d)/'output';release.export_source(out,1700000000,r)
            self.assertFalse((out/'native/askpass/obj').exists());self.assertEqual((out/'native/askpass/Program.cs').read_text(),'source')
            self.assertEqual(int((out/'README.md').stat().st_mtime),1700000000)
            if os.name!='nt':
                (r/'native/askpass/linked.cs').symlink_to(r/'native/askpass/Program.cs')
                with self.assertRaises(ValueError):release.export_source(Path(d)/'rejected',1700000000,r)

    def test_payload_difference_cannot_be_hidden_by_archive_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d)
            for label,mtime in (('a',11),('b',19)):
                with tarfile.open(r/(label+'.tar.gz'),'w:gz') as z:
                    entry=tarfile.TarInfo('package/value');entry.size=7;entry.mtime=mtime;entry.uid=mtime;z.addfile(entry,io.BytesIO(b'payload'))
                (r/label).mkdir();release.canonical_sdist(r/(label+'.tar.gz'),r/label/'package.tar.gz',1700000000)
            release.verify_equal(r/'a',r/'b')
            (r/'b/package.tar.gz').write_bytes(b'changed')
            with self.assertRaises(ValueError):release.verify_equal(r/'a',r/'b')
            with tarfile.open(r/'unsafe.tar.gz','w:gz') as z:z.addfile(tarfile.TarInfo('../outside'))
            with self.assertRaises(ValueError):release.canonical_sdist(r/'unsafe.tar.gz',r/'rejected.tar.gz',1700000000)

    def test_wrong_tool_identity_and_wrong_helper_fail_before_tests(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'tool';p.write_bytes(b'tool');item={'path':str(p),'sha256':'0'*64,'version':'fixture'}
            with patch.object(release.subprocess,'check_output') as call:
                with self.assertRaises(ValueError):release.checked_tool(item,[],{})
                call.assert_not_called()
            item['sha256']=release.digest(p)
            with patch.object(release.subprocess,'check_output',return_value='other'):
                with self.assertRaises(ValueError):release.checked_tool(item,[],{})
            with patch.object(tools.subprocess,'run',return_value=SimpleNamespace(returncode=2,stdout=b'',stderr=b'')):
                with self.assertRaisesRegex(ValueError,'dedicated askpass'):tools.askpass_probe('dotnet',p,{})

    @unittest.skipIf(os.name=='nt','POSIX venv executable link')
    def test_venv_entry_is_not_replaced_by_resolved_base_interpreter(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'base';target.write_bytes(b'python');entry=Path(d)/'venv/bin/python';entry.parent.mkdir(parents=True);entry.symlink_to(target)
            item={'path':str(entry),'sha256':release.digest(target),'version':'fixture'}
            with patch.object(release.subprocess,'check_output',return_value='fixture') as call:
                self.assertEqual(release.checked_tool(item,[],{}),str(entry));self.assertEqual(call.call_args.args[0][0],str(entry))

    def test_seeded_models_fragmentation_and_at_most_once_across_restarts(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'models';report=generated.run(out,seeds=(17,911),cases=30)
            self.assertEqual(report['status'],'passed')
            old=(out/'result.json').read_bytes()
            with self.assertRaises(FileExistsError):generated.run(out)
            self.assertEqual((out/'result.json').read_bytes(),old)
