"""Real rooted file operations, including adversarial links and remote execution."""
import base64
import hashlib
import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from enclave_gateway.agents.rooted_fs import RootedFS, request
from enclave_gateway.security.scoped_sync import synchronize, remote_script


@unittest.skipIf(os.name=='nt','Native Windows protocol has a separate runtime fixture')
class ScopedSyncTests(unittest.TestCase):
    def test_binary_empty_unicode_and_atomic_replacement(self):
        with TemporaryDirectory() as temp:
            temp=str(Path(temp).resolve())
            source=Path(temp)/'source'; destination=Path(temp)/'destination'
            source.mkdir(); destination.mkdir(); (source/'sub').mkdir()
            for name,data in [('empty',b''),("sub/тест ' .bin",bytes(range(256))*1800)]: (source/name).write_bytes(data)
            def endpoint(root): return lambda payload:request({**payload,'root':str(root)})
            result=synchronize(endpoint(source),endpoint(destination))
            self.assertEqual(result['files_synced'],2)
            self.assertEqual((destination/"sub/тест ' .bin").read_bytes(),(source/"sub/тест ' .bin").read_bytes())
            self.assertEqual((destination/'empty').read_bytes(),b'')
            self.assertFalse(list(destination.rglob('.egw_sync_*')))
            (source/'empty').write_bytes(b'changed')
            synchronize(endpoint(source),endpoint(destination))
            self.assertEqual((destination/'empty').read_bytes(),b'changed')

    def test_engine_scoped_sync_uses_protocol_instead_of_tar(self):
        from test_operations import engine_at
        from enclave_gateway.security.policy import Grant,grant_scope
        from enclave_gateway.control.qga_client import ExecResult
        from unittest.mock import Mock
        with TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); source=root/'source';guest=root/'guest';source.mkdir();guest.mkdir()
            (source/'run.sh').write_bytes(b'#!/bin/sh\necho fixture\n');(source/'run.sh').chmod(0o755)
            engine=engine_at(root,Mock())
            def execute(node,script,**kwargs):
                self.assertNotIn('tar -x',script)
                result=subprocess.run(['sh','-s'],input=script,text=True,capture_output=True,timeout=10)
                return ExecResult(result.returncode,result.stdout,result.stderr,0)
            engine.exec_node=execute
            grant=Grant('fixture',('node_sync',),nodes=('app01',),write_roots={'app01':[str(guest)]},local_read_roots=(str(source),))
            with grant_scope(grant): result=engine.sync_directory('push',source,'app01',str(guest))
            self.assertEqual(result['mode'],'rooted-files')
            self.assertEqual((guest/'run.sh').read_bytes(),(source/'run.sh').read_bytes())
            self.assertEqual((guest/'run.sh').stat().st_mode&0o777,0o755)

    def test_symlink_hardlink_fifo_and_traversal_cannot_escape(self):
        with TemporaryDirectory() as temp:
            temp=str(Path(temp).resolve())
            root=Path(temp)/'root'; root.mkdir(); outside=Path(temp)/'outside'; outside.write_bytes(b'unchanged')
            (root/'link').symlink_to(outside)
            os.link(outside,root/'hard')
            os.mkfifo(root/'pipe')
            with RootedFS(str(root)) as fs:
                for name in ('link','hard','pipe','../outside'):
                    with self.subTest(name=name),self.assertRaises((ValueError,OSError)):
                        fs.read(name,0,10)
                (root/'dir').symlink_to(root.parent,target_is_directory=True)
                with self.assertRaises(OSError): fs.write('dir/outside',0,b'changed')
            self.assertEqual(outside.read_bytes(),b'unchanged')

    def test_remote_protocol_runs_without_installed_package(self):
        with TemporaryDirectory() as temp:
            temp=str(Path(temp).resolve())
            (Path(temp)/'file').write_bytes(b'fixture')
            script=remote_script({'root':temp,'action':'list'})
            process=subprocess.run(['sh','-c',script],capture_output=True,text=True,timeout=10,env={'PATH':os.environ['PATH']})
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertEqual(json.loads(process.stdout)['entries'][0]['sha256'],hashlib.sha256(b'fixture').hexdigest())

    def test_wrong_hash_preserves_destination(self):
        with TemporaryDirectory() as temp:
            temp=str(Path(temp).resolve())
            root=Path(temp); (root/'target').write_bytes(b'old')
            with RootedFS(temp) as fs:
                fs.write('stage',0,b'new')
                with self.assertRaises(ValueError): fs.commit('stage','target','0'*64)
            self.assertEqual((root/'target').read_bytes(),b'old')
