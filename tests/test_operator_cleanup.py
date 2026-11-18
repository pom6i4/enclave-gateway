"""Large stopped operator spools retain evidence and clean in one local pass."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from enclave_gateway.spool_cleanup import cleanup_script


@unittest.skipUnless(os.name=='nt','Requires native Windows same-handle deletion')
class WindowsOperatorCleanupTests(unittest.TestCase):
    def run_cleanup(self, root, stage=False, locked=False):
        executable=os.environ.get('EGW_TEST_POWERSHELL') or shutil.which('powershell.exe')
        if not executable:self.skipTest('Windows PowerShell is unavailable')
        script=cleanup_script(str(root),execution_profile='structured_only',structured_backend='operator',
                              prepare_for_start=stage)
        if locked:
            script="$fixtureLease=[IO.File]::Open('"+str(root/'.worker-session').replace("'","''")+"','Open','ReadWrite','None')\n"+script
        source=root.parent/'cleanup.ps1'
        source.write_text(script,encoding='utf-8')
        result=subprocess.run([executable,'-NoProfile','-NonInteractive','-File',str(source)],
                              capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        return json.loads(result.stdout.split('APPLIANCE_CLEAN_OK:',1)[1])

    def prepare(self, root):
        root.mkdir()
        (root/'.worker-session').touch()
        (root/'worker_state.json').write_text(json.dumps(dict(status='stopped',instance_id='a'*32,
            execution_profile='structured_only',structured_backend='operator',spool_protocol='stream')))
        (root/'worker_structured_storage.json').write_text(json.dumps(dict(revision=1,owner_sha256='b'*64)))
        (root/'ipc_descriptor.json').write_text('preserved descriptor')
        (root/'.structured-transactions').mkdir()
        (root/'.structured-transactions/receipt.json').write_text('durable evidence')

    def test_clean_reclaims_400_scrubbed_megabyte_slots_and_preserves_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'spool';self.prepare(root)
            for index in range(400):
                with (root/('ipc_res_'+'a'*32+'_'+str(index)+'.bin')).open('wb') as stream:
                    stream.truncate(1024*1024)
            payload=root/('ipc_upload_'+'a'*32+'.bin');payload.write_bytes(b'unconsumed payload')
            locked=self.run_cleanup(root,locked=True)
            self.assertFalse(locked['stopped_worker_verified'])
            self.assertEqual(len(list(root.glob('ipc_res_*'))),400)
            result=self.run_cleanup(root)
            self.assertTrue(result['stopped_worker_verified'])
            self.assertEqual(result['stream_cleanup'],'complete')
            self.assertEqual(result['removed'],400)
            self.assertEqual(result['stream_preserved'],1)
            self.assertEqual(payload.read_bytes(),b'unconsumed payload')
            self.assertFalse(list(root.glob('ipc_res_*')))
            self.assertEqual((root/'.structured-transactions/receipt.json').read_text(),'durable evidence')
            self.assertTrue((root/'worker_state.json').exists())

    def test_stage_retires_400_slots_and_publication_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'spool';self.prepare(root)
            for index in range(400):
                (root/('ipc_res_'+'a'*32+'_'+str(index)+'.bin')).write_bytes(b'preserve')
            result=self.run_cleanup(root,stage=True)
            self.assertEqual(result['stream_cleanup'],'complete')
            self.assertEqual(result['retired_state_files'],402)
            retired=Path(result['retired_state_directory'])
            self.assertTrue((retired/'worker_state.json').exists())
            self.assertTrue((retired/'ipc_descriptor.json').exists())
            self.assertFalse((root/'worker_state.json').exists())
            self.assertEqual(len(list(retired.glob('ipc_res_*'))),400)
