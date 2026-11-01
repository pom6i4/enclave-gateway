"""Exercise the full public fixture control flow through its final cleanup."""
import argparse
from contextlib import contextmanager,redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from enclave_gateway.control.qga_client import ExecResult

ROOT=Path(__file__).resolve().parents[1]


def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts/qualification'/f'{name}.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class DisposableLifecycleTests(unittest.TestCase):
    def test_full_flow_always_cleans_owned_vm_and_preserves_failure_status(self):
        for failure in (None,'post-install','cleanup'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);media=root/'qemu-ga-x86_64.msi';media.write_bytes(b'fixture media')
                out=root/'run';runner=module('disposable_windows');lifecycle=module('windows_lifecycle')
                args=argparse.Namespace(output=out,guest_agent_msi=media,arch='x86_64',accelerator='tcg',cpus=2,memory_mb=4096,
                    firmware_code=media,firmware_vars=media,tpm=True,secure_boot=True,port_base=24689,vnc_display=106,
                    windows_iso=media,virtio_iso=media,virtio_directory=None,deadline_sec=60,completion_mode='StartupTask',full_lifecycle=True)
                replies=iter([ExecResult(0,json.dumps({'ready':True,'machine':True}),'',0),
                              ExecResult(1 if failure=='post-install' else 0,'','',0),
                              ExecResult(0,json.dumps({'status':'machine_ready'}),'',0)])
                class Agent:
                    @contextmanager
                    def _connect_synced(self,*args):yield None,None
                    def _request(self,*args):return {}
                    def exec_powershell(self,*args,**kwargs):return next(replies)
                    def sync_guest_clock(self):return True
                def cli(argv,**kwargs):
                    if '--create-disk' in argv:
                        (out/'seed').mkdir();(out/'seed/post_install.ps1').write_text('fixture post install')
                    return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
                with patch.dict(sys.modules,{'windows_lifecycle':lifecycle}),patch.object(runner.subprocess,'run',side_effect=cli),\
                     patch.object(runner.tempfile,'mkdtemp',return_value=str(root/'runtime')),\
                     patch.object(runner,'seed_iso'),patch.object(runner,'QgaClient',return_value=Agent()),\
                     patch.object(runner,'verify_guest_security',return_value={'attempts':1,'secure_boot':True,'tpm_ready':True}),\
                     patch.object(lifecycle,'blank_disk',return_value={'status':'passed'}),\
                     patch.object(lifecycle,'powercycle',return_value={'status':'passed'}) as cycle,\
                     patch.object(lifecycle,'cleanup',side_effect=RuntimeError('owned cleanup failure') if failure=='cleanup' else None) as cleanup,\
                     redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaises(RuntimeError):runner.run(args)
                    else:self.assertEqual(runner.run(args)['status'],'passed')
                    cleanup.assert_called_once_with(out.resolve())
                    self.assertEqual(cycle.call_count,0 if failure=='post-install' else 1)
                report=json.loads((out/'result.json').read_text())
                self.assertEqual(report['status'],'failed' if failure else 'passed')
                self.assertEqual(report['cleanup'],'failed' if failure=='cleanup' else 'passed')
