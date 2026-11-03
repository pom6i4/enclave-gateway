"""Opt-in current-user HKCU lifecycle using only a private local Windows spool."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid

from enclave_gateway import __file__ as package_file
from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.security.secrets import SecretVault


@unittest.skipUnless(os.name == 'nt' and os.environ.get('EGW_TEST_WINDOWS_AUTOSTART') == '1',
                     'Current-user Windows registry fixture is opt-in')
class WindowsAutostartTests(unittest.TestCase):
    def test_registration_replay_tamper_denial_and_acknowledged_removal(self):
        import winreg
        run_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        value = 'EnclaveGatewayWorker'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, run_path) as key:
            try:
                winreg.QueryValueEx(key, value)
            except FileNotFoundError:
                pass
            else:
                self.skipTest('Preserve an existing worker autostart registration')
        agents = Path(package_file).parent / 'agents'
        shell = str(Path(os.environ['SystemRoot']) / r'System32\WindowsPowerShell\v1.0\powershell.exe')
        # Keep the HKCU Run command within Windows' 260-character limit.
        install = Path(tempfile.mkdtemp(prefix='EU', dir=os.environ['LOCALAPPDATA']))
        processes = []
        unrelated = 'EGWFixture_' + uuid.uuid4().hex
        try:
            with tempfile.TemporaryDirectory(prefix='egw-autostart-') as name:
                root = Path(name)
                spool = root / 'spool'
                spool.mkdir()
                cfg = EnclaveConfig.from_dict({
                    'security': {'mode': 'standard'}, 'appliance': {'hypervisor': 'direct'},
                    'bastion': {'enabled': True, 'spool_protocol': 'stream',
                                'appliance_spool_dir': str(spool), 'bastion_spool_dir': str(spool)}})
                engine = EnclaveEngine(cfg, vault=SecretVault(env_file=root / '.env'),
                                       recorder=FlightRecorder(root / 'audit.jsonl'))

                def launch(command, label):
                    with (root / (label + '.log')).open('wb') as log:
                        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                                   stdout=log, stderr=subprocess.STDOUT)
                    processes.append(process)
                    return process

                def ready(process):
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), 'Worker exited; inspect fixture logs')
                        try:
                            state = json.loads((spool / 'worker_state.json').read_text(encoding='utf-8-sig'))
                        except (OSError, ValueError):
                            state = {}
                        if state.get('status') == 'running':
                            return state
                        time.sleep(.1)
                    self.fail('Worker did not become ready within 30 seconds')

                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, run_path) as key:
                    winreg.SetValueEx(key, unrelated, 0, winreg.REG_SZ, 'preserve')
                first = launch([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
                                '-File', str(agents / 'bastion_bootstrap.ps1'), '-Mode', 'Standard',
                                '-WorkerPath', str(agents / 'bastion_worker.ps1'), '-SourceSpool', str(spool),
                                '-InstallDir', str(install), '-StateRoot', str(root / 'state'),
                                '-SpoolProtocol', 'Stream', '-MigrateLegacyState', '-RegisterAutostart'], 'first')
                before = ready(first)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_path) as key:
                    command, kind = winreg.QueryValueEx(key, value)
                self.assertEqual(kind, winreg.REG_SZ)
                self.assertLessEqual(len(command), 260)
                self.assertNotIn('MigrateLegacyState', command)
                self.assertNotIn('Bypass', command)
                settings = json.loads((install / 'autostart.json').read_text())
                self.assertEqual(settings['spool_protocol'], 'Stream')
                self.assertFalse(settings['process_isolation'])
                self.assertFalse(settings['require_signed_agents'])
                self.assertNotIn('migrate', json.dumps(settings).lower())
                self.assertEqual((install / 'start_worker.ps1').read_bytes(),
                                 (agents / 'bastion_bootstrap.ps1').read_bytes())
                self.assertEqual(engine.exec_node('@bastion', "Write-Output 'FIRST_OK'", timeout_sec=30).stdout.strip(), 'FIRST_OK')
                self.assertEqual(engine.stop_worker(timeout_sec=30).exit_code, 0)
                self.assertEqual(first.wait(timeout=15), 0)
                replay = launch(command, 'replay')
                after = ready(replay)
                self.assertNotEqual(before['instance_id'], after['instance_id'])
                self.assertEqual(after['journal_location'], 'bastion-local')
                self.assertEqual(engine.exec_node('@bastion', "Write-Output 'REPLAY_OK'", timeout_sec=30).stdout.strip(), 'REPLAY_OK')
                self.assertEqual(engine.stop_worker(timeout_sec=30, unregister_autostart=True).stdout,
                                 'WORKER_STOP_ACCEPTED;AUTOSTART_UNREGISTERED')
                self.assertEqual(replay.wait(timeout=15), 0)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_path) as key:
                    with self.assertRaises(FileNotFoundError):
                        winreg.QueryValueEx(key, value)
                    self.assertEqual(winreg.QueryValueEx(key, unrelated)[0], 'preserve')
                worker = Path(settings['worker_path'])
                worker.write_bytes(worker.read_bytes() + b'\r\n# Changed fixture bytes\r\n')
                denied = launch(command, 'tampered')
                self.assertNotEqual(denied.wait(timeout=15), 0)
                self.assertIn('Autostart script content mismatch', (root / 'tampered.log').read_text(errors='replace'))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, run_path) as key:
                for name in (value, unrelated):
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
            __import__('shutil').rmtree(install)
