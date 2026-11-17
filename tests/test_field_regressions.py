"""Field regressions with local files and opt-in PowerShell fault fixtures."""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.cli import main
from enclave_gateway.config import BastionSpec, TargetNodeSpec
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.spool_cleanup import cleanup_script
from enclave_gateway.transports.structured import StructuredSshExecutor, StructuredTransport
from enclave_gateway.worker_channel import require_running_worker

WORKER = Path(__file__).resolve().parents[1] / 'src/enclave_gateway/agents/bastion_structured.ps1'


class HeartbeatTests(unittest.TestCase):
    def test_chunked_copy_refreshes_future_heartbeat_after_original_expiry(self):
        wall = [1000.0]
        stamps = []
        instance = 'a' * 32
        worker_hash = 'b' * 64

        class Control:
            def read_file_snapshot(self, path):
                stamps.append(wall[0])
                state = dict(status='running', execution_profile='structured_only',
                             structured_backend='operator', spool_protocol='stream',
                             instance_id=instance, worker_sha256=worker_hash)
                return json.dumps(state).encode(), wall[0] + 2.0

        spec = BastionSpec(execution_profile='structured_only', structured_backend='operator',
                           spool_protocol='stream', worker_policy_sha256='c' * 64)
        control = Control()
        transport = StructuredTransport(control, spec)
        transport.readiness_guard = lambda: require_running_worker(control, spec)
        transport._verify_dispatch = Mock(return_value=dict(
            instance_id=instance, loaded_sha256=worker_hash,
            stream_upload_v1=True, chunked_copy_slots_v1=True))
        expiries = []

        def dispatch(envelope, evidence, deadline, started, readiness, **options):
            expiry = readiness['_heartbeat_expires_unix']
            expiries.append(expiry)
            self.assertEqual(expiry, wall[0] + spec.heartbeat_max_age_sec)
            self.assertEqual(readiness['age_sec'], -2.0)
            action = envelope['copy_action']
            attachment = options['attachment']
            if action == 'push_part':
                self.assertEqual(hashlib.sha256(attachment).hexdigest(), envelope['sha256'])
            wall[0] += 16.0
            prefix = 'PART:' if action == 'push_part' else 'VERIFIED:'
            return ExecResult(0, prefix + envelope['sha256'], '', 0)

        transport._dispatch_stream = Mock(side_effect=dispatch)
        executor = StructuredSshExecutor(transport, control, spec)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'artifact.bin'
            source.write_bytes(b'x' * (4 * 1024 * 1024))
            with patch('enclave_gateway.worker_channel.time.time', side_effect=lambda: wall[0]):
                digest = executor.copy_chunked('push', TargetNodeSpec('app01', '10.0.0.10'),
                                               source, '/tmp/artifact.bin', timeout_sec=120, as_root=False)
            self.assertEqual(digest, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(len(stamps), 5)
        self.assertGreater(stamps[-1], expiries[0])

    def test_snapshot_clock_skew_boundaries_and_invalid_ages(self):
        class Control:
            age = 0

            def exec_powershell(self, script, timeout_sec):
                return ExecResult(0, json.dumps(dict(running=True, age_sec=self.age,
                                                    spool_protocol='files')), '', 0)

        control = Control()
        for age, accepted in ((-5, True), (-2, True), (44.99, True), (-5.01, False),
                              (45, False), (float('nan'), False), (float('inf'), False), (True, False)):
            with self.subTest(age=age):
                control.age = age
                if accepted:
                    self.assertTrue(require_running_worker(control, BastionSpec())['running'])
                else:
                    with self.assertRaisesRegex(Exception, 'no recent running heartbeat'):
                        require_running_worker(control, BastionSpec())

    def test_alternating_pulse_accepts_small_lead_and_rejects_large_lead(self):
        instance = 'a' * 32
        state = dict(instance_id=instance, worker_sha256='b' * 64,
                     spool_protocol='stream', status='running')

        class Control:
            def try_read_bytes(self, path, **kwargs):
                if path.endswith('ipc_descriptor.json'):
                    return json.dumps(dict(revision=3, block_bytes=4096, instance=instance,
                                           worker_sha256='b' * 64)).encode()
                return json.dumps(state).encode()

        with patch('enclave_gateway.worker_channel.time.time', return_value=1000.0):
            for lead, accepted in ((2, True), (5, True), (5.01, False), (-45, False)):
                with self.subTest(lead=lead):
                    stamp = datetime.datetime.fromtimestamp(1000 + lead, datetime.timezone.utc)
                    state['last_heartbeat_utc'] = stamp.isoformat()
                    if accepted:
                        result = require_running_worker(Control(), BastionSpec(spool_protocol='stream'))
                        self.assertLessEqual(result['_heartbeat_expires_unix'], 1045)
                    else:
                        with self.assertRaisesRegex(Exception, 'no recent running heartbeat'):
                            require_running_worker(Control(), BastionSpec(spool_protocol='stream'))


class SudoGuidanceTests(unittest.TestCase):
    def test_cli_reports_secret_stdin_guidance_without_exposing_password(self):
        from test_field_reliability import engine_at
        from test_operator_ssh import operator_configuration
        from enclave_gateway.config import EnclaveConfig

        raw = operator_configuration('a' * 64, 'b' * 64)
        raw['targets']['app01']['sudo_password_env'] = 'FIXTURE_SUDO_PASSWORD'
        config = EnclaveConfig.from_dict(raw)
        with tempfile.TemporaryDirectory() as directory:
            engine = engine_at(Path(directory), Mock(), config)
            engine._ssh_password = Mock(return_value='')
            engine.vault.get = Mock(return_value='private-fixture-password')
            engine.vault.scrubber.register('private-fixture-password')
            with patch('enclave_gateway.cli.EnclaveConfig.load', return_value=config), patch(
                    'enclave_gateway.cli.EnclaveEngine', return_value=engine), patch(
                    'sys.stderr', new_callable=io.StringIO) as error:
                self.assertEqual(main(['exec', 'app01', '--sudo', 'id']), 1)
            detail = json.loads(error.getvalue())['error']
            self.assertIn('--secret-env', detail['remediation'])
            self.assertIn('sudo -S -p ""', detail['remediation'])
            self.assertIn('omit --sudo', detail['remediation'])
            self.assertNotIn('private-fixture-password', error.getvalue())
            engine.rdp_vfs.control.exec_powershell.assert_not_called()


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'), 'Requires PowerShell')
class PowerShellFieldTests(unittest.TestCase):
    def run_script(self, script, directory):
        path = Path(directory).resolve() / 'fixture.ps1'
        path.write_text("$ErrorActionPreference='Stop'\n" + script, encoding='utf-8')
        result = subprocess.run([os.environ['EGW_TEST_POWERSHELL'], '-NoProfile', '-File', str(path)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def generate_launcher(self, directory):
        source = WORKER.read_text()
        atomic = source[source.index('function Write-Atomic'):source.index('function Assert-Signature')]
        pipes = source[source.index('function Open-OperatorPipes'):source.index('function Open-OperatorSlot')]
        # Exercise publication and command construction with connected local
        # fixture pipes. Windows identity, ACL and SSH trust remain native tests.
        pipes = 'function Open-OperatorPipes{\n' + pipes[pipes.index('    # Local command only.'):]
        pipes = pipes.replace("if(-not [IO.File]::Exists($path)){throw 'Approved SSH material missing'}", '')
        script = r'''
function Assert-PlainPath {}
function Operator-Remaining { return 90000 }
function Operator-Read { return [Text.Encoding]::ASCII.GetBytes("EGWSSH1`n") }
$instance='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$extendedOperator=$false
$ssh='C:\Windows\System32\OpenSSH\ssh.exe'
$policy=[pscustomobject]@{
 operator_state_dir=$PSScriptRoot
 targets=[pscustomobject]@{app01=[pscustomobject]@{
  host='10.0.0.10';user='fixture';port=22
  key_path='C:\fixture\key';known_hosts_path='C:\fixture\known_hosts'
 }}
}
$operatorInput=[pscustomobject]@{}
$operatorInput|Add-Member ScriptMethod WaitForConnectionAsync { return [Threading.Tasks.Task]::CompletedTask }
$operatorOutput=$operatorInput
''' + atomic + pipes + '\nOpen-OperatorPipes\n'
        output = self.run_script(script, directory)
        self.assertIn('OPERATOR_ATTACH_READY: ' + 'a' * 32, output)
        return (Path(directory) / 'attach-ssh.cmd').read_text()

    def test_attach_launcher_selects_sysnative_and_binds_new_pipe_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = self.generate_launcher(directory)
            self.assertIn('if defined PROCESSOR_ARCHITEW6432 set "EGW_OPENSSH=%SystemRoot%\\Sysnative\\OpenSSH\\ssh.exe"', launcher)
            self.assertIn('set "EGW_OPENSSH=C:\\Windows\\System32\\OpenSSH\\ssh.exe"', launcher)
            self.assertIn('"%EGW_OPENSSH%" -F NUL', launcher)
            self.assertIn('StrictHostKeyChecking=yes', launcher)
            self.assertIn('EgwIn' + 'a' * 32, launcher)
            self.assertIn('EgwOut' + 'a' * 32, launcher)

    @unittest.skipUnless(os.name == 'nt', 'Requires native 64-bit Windows with system OpenSSH')
    def test_native_32_and_64_bit_cmd_launch_the_same_system_openssh(self):
        if not os.environ.get('PROCESSOR_ARCHITEW6432') and os.environ.get('PROCESSOR_ARCHITECTURE') == 'x86':
            self.skipTest('Requires a 64-bit Windows installation')
        system = Path(os.environ['SystemRoot'])
        native = 'Sysnative' if os.environ.get('PROCESSOR_ARCHITEW6432') else 'System32'
        if not (system / native / 'OpenSSH/ssh.exe').exists():
            self.skipTest('Requires installed system OpenSSH')
        with tempfile.TemporaryDirectory() as directory:
            launcher = self.generate_launcher(directory)
            # Retain the generated selector, invoke only the version option.
            prefix = launcher.split('"%EGW_OPENSSH%" -F NUL')[0]
            prefix = prefix.replace('C:\\Windows\\System32', str(system / 'System32'))
            batch = Path(directory) / 'version.cmd'
            batch.write_text(prefix + 'echo %EGW_OPENSSH%\n"%EGW_OPENSSH%" -V\n')
            environment = dict(os.environ)
            environment.pop('PROCESSOR_ARCHITEW6432', None)
            for folder, selected in ((native, 'System32'), ('SysWOW64', 'Sysnative')):
                with self.subTest(cmd=folder):
                    result = subprocess.run([str(system / folder / 'cmd.exe'), '/d', '/c', str(batch)],
                                            env=environment, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(selected + '\\OpenSSH\\ssh.exe', result.stdout)
                    self.assertIn('OpenSSH', result.stderr)

    def test_transient_replace_fallback_retries_and_preserves_durable_records(self):
        source = WORKER.read_text()
        guard = source[source.index('function Assert-PlainPath'):source.index('function Hash-File')]
        atomic = source[source.index('function Write-Atomic'):source.index('function Assert-Signature')]
        atomic = atomic.replace('[IO.File]::Replace($temporary,$Path,[NullString]::Value)',
                                'Invoke-FixtureReplace $temporary $Path')
        atomic = atomic.replace('[IO.File]::Move($temporary,$Path)', 'Invoke-FixtureMove $temporary $Path')
        with tempfile.TemporaryDirectory() as directory:
            script = guard + atomic + r'''
function Invoke-FixtureReplace($Temporary,$Destination){
 if($script:denied){throw [UnauthorizedAccessException]::new('RDP replace denied')}
 throw [IO.IOException]::new('RDP replace unavailable')
}
function Invoke-FixtureMove($Temporary,$Destination){
 $script:moves++
 if($script:moves -lt 3){throw [IO.IOException]::new('RDP sharing violation')}
 [IO.File]::Move($Temporary,$Destination)
}
$path=Join-Path $PSScriptRoot 'state.json'
foreach($denied in @($false,$true)){
 $script:denied=$denied;$script:moves=0
 [IO.File]::WriteAllText($path,'stopped')
 Write-Atomic $path 'running' -Transient
 if([IO.File]::ReadAllText($path) -cne 'running' -or $moves -ne 3){throw 'Transient replacement failed'}
}
$script:moves=0
[IO.File]::WriteAllText($path,'committed')
try{Write-Atomic $path 'replacement';throw 'Durable failure was hidden'}
catch [UnauthorizedAccessException]{}
if([IO.File]::ReadAllText($path) -cne 'committed' -or $moves){throw 'Durable record was changed'}
if(@(Get-ChildItem $PSScriptRoot -Filter '*.tmp').Count){throw 'Temporary publication leaked'}
'''
            self.run_script(script, directory)

    @unittest.skipIf(os.name == 'nt', 'Portable symlink fault injection uses .NET symbolic links')
    def test_replace_fallback_rejects_a_link_introduced_during_publication(self):
        source = WORKER.read_text()
        guard = source[source.index('function Assert-PlainPath'):source.index('function Hash-File')]
        atomic = source[source.index('function Write-Atomic'):source.index('function Assert-Signature')]
        atomic = atomic.replace('[IO.File]::Replace($temporary,$Path,[NullString]::Value)',
                                'Invoke-FixtureReplace $temporary $Path')
        with tempfile.TemporaryDirectory() as directory:
            script = guard + atomic + r'''
$path=Join-Path $PSScriptRoot 'state.json'
$sentinel=Join-Path $PSScriptRoot 'sentinel'
[IO.File]::WriteAllText($path,'stopped')
[IO.File]::WriteAllText($sentinel,'preserve')
function Invoke-FixtureReplace($Temporary,$Destination){
 [IO.File]::Delete($Destination)
 [void][IO.File]::CreateSymbolicLink($Destination,$sentinel)
 throw [IO.IOException]::new('RDP replace unavailable')
}
try{Write-Atomic $path 'running' -Transient;throw 'Linked target was accepted'}
catch{if($_.Exception.Message -ne 'Linked worker paths are forbidden'){throw}}
if([IO.File]::ReadAllText($sentinel) -cne 'preserve'){throw 'Link target was changed'}
if(@(Get-ChildItem $PSScriptRoot -Filter '*.tmp').Count){throw 'Temporary publication leaked'}
'''
            self.run_script(script, directory)

    def test_staging_retires_stopped_state_and_keeps_live_state(self):
        from test_field_reliability import engine_at
        from test_operational_ux import LocalPowerShellControl
        from test_operator_ssh import operator_configuration
        from enclave_gateway.config import EnclaveConfig

        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory).resolve() / 'spool'
            spool.mkdir()
            (spool / '.worker-session').touch()
            (spool / 'worker_structured_storage.json').write_text(
                json.dumps(dict(revision=1, owner_sha256='b' * 64)))
            state = dict(status='stopped', instance_id='a' * 32, execution_profile='structured_only',
                         structured_backend='operator', spool_protocol='stream')
            state_path = spool / 'worker_state.json'
            state_path.write_text(json.dumps(state))
            descriptor = spool / 'ipc_descriptor.json'
            descriptor.write_text('old descriptor')
            request = spool / ('ipc_req_' + 'a' * 32 + '.bin')
            request.write_bytes(b'preserved payload')
            journal = spool / '.structured-transactions'
            journal.mkdir()
            (journal / 'receipt.json').write_text('preserved journal')
            script = cleanup_script(str(spool), execution_profile='structured_only',
                                    structured_backend='operator', prepare_for_start=True)
            # A stopped snapshot alone never permits cleanup of a locked lease.
            locked = "$fixtureLease=[IO.File]::Open('" + str(spool / '.worker-session').replace("'", "''") + "','Open','ReadWrite','None')\n"
            output = self.run_script(locked + script, directory)
            self.assertFalse(json.loads(output.split('APPLIANCE_CLEAN_OK:')[1])['stopped_worker_verified'])
            self.assertTrue(state_path.exists() and request.exists())
            state_path.write_text(json.dumps({**state, 'status': 'running'}))
            output = self.run_script(script, directory)
            self.assertFalse(json.loads(output.split('APPLIANCE_CLEAN_OK:')[1])['stopped_worker_verified'])
            state_path.write_text(json.dumps(state))
            raw = operator_configuration(hashlib.sha256(WORKER.read_bytes()).hexdigest(), 'c' * 64)
            raw['bastion']['appliance_spool_dir'] = str(spool)
            class StageControl(LocalPowerShellControl):
                def exec_powershell(self, script, timeout_sec=60):
                    # Translate fixture paths, leaving PowerShell regexes intact.
                    script = re.sub(r"'([^']*)'", lambda match: (
                        "'" + match[1].replace('\\', '/') + "'"
                        if match[1].startswith(str(spool)) else match[0]), script)
                    return super().exec_powershell(script, timeout_sec)

            control = StageControl(os.environ['EGW_TEST_POWERSHELL'], translate_paths=False)
            engine = engine_at(Path(directory), control, EnclaveConfig.from_dict(raw))
            receipt = engine.stage_agents()['stream_prune']
            self.assertTrue(receipt['stopped_worker_verified'])
            self.assertEqual(receipt['retired_state_files'], 3)
            retired = Path(receipt['retired_state_directory'])
            self.assertEqual((retired / request.name).read_bytes(), b'preserved payload')
            self.assertFalse(request.exists() or descriptor.exists() or state_path.exists())
            self.assertEqual((journal / 'receipt.json').read_text(), 'preserved journal')
