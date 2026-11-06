"""Endpoint policy boundaries and secret-bearing data never becoming PS source."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.cli import main
from enclave_gateway.config import BastionSpec, EnclaveConfig, TargetNodeSpec
from enclave_gateway.control.qga_client import ExecResult, QgaClient
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.operations.request import PowerShellRequest
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
from enclave_gateway.transports.ssh_hop import build_powershell_ssh_hop_script
from enclave_gateway.transports.stream_frames import encode_frame, Decoder

ROOT=Path(__file__).resolve().parents[1]


class RequestDataTests(unittest.TestCase):
    def test_passwords_and_remote_payload_are_data_on_both_interpreter_hops(self):
        secret="fixture-password-'-$-пароль"
        sudo='fixture-sudo-password'
        source=build_powershell_ssh_hop_script(TargetNodeSpec('app01','10.0.20.11'),
                    'printf fixture-output',as_root=True,ssh_password=secret,sudo_password=sudo)
        for value in (secret,sudo,base64.b64encode(secret.encode()).decode(),source.request_data['ssh_stdin_b64']):
            self.assertNotIn(value,str(source))
        self.assertIn(sudo,base64.b64decode(source.request_data['ssh_stdin_b64']).decode())
        transport=RdpVfsTransport(Mock(),BastionSpec())
        transport._dispatch_envelope=Mock(return_value=ExecResult(0,'','',0))
        transport.exec_bastion(source)
        envelope=transport._dispatch_envelope.call_args.args[0]
        self.assertEqual(Decoder().feed(encode_frame(envelope))[0][2],envelope)
        data=json.loads(envelope['request_data_json'])
        self.assertEqual(data.pop('egw_request_nonce').__len__(),32)
        self.assertEqual(data,source.request_data)
        captured=[]
        class Channel(QgaClient):
            def __init__(self):pass
            def exec_guest(self,path,arguments,**options):
                captured.append((path,arguments,options));return ExecResult(0,'','',0)
        Channel().exec_powershell(source)
        script=base64.b64decode(captured[0][1][-1]).decode('utf-16le')
        self.assertNotIn(secret,script)
        self.assertNotIn(base64.b64encode(secret.encode()).decode(),script)
        self.assertEqual(json.loads(captured[0][2]['input_data']),source.request_data)

    def test_rdp_refresh_uses_pinned_task_identity_and_native_stdin(self):
        calls=[]
        class Channel:
            def exec_powershell(self,source,**options):
                calls.append(('source',source))
                return ExecResult(0,json.dumps({'runtime':r'C:\EnclaveGateway\bin\egw-runtime.exe','expected_sid':'S-1-5-21-1000'}),'',0)
            def exec_guest(self,path,arguments,**options):
                calls.append(('data',arguments,options['input_data']))
                return ExecResult(0,'{"credential_updated":true}','',0)
        engine=object.__new__(EnclaveEngine)
        engine.config=EnclaveConfig.from_dict({'security':{'mode':'standard'}})
        engine.control=Channel()
        engine._refresh_rdp_credentials('fixture-user','fixture-password')
        self.assertNotIn('fixture-password',calls[0][1])
        self.assertNotIn(base64.b64encode(b'fixture-password').decode(),calls[0][1])
        self.assertEqual(calls[1][1],['credentials'])
        self.assertEqual(json.loads(calls[1][2])['expected_sid'],'S-1-5-21-1000')
        self.assertEqual(json.loads(calls[1][2])['password'],'fixture-password')

    def test_offline_recovery_command_requires_no_configuration_or_worker(self):
        with patch('enclave_gateway.cli.EnclaveConfig.load',side_effect=AssertionError('No configuration access')),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['agents','unregister-autostart-command']),0)
        command=output.getvalue()
        self.assertIn('Unrecognized worker startup value',command)
        self.assertIn("DeleteValue('EnclaveGatewayWorker'",command)
        self.assertNotIn('Remove-Item',command)
        self.assertNotIn('Stop-Process',command)
        self.assertNotIn('tsclient',command)

    @unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real interpreter fixture is opt-in')
    def test_worker_consumes_request_data_in_files_and_stream(self):
        shell=os.environ['EGW_TEST_POWERSHELL']
        for protocol in ('files','stream'):
            with self.subTest(protocol=protocol),tempfile.TemporaryDirectory(prefix='egw-request-data-') as temporary:
                root=Path(temporary);spool=root/'spool';spool.mkdir();stop=root/'stop'
                from enclave_gateway.control.qga_client import DirectHostControlChannel
                class Mapped(DirectHostControlChannel):
                    supports_direct_spool_ipc=True
                    def _map_path(self,path):return Path(str(path).replace('\\',os.sep))
                transport=RdpVfsTransport(Mapped(),BastionSpec(appliance_spool_dir=str(spool),bastion_spool_dir=str(spool),spool_protocol=protocol))
                log=root/'worker.log'
                with log.open('wb') as output:
                    process=subprocess.Popen([shell,'-NoProfile','-NonInteractive','-File',str(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1'),
                                              '-Mode','Standard','-SpoolDir',str(spool),'-SpoolProtocol',protocol.title(),'-StopFile',str(stop),'-HeartbeatIntervalMs','250'],stdout=output,stderr=output)
                    try:
                        until=time.monotonic()+20
                        while not (spool/'worker_state.json').exists():
                            if process.poll() is not None or time.monotonic()>until:self.fail(log.read_text(errors='replace'))
                            time.sleep(.02)
                        source=PowerShellRequest('Write-Output $RequestData.marker',{'marker':'fixture-data-value'})
                        result=transport.exec_bastion(source,timeout_sec=15)
                        self.assertEqual((result.exit_code,result.stdout.strip()),(0,'fixture-data-value'),result.stderr)
                        # A reused runspace must not retain another request's data.
                        result=transport.exec_bastion('if($RequestData){throw "Stale request data"};Write-Output "DATA_CLEARED"',timeout_sec=15)
                        self.assertEqual((result.exit_code,result.stdout.strip()),(0,'DATA_CLEARED'),result.stderr)
                        dispatch=transport._dispatch_envelope
                        with patch.object(transport,'_dispatch_envelope',side_effect=lambda envelope,timeout_sec:dispatch(
                                {key:value for key,value in envelope.items() if key!='request_data_json'},timeout_sec=timeout_sec)):
                            denied=transport.exec_bastion(PowerShellRequest('Write-Output "MUST_NOT_EXECUTE"',{'marker':'fixture'}),timeout_sec=15)
                        self.assertNotEqual(denied.exit_code,0)
                        self.assertNotIn('MUST_NOT_EXECUTE',denied.stdout)
                        self.assertIn('WORKER_REQUEST_DATA_UNSUPPORTED',denied.stderr)
                    except BaseException:
                        import shutil
                        evidence=Path(tempfile.mkdtemp(prefix='egw-request-data-failure-'))
                        shutil.copytree(root,evidence/'evidence')
                        print('Failed request data fixture retained at',evidence)
                        raise
                    finally:
                        stop.touch()
                        try:process.wait(timeout=10)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5);self.fail('Worker did not stop')
