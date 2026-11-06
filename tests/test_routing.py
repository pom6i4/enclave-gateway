"""Explicit route selection and optional isolated native OpenSSH qualification."""
from contextlib import contextmanager, redirect_stdout
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.cli import main
from enclave_gateway.config import BastionSpec, EnclaveConfig
from enclave_gateway.control.qga_client import DirectHostControlChannel, ExecResult
from enclave_gateway.diagnostics import preflight
from enclave_gateway.onboarding import configuration_summary, starter_configuration
from enclave_gateway.operations.context import OperationError
from enclave_gateway.routing import route_summary
from enclave_gateway.security.policy import AccessPolicy, Grant
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, RdpVfsTunnelServer
from enclave_gateway.transports.socks5_mux import Socks5VfsServer
from test_field_reliability import engine_at


class RouteContracts(unittest.TestCase):
    def test_ssh_starter_has_explicit_route_and_no_worker_requirement(self):
        with tempfile.TemporaryDirectory() as folder,redirect_stdout(io.StringIO()):
            path=Path(folder)/'enclave.yaml'
            self.assertEqual(main(['config','init','--route','ssh','--output',str(path)]),0)
            cfg=EnclaveConfig.load(path)
        summary=configuration_summary(cfg)
        self.assertFalse(summary['bastion_worker_required'])
        self.assertEqual(summary['execution_model'],'agentless-ssh')
        self.assertEqual(summary['routes']['app01'],{'transport':'ssh','execution_hop':'appliance',
                         'ssh_jumps':[],'worker_required':False,'automatic_fallback':False})
        self.assertNotIn('agents stage',json.dumps(summary['next_steps']))
        self.assertNotIn('agent_package',{c['check'] for c in preflight(cfg)['checks']})
        cfg.targets['app01'].via='bastion'
        with self.assertRaisesRegex(ValueError,'disabled RDP Bastion'):configuration_summary(cfg)
        with self.assertRaisesRegex(ValueError,'bastion.transport'):BastionSpec(transport='ssh')

    def test_jump_routes_are_identical_in_setup_and_execution_and_never_fallback(self):
        cfg=EnclaveConfig.from_dict(starter_configuration(route='ssh'))
        from enclave_gateway.config import TargetNodeSpec
        cfg.targets['jump01']=TargetNodeSpec('jump01','10.0.10.5',via='appliance')
        cfg.targets['app01'].via='jump01'
        with tempfile.TemporaryDirectory() as folder:
            engine=engine_at(Path(folder),Mock(),cfg)
            self.assertEqual(route_summary(cfg)['app01']['ssh_jumps'],['jump01'])
            hop,jumps=engine._resolve_hop_and_jump(cfg.targets['app01'])
            self.assertIs(hop,engine.appliance_ssh);self.assertEqual([n.name for n in jumps],['jump01'])
            for selected,other in ((engine.appliance_ssh,engine.bastion_ssh),(engine.bastion_ssh,engine.appliance_ssh)):
                cfg.targets['jump01'].via='appliance' if selected is engine.appliance_ssh else 'bastion'
                cfg.bastion.enabled=selected is engine.bastion_ssh
                selected.exec_node=Mock(return_value=ExecResult(255,'','Host key verification failed',1))
                selected.push_file_to_node=Mock(side_effect=ConnectionError('Selected route failed'))
                selected.pull_file_from_node=Mock(side_effect=ConnectionError('Selected route failed'))
                other.exec_node=Mock(side_effect=AssertionError('No transport fallback'))
                other.push_file_to_node=Mock(side_effect=AssertionError('No transfer fallback'))
                other.pull_file_from_node=Mock(side_effect=AssertionError('No transfer fallback'))
                self.assertEqual(engine.exec_node('app01','true').exit_code,255)
                source=Path(folder)/'source';source.write_bytes(b'fixture')
                for direction in ('push','pull'):
                    with self.assertRaises(ConnectionError):engine.transfer_file(direction,source,'app01','/tmp/fixture')
                other.exec_node.assert_not_called();other.push_file_to_node.assert_not_called();other.pull_file_from_node.assert_not_called()

    def test_disabled_rdp_and_structured_mux_fail_before_files_or_listeners(self):
        control=Mock();transport=RdpVfsTransport(control,BastionSpec(enabled=False))
        for action in (lambda:transport.exec_bastion('unused'),lambda:transport.push_file(Path('missing'),'unused'),
                       lambda:transport.pull_file('unused',Path('unused')),lambda:transport.request_cancel('tx_fixture'),
                       lambda:transport._dispatch_envelope({'tx_id':'fixture'})):
            with self.assertRaises(OperationError) as raised:action()
            self.assertEqual(raised.exception.code,'bastion_disabled')
        for spec in (BastionSpec(enabled=False),BastionSpec(execution_profile='structured_only',worker_policy_sha256='a'*64)):
            with patch('socket.socket',side_effect=AssertionError('No listener may be bound')):
                for create in (lambda:Socks5VfsServer(RdpVfsTransport(control,spec),bind_port=0),
                               lambda:RdpVfsTunnelServer(RdpVfsTransport(control,spec),0,'127.0.0.1',22)):
                    with self.assertRaises(OperationError):create()
        self.assertFalse(control.mock_calls)

    def test_ssh_maintenance_and_policy_do_not_require_a_nonexistent_bastion(self):
        cfg=EnclaveConfig.from_dict(starter_configuration(route='ssh'));cfg.appliance.hypervisor='direct'
        with tempfile.TemporaryDirectory() as folder:
            control=Mock();engine=engine_at(Path(folder),control,cfg)
            self.assertTrue(engine.clean_session()['ok']);control.assert_not_called();self.assertFalse(control.mock_calls)
            for call in (engine.generate_ssh_config,engine.stage_agents,engine.prune_agents,engine.attest_worker,lambda:engine.heal(update_credentials=True)):
                with self.assertRaises((ValueError,OperationError)):call()
            engine.control=DirectHostControlChannel()
            command=engine.build_ssh_command('app01')
            self.assertNotIn('stdio-proxy',' '.join(command))
            self.assertIn('StrictHostKeyChecking=yes',command)
            self.assertIn('BatchMode=yes',command)
            self.assertIn('/dev/null' if os.name!='nt' else 'NUL',command)
            self.assertTrue(engine.capabilities()['interactive_ssh']['direct_host'])
            cfg.appliance.hypervisor='auto'
            with self.assertRaisesRegex(OperationError,'QGA Appliance'):engine.build_ssh_command('app01')
            cfg.bastion.enabled=True
            with self.assertRaisesRegex(OperationError,'only RDP TCP mux routes'):engine.generate_ssh_config()
            cfg.bastion.enabled=False
            self.assertFalse(control.mock_calls)
            caps=engine.capabilities();self.assertFalse(caps['bastion_execution']['tcp_mux'])
            self.assertFalse(caps['worker_verification']['applicable'])
        grant=Grant(name='operator',tools=('*',),nodes=('@appliance',),allow_repair=True)
        policy=AccessPolicy({'operator':grant})
        for tool in ('enclave_status','enclave_doctor','enclave_clean','enclave_heal'):policy.authorize('operator',tool,{},cfg)
        cfg.bastion.enabled=True
        with self.assertRaises(OperationError):policy.authorize('operator','enclave_doctor',{},cfg)


@unittest.skipUnless(os.environ.get('EGW_TEST_SSHD') and os.environ.get('EGW_TEST_SSH_ROOT') and os.name!='nt',
                     'Isolated native OpenSSH test requires explicit tools and a private owned fixture parent')
class NativeSshRouteTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='egw-ssh-route-',dir=os.environ['EGW_TEST_SSH_ROOT']) as temporary:
            root=Path(temporary).resolve();root.chmod(0o700);processes=[];logs=[]
            try:
                bindir=root/'bin';bindir.mkdir()
                native_ssh=shutil.which('ssh');self.assertIsNotNone(native_ssh)
                # Ignore unrelated local SSH configuration and agents in this fixture.
                wrapper=bindir/'ssh';wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(native_ssh)+' -F /dev/null -o GlobalKnownHostsFile=/dev/null -o IdentityAgent=none -o ControlMaster=no -o ControlPath=none "$@"\n');wrapper.chmod(0o700)
                ports={}
                for name in ('jump01','app01'):
                    folder=root/name;folder.mkdir()
                    for key in ('host','identity'):
                        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/key)],check=True,capture_output=True,timeout=10)
                    (folder/'authorized_keys').write_bytes((folder/'identity.pub').read_bytes())
                    with socket.socket() as listener:listener.bind(('127.0.0.1',0));ports[name]=listener.getsockname()[1]
                    settings=f'''Port {ports[name]}
ListenAddress 127.0.0.1
HostKey "{folder/'host'}"
PidFile "{folder/'pid'}"
AuthorizedKeysFile "{folder/'authorized_keys'}"
StrictModes yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitUserRC no
AllowUsers {getpass.getuser()}
AllowTcpForwarding yes
SetEnv PATH={Path(sys.executable).parent}:/usr/bin:/bin
LogLevel VERBOSE
'''
                    config=folder/'sshd_config';config.write_text(settings)
                    public=(folder/'host.pub').read_text().split()
                    (folder/'known hosts').write_text(f'[127.0.0.1]:{ports[name]} '+public[0]+' '+public[1]+'\n')
                    output=(folder/'sshd.log').open('wb');logs.append(output)
                    process=subprocess.Popen([os.environ['EGW_TEST_SSHD'],'-D','-e','-f',str(config)],stdout=output,stderr=output);processes.append(process)
                    deadline=time.monotonic()+5
                    while True:
                        if process.poll() is not None:self.fail((folder/'sshd.log').read_text())
                        try:
                            with socket.create_connection(('127.0.0.1',ports[name]),timeout=.1):break
                        except OSError:
                            if time.monotonic()>deadline:self.fail('Isolated SSH listener unavailable')
                            time.sleep(.02)
                cfg=starter_configuration(route='ssh');cfg['appliance']['hypervisor']='direct'
                cfg['provider'].update(probe_host='127.0.0.1',probe_port=ports['app01'])
                cfg['targets']={name:{'host':'127.0.0.1','port':ports[name],'user':getpass.getuser(),
                    'via':'appliance' if name=='jump01' else 'jump01','ssh_key_path':str(root/name/'identity'),
                    'ssh_known_hosts_path':str(root/name/'known hosts')} for name in ports}
                with patch.dict(os.environ,{'PATH':str(bindir)+os.pathsep+os.environ.get('PATH','')}):
                    yield root,EnclaveConfig.from_dict(cfg)
                evidence=root.parent/(root.name+'-passed');evidence.mkdir(mode=0o700)
                for name in ('jump01','app01'):shutil.copy2(root/name/'sshd.log',evidence/(name+'.log'))
                shutil.copy2(root/'result.json',evidence/'result.json')
            except BaseException:
                evidence=root.parent/(root.name+'-failed');shutil.copytree(root,evidence,symlinks=True)
                print('Failed native SSH fixture preserved:',evidence)
                raise
            finally:
                for process in processes:
                    if process.poll() is None:process.terminate()
                for process in processes:
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                for stream in logs:stream.close()

    def test_native_jump_exec_copy_doctor_and_host_key_rejection(self):
        with self.fixture() as (root,cfg):
            engine=engine_at(root,DirectHostControlChannel(),cfg)
            engine.bastion_ssh=Mock(side_effect=AssertionError('RDP route is forbidden'))
            engine.rdp_vfs=Mock(side_effect=AssertionError('RDP transport is forbidden'))
            started=time.monotonic();measurements=[]
            def measure(name,call):
                begin=time.monotonic()
                try:return call()
                finally:measurements.append({'operation':name,'wall_ms':round((time.monotonic()-begin)*1000,3)})
            cfg.targets['app01'].via='appliance'
            direct=measure('direct_ssh_exec',lambda:engine.exec_node('app01','printf DIRECT_OK',timeout_sec=15))
            self.assertEqual((direct.exit_code,direct.stdout),(0,'DIRECT_OK'))
            cfg.targets['app01'].via='jump01'
            interactive=measure('direct_host_interactive_jump_ssh',lambda:subprocess.run(
                engine.build_ssh_command('app01',extra_args=['-tt']),
                input=b"test -t 0 && printf 'TTY_%s\\n' CONFIRMED; exit 7\n",capture_output=True,timeout=15))
            self.assertEqual(interactive.returncode,7,interactive.stderr)
            self.assertIn(b'TTY_CONFIRMED',interactive.stdout)
            result=measure('jump_ssh_exec_nonzero',lambda:engine.exec_node('app01',"printf 'тест'; printf 'warning' >&2; exit 7",timeout_sec=15))
            self.assertEqual((result.exit_code,result.stdout,result.stderr),(7,'тест','warning'))
            source=root/'source.bin';data=bytes(range(256))*80;source.write_bytes(data);remote=str(root/"remote ' file.bin")
            expected=hashlib.sha256(data).hexdigest()
            self.assertEqual(measure('jump_copy_push',lambda:engine.transfer_file('push',source,'app01',remote,timeout_sec=15))['sha256'],expected)
            received=root/'received.bin'
            self.assertEqual(measure('jump_copy_pull',lambda:engine.transfer_file('pull',received,'app01',remote,timeout_sec=15))['sha256'],expected)
            self.assertEqual(received.read_bytes(),data)
            report=measure('doctor_probe_target',lambda:engine.doctor(probe_targets=True,nodes={'app01'}))
            self.assertTrue(report['healthy'],report)
            (root/'app01/known hosts').write_text('')
            rejected=measure('reject_unknown_target_key',lambda:engine.exec_node('app01','printf MUST_NOT_EXECUTE',timeout_sec=15))
            self.assertEqual(rejected.exit_code,255);self.assertNotIn('MUST_NOT_EXECUTE',rejected.stdout)
            self.assertIn('Host key verification failed',rejected.stderr)
            engine.bastion_ssh.assert_not_called();self.assertFalse(engine.bastion_ssh.mock_calls);self.assertFalse(engine.rdp_vfs.mock_calls)
            self.assertNotIn('Starting session:',(root/'jump01/sshd.log').read_text())
            (root/'result.json').write_text(json.dumps({'elapsed_ms':round((time.monotonic()-started)*1000),'status':'passed','measurements':measurements,'doctor':report},indent=2))
