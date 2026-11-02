"""First-run mode boundaries, offline setup and actual helper-free worker behavior."""
import base64
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
from enclave_gateway.cli import main
from enclave_gateway.config import EnclaveConfig,SecuritySpec,TargetNodeSpec,parse_yaml_or_json
from enclave_gateway.onboarding import starter_configuration,configuration_summary,agent_bundle,stage_agents
from enclave_gateway.transports.ssh_hop import _ssh_args
from enclave_gateway.control.qga_client import ExecResult

ROOT=Path(__file__).resolve().parents[1]


def enterprise(**extra):
    return {'mode':'enterprise','worker_sha256':'a'*64,'runtime_sha256':'b'*64,
            'worker_account':'S-1-5-21-1000-1001','trusted_signers':['C'*40],**extra}


class ConfigurationTests(unittest.TestCase):
    def test_named_modes_preserve_legacy_and_reject_enterprise_downgrades(self):
        old=SecuritySpec();self.assertTrue(old.require_signed_helpers);self.assertTrue(old.require_signed_agents)
        self.assertFalse(old.require_process_isolation);self.assertEqual(old.mode,'custom')
        standard=SecuritySpec(mode='standard');self.assertFalse(standard.require_signed_helpers);self.assertFalse(standard.require_process_isolation)
        self.assertTrue(SecuritySpec.from_dict(enterprise()).require_process_isolation)
        for field in ('require_signed_helpers','require_signed_agents','enforce_worker_attestation','require_process_isolation','owned_ssh_commands'):
            for value in (False,None,'false',0):
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):SecuritySpec.from_dict(enterprise(**{field:value}))
        with self.assertRaises(ValueError):SecuritySpec.from_dict({'mode':'enterprise'})
        cfg=EnclaveConfig.from_dict(starter_configuration());self.assertEqual(EnclaveConfig.from_dict(asdict(cfg)),cfg)

    def test_example_matches_effective_starter_and_unknown_security_is_rejected(self):
        self.assertEqual(EnclaveConfig.load(ROOT/'config/enclave.example.yaml'),EnclaveConfig.from_dict(starter_configuration()))
        for value in ({'applince':{}},{'bastion':{'user':'ignored'}},{'security':{'require_process_isolaton':False}},
                      {'targets':{'app':{'host':'10.0.0.10','nmae':'ignored'}}},
                      {'targets':{'app':{'host':'10.0.0.10','port':None}}},
                      {'bastion':{'enabled':'false'}},{'appliance':{'cpus':True}},
                      {'targets':{'app':{'user':'deploy'}}}):
            with self.subTest(value=value),self.assertRaises(ValueError):EnclaveConfig.from_dict(value)

    def test_duplicate_security_profiles_are_rejected_with_both_parsers(self):
        json_text='{"security":{"mode":"enterprise","mode":"standard"}}'
        yaml_text='security:\n  mode: enterprise\n  mode: standard\n'
        for text in (json_text,yaml_text):
            with self.assertRaises(ValueError):parse_yaml_or_json(text)
            original=__import__('builtins').__import__
            def without_yaml(name,*args,**kwargs):
                if name=='yaml':raise ImportError()
                return original(name,*args,**kwargs)
            with patch('builtins.__import__',side_effect=without_yaml),self.assertRaises(ValueError):parse_yaml_or_json(text)

    def test_init_check_and_preflight_are_offline_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'enclave.yaml'
            with patch('enclave_gateway.cli.EnclaveEngine') as engine,patch('sys.stdout',new_callable=io.StringIO):
                self.assertEqual(main(['config','init','--output',str(file)]),0)
                data=file.read_bytes()
                with patch('sys.stderr',new_callable=io.StringIO):self.assertEqual(main(['config','init','--output',str(file)]),1)
                self.assertEqual(file.read_bytes(),data)
                self.assertEqual(main(['-c',str(file),'config','check']),0)
                main(['-c',str(file),'doctor','--preflight'])
                engine.assert_not_called()
            if os.name!='nt':self.assertEqual(file.stat().st_mode&0o777,0o600)

    def test_missing_config_does_not_load_repository_example_and_parse_errors_hide_values(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch('enclave_gateway.config.Path.is_file',return_value=False),self.assertRaises(FileNotFoundError):EnclaveConfig.load()
            file=Path(folder)/'invalid.yaml';file.write_text('{"password":"private-fixture-value", invalid')
            with patch('sys.stderr',new_callable=io.StringIO) as stderr:
                self.assertEqual(main(['-c',str(file),'config','check']),1)
            self.assertNotIn('private-fixture-value',stderr.getvalue());self.assertNotIn('Traceback',stderr.getvalue())

    def test_routes_and_known_hosts_include_every_configured_jump(self):
        cfg=EnclaveConfig.from_dict({'targets':{'app':{'host':'10.0.0.10','via':'jump'},'jump':{'host':'10.0.0.11','via':'appliance'}}})
        self.assertEqual(configuration_summary(cfg)['ssh_execution_hops']['app'],'appliance')
        cfg.targets['jump'].via='app'
        with self.assertRaises(ValueError):configuration_summary(cfg)
        target=TargetNodeSpec('app','10.0.0.10',ssh_known_hosts_path=r'C:\Users\operator\known hosts')
        jump=TargetNodeSpec('jump','10.0.0.11',ssh_known_hosts_path=r'C:\trusted\known_hosts')
        args=_ssh_args(target,jump_node=[jump]);self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertTrue(any('UserKnownHostsFile=' in s for s in args));self.assertTrue(any('C:' in s and 'trusted' in s for s in args if s.startswith('ProxyCommand=')))
        with self.assertRaises(ValueError):TargetNodeSpec('app','10.0.0.10',ssh_known_hosts_path='file\nStrictHostKeyChecking no')

    def test_schema_exports_and_secret_stdin_do_not_require_topology_or_leak_value(self):
        with patch('enclave_gateway.cli.EnclaveEngine') as engine,patch('enclave_gateway.cli.EnclaveConfig.load') as load:
            with patch('sys.stdout',new_callable=io.StringIO):
                self.assertEqual(main(['mcp','--export-openapi']),0)
                self.assertEqual(main(['mcp-config','--client','all']),0)
            with patch('enclave_gateway.security.secrets.SecretVault') as vault,patch('sys.stdin',io.StringIO('fixture-hidden-value\n')),patch('sys.stdout',new_callable=io.StringIO) as output:
                self.assertEqual(main(['secret','set','ENCLAVE_FIXTURE','--stdin']),0)
                vault.return_value.set_in_keychain.assert_called_once_with('ENCLAVE_FIXTURE','fixture-hidden-value')
                self.assertNotIn('fixture-hidden-value',output.getvalue())
            load.assert_not_called();engine.assert_not_called()

    def test_enterprise_service_needs_policy_and_isolated_mutable_backends(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'enterprise.json';file.write_text(json.dumps({'security':enterprise()}))
            with patch('enclave_gateway.cli.EnclaveEngine') as engine,patch('sys.stderr',new_callable=io.StringIO):
                self.assertEqual(main(['-c',str(file),'mcp']),1)
                self.assertEqual(main(['-c',str(file),'mcp','--policy',str(Path(folder)/'policy.json')]),1)
                engine.assert_not_called()


class AgentDeploymentTests(unittest.TestCase):
    def test_missing_or_changed_signed_package_never_deploys_unsigned_source(self):
        cfg=EnclaveConfig.from_dict({'security':enterprise()});control=Mock()
        with self.assertRaises(ValueError):stage_agents(control,cfg)
        control.exec_powershell.assert_not_called();control.write_bytes.assert_not_called()
        with tempfile.TemporaryDirectory() as folder:
            for name in ('bastion_worker.ps1','bastion_bootstrap.ps1'):(Path(folder)/name).write_text('changed')
            cfg.security.agent_package_dir=folder;cfg.security.bootstrap_sha256='d'*64
            with self.assertRaisesRegex(ValueError,'hashes'):stage_agents(control,cfg)
            control.exec_powershell.assert_not_called()

    def test_partial_upload_runs_cleanup_without_publishing_or_overwriting(self):
        cfg=EnclaveConfig.from_dict(starter_configuration());control=Mock()
        control.exec_powershell.return_value=ExecResult(0,'','',0);control.write_bytes.side_effect=OSError('fixture upload failure')
        with self.assertRaises(OSError):stage_agents(control,cfg)
        self.assertEqual(control.exec_powershell.call_count,2)
        self.assertIn('Remove-Item',control.exec_powershell.call_args.args[0])
        self.assertNotIn('Directory]::Move',control.exec_powershell.call_args.args[0])

    def test_staging_reports_manual_start_and_never_reconnects_rdp(self):
        cfg=EnclaveConfig.from_dict(starter_configuration());control=Mock();control.exec_powershell.return_value=ExecResult(0,'','',0)
        result=stage_agents(control,cfg)
        self.assertFalse(result['worker_started']);self.assertEqual(control.write_bytes.call_count,2)
        self.assertIn('-Mode Standard',result['start_command']);self.assertIn('-ProcessIsolation:$false',result['start_command'])
        self.assertIn('-WorkerPath',result['start_command'])
        self.assertTrue(all('Start-ScheduledTask' not in c.args[0] for c in control.exec_powershell.call_args_list))
        self.assertIn('Assert-Bundle $stage',control.exec_powershell.call_args_list[1].args[0])

    def test_heal_stages_before_reconnect_and_does_not_claim_remote_start(self):
        from enclave_gateway.engine import EnclaveEngine
        from enclave_gateway.audit.flight_recorder import FlightRecorder
        from enclave_gateway.security.secrets import SecretVault
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);control=Mock();control.exec_powershell.return_value=ExecResult(124,'SESSION_PENDING_WORKER','',0)
            engine=EnclaveEngine(EnclaveConfig.from_dict(starter_configuration()),control_override=control,
                    vault=SecretVault(root/'absent.env'),recorder=FlightRecorder(root/'audit.jsonl'))
            with patch.object(engine,'stage_agents',return_value={'start_command':"& 'approved-bootstrap.ps1' -Mode Standard"}) as stage:
                result=engine.heal()
            stage.assert_called_once();self.assertEqual(result.exit_code,124)
            self.assertIn('In the Bastion RDP session',result.stdout);self.assertIn('-Mode Standard',result.stdout)

    def test_doctor_reports_connection_errors_and_skips_disabled_bastion(self):
        from enclave_gateway.engine import EnclaveEngine
        from enclave_gateway.audit.flight_recorder import FlightRecorder
        from enclave_gateway.security.secrets import SecretVault
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);control=Mock()
            cfg=EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'bastion':{'enabled':False}})
            engine=EnclaveEngine(cfg,control_override=control,vault=SecretVault(root/'absent.env'),recorder=FlightRecorder(root/'audit.jsonl'))
            status={'appliance':{'running':False,'hypervisor':'direct'},'provider':{'tunnel_up':True,'probe_host':'127.0.0.1','probe_port':22},'bastion':{'worker_healthy':False}}
            with patch.object(engine,'status',return_value=status):
                control.exec_powershell.return_value=ExecResult(0,'DIAG_CLOCK:'+str(int(time.time()))+':UDP:0','',0)
                result=engine.doctor();self.assertTrue(result['healthy'])
                self.assertFalse(next(v for v in result['checks'] if v['check']=='bastion_rdp_vfs_ipc')['applicable'])
                control.exec_powershell.side_effect=ConnectionError('QGA unavailable')
                result=engine.doctor();self.assertFalse(result['healthy'])
                self.assertTrue(any('remediation' in row for row in result['checks'] if not row['ok']))


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
class StandardWorkerTests(unittest.TestCase):
    def test_enterprise_bootstrap_rejects_weaker_execution_before_any_spool_write(self):
        with tempfile.TemporaryDirectory() as folder:
            spool=Path(folder)/'not-created'
            quote=lambda v:"'"+str(v).replace("'","''")+"'"
            invoke='& '+quote(ROOT/'src/enclave_gateway/agents/bastion_bootstrap.ps1')+' -Mode Enterprise -ProcessIsolation:$false -SourceSpool '+quote(spool)
            result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-Command',invoke],capture_output=True,timeout=30)
            self.assertNotEqual(result.returncode,0);self.assertFalse(spool.exists())

    @unittest.skipUnless(os.name=='nt','Windows execution policy fixture')
    def test_standard_does_not_bypass_allsigned_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            spool=Path(folder)/'not-created'
            result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-ExecutionPolicy','AllSigned','-File',
                str(ROOT/'src/enclave_gateway/agents/bastion_bootstrap.ps1'),'-Mode','Standard','-SourceSpool',str(spool)],capture_output=True,timeout=30)
            self.assertNotEqual(result.returncode,0);self.assertFalse(spool.exists())

    def test_real_bootstrap_runs_commands_without_runtime_and_honors_explicit_isolation(self):
        sys.path.insert(0,str(ROOT/'scripts/qualification'))
        from worker_loopback import FileChannel
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        from enclave_gateway.config import BastionSpec
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);spool=root/'spool';spool.mkdir();stop=root/'stop';missing=root/'missing-runtime.exe'
            cfg=EnclaveConfig.from_dict({'security':{'mode':'standard'},'bastion':{'bastion_spool_dir':str(spool)}})
            files,_,identity,start=agent_bundle(cfg);bundle=spool/'agents'/identity;bundle.mkdir(parents=True)
            (bundle.parent/'.bundle-lease').touch()
            for name,data in files.items():(bundle/name).write_bytes(data)
            if os.name!='nt':start=start.replace('\\','/')
            quote=lambda v:"'"+str(v).replace("'","''")+"'"
            command=[os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-NonInteractive','-Command',
                     start+' -RuntimeHelper '+quote(missing)+' -StopFile '+quote(stop)]
            environment=dict(os.environ)
            if os.name!='nt':
                fake=root/'ssh.exe'
                fake.write_text('#!'+sys.executable+"\nimport sys;sys.stdin.buffer.read();print('ssh-тест');print('ssh-warning',file=sys.stderr)\n")
                fake.chmod(0o700);environment['PATH']=str(root)+os.pathsep+environment.get('PATH','')
            with (root/'worker.log').open('wb') as log:
                process=subprocess.Popen(command,stdout=log,stderr=log,env=environment)
                try:
                    deadline=time.monotonic()+20
                    while not (spool/'worker_state.json').exists():
                        if process.poll() is not None or time.monotonic()>deadline:self.fail((root/'worker.log').read_text(errors='replace'))
                        time.sleep(.05)
                    state=json.loads((spool/'worker_state.json').read_text());self.assertEqual(state['execution_model'],'runspace');self.assertEqual(state['security_mode'],'standard')
                    transport=RdpVfsTransport(FileChannel(spool,os.environ['EGW_TEST_POWERSHELL']),BastionSpec(appliance_spool_dir=str(spool),bastion_spool_dir=str(spool)))
                    result=transport.exec_bastion("Write-Output 'first-run-ready'",timeout_sec=10)
                    self.assertEqual(result.exit_code,0);self.assertEqual(result.stdout,'first-run-ready');self.assertFalse(missing.exists())
                    if os.name!='nt':
                        from enclave_gateway.transports.ssh_hop import SshHopExecutor
                        executor=SshHopExecutor(transport.exec_bastion,Mock(),Mock())
                        result=executor.exec_node(TargetNodeSpec('fixture','127.0.0.1',user='fixture'),'unused',timeout_sec=15)
                        self.assertEqual(result.exit_code,0);self.assertEqual(result.stdout,'ssh-тест\n');self.assertIn('ssh-warning',result.stderr)
                    source=root/'source.bin';source.write_bytes(bytes(range(256))*257)
                    remote=root/'target space'/'тест.bin';remote.parent.mkdir()
                    digest=transport.push_file(source,str(remote))
                    self.assertEqual(transport.pull_file(str(remote),root/'received.bin'),digest)
                    self.assertEqual((root/'received.bin').read_bytes(),source.read_bytes())
                finally:
                    stop.write_text('stop')
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            # Use PowerShell boolean syntax (not native argv string-to-bool conversion).
            quoted=lambda v:"'"+str(v).replace("'","''")+"'"
            invoke='& '+quoted(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1')+' -Mode Standard -ProcessIsolation:$true -RuntimeHelper '+quoted(missing)+' -SpoolDir '+quoted(root/'isolated')
            result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-Command',invoke],capture_output=True,timeout=30)
            self.assertNotEqual(result.returncode,0);self.assertIn(b'managed runtime',result.stderr)
