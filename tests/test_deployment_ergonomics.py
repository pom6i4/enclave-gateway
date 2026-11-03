"""Global installation, explicit authentication and current-user worker startup."""
from __future__ import annotations
import builtins
from contextlib import contextmanager,redirect_stdout
from dataclasses import asdict
import io
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from enclave_gateway.config import EnclaveConfig,SecuritySpec,global_config_path,parse_yaml_or_json,state_directory
from enclave_gateway.cli import _main
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.security.secrets import SecretVault
from enclave_gateway.onboarding import configuration_summary,agent_bundle
from enclave_gateway.diagnostics import preflight
from enclave_gateway.transports.ssh_hop import SshHopExecutor
from enclave_gateway.operations.context import OperationError


@contextmanager
def isolated():
    with tempfile.TemporaryDirectory(prefix='egw-ux-') as name:
        root=Path(name);cwd=Path.cwd();work=root/'work';work.mkdir()
        with patch.dict(os.environ,{'HOME':str(root),'XDG_CONFIG_HOME':str(root/'xdg'),'ENCLAVE_CONFIG':'','ENCLAVE_STATE_DIR':''}),patch('pathlib.Path.home',return_value=root):
            os.chdir(work)
            try:yield root,work
            finally:os.chdir(cwd)


def config_data(**extra):
    return {'security':{'mode':'standard'},'appliance':{'hypervisor':'direct'},'bastion':{'enabled':False},'provider':{'type':'custom','probe_host':'127.0.0.1'},**extra}


def save(path,profile):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps({**config_data(),'profile':profile}))


class GlobalConfigurationTests(unittest.TestCase):
    def test_search_precedence_and_explicit_missing_paths_never_fall_through(self):
        with isolated() as (root,work):
            global_file=global_config_path();save(global_file,'global')
            self.assertEqual(EnclaveConfig.load().profile,'global')
            local=work/'config/enclave.yaml';save(local,'nested');self.assertEqual(EnclaveConfig.load().profile,'nested')
            save(work/'enclave.yaml','cwd');self.assertEqual(EnclaveConfig.load().profile,'cwd')
            env=root/'environment.yaml';save(env,'environment');os.environ['ENCLAVE_CONFIG']=str(env)
            self.assertEqual(EnclaveConfig.load().profile,'environment')
            explicit=root/'explicit.yaml';save(explicit,'explicit');self.assertEqual(EnclaveConfig.load(explicit).profile,'explicit')
            with self.assertRaises(FileNotFoundError):EnclaveConfig.load(root/'missing')
            os.environ['ENCLAVE_CONFIG']=str(root/'missing')
            with self.assertRaises(FileNotFoundError):EnclaveConfig.load()
            cfg=EnclaveConfig.load(explicit);self.assertEqual(EnclaveConfig.from_dict(asdict(cfg)),cfg)
            self.assertNotIn('_source_path',asdict(cfg))
            with self.assertRaises(ValueError):EnclaveConfig.from_dict({'source_path':str(global_file)})

    def test_global_state_overrides_and_actual_audit_never_touch_cwd(self):
        with isolated() as (root,work):
            save(global_config_path(),'global');cfg=EnclaveConfig.load();state=global_config_path().parent/'state'
            state.mkdir();(state/'.env').write_text('EGW_FIXTURE_VALUE=global-state\n');(work/'.env').write_text('EGW_FIXTURE_VALUE=wrong-cwd\n')
            control=Mock();control.exec_powershell.return_value=ExecResult(0,'GLOBAL_OK','',1)
            engine=EnclaveEngine(cfg,control_override=control)
            self.assertEqual(engine.vault.get('EGW_FIXTURE_VALUE'),'global-state')
            self.assertEqual(engine.recorder.log_path,state/'audit.jsonl')
            self.assertEqual(engine.journal.path,state/'audit.transactions.sqlite3')
            self.assertEqual(engine.exec_node('@appliance','printf GLOBAL_OK').stdout,'GLOBAL_OK')
            self.assertEqual(set(p.name for p in work.iterdir()),{'.env'})
            if os.name!='nt':self.assertEqual(state.stat().st_mode&0o777,0o700)
            os.environ['ENCLAVE_STATE_DIR']=str(root/'environment-state')
            self.assertEqual(state_directory(cfg),root/'environment-state')
            explicit=root/'explicit-state';self.assertEqual(state_directory(cfg,explicit),explicit)
            engine=EnclaveEngine(cfg,state_dir=explicit,control_override=control);self.assertEqual(engine.recorder.log_path,explicit/'audit.jsonl')
            os.environ['ENCLAVE_STATE_DIR']='';save(work/'enclave.yaml','local')
            self.assertIsNone(state_directory(EnclaveConfig.load()))

    def test_global_init_permissions_no_overwrite_and_offline_check(self):
        with isolated() as (root,work),redirect_stdout(io.StringIO()):
            self.assertEqual(_main(['config','init','--global']),0)
            path=global_config_path();self.assertTrue(path.is_file());original=path.read_bytes()
            if os.name!='nt':
                self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertEqual(path.parent.stat().st_mode&0o777,0o700)
            with self.assertRaises(FileExistsError):_main(['config','init','--global'])
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(_main(['config','check']),0)
            self.assertFalse((path.parent/'state').exists());self.assertEqual(list(work.iterdir()),[])
            path.unlink();self.assertEqual(_main(['config','init','--output',str(path)]),0)
            with self.assertRaises(SystemExit):_main(['config','init','--global','--output','other.yaml'])

    def test_default_home_and_relative_xdg_do_not_create_relative_global_paths(self):
        with isolated() as (root,work):
            os.environ['XDG_CONFIG_HOME']='relative'
            self.assertEqual(global_config_path(),root/'.config/enclave-gateway/enclave.yaml')
            save(global_config_path(),'home');self.assertEqual(EnclaveConfig.load().profile,'home')


class YamlPathTests(unittest.TestCase):
    def test_windows_paths_and_quoted_escapes_with_and_without_pyyaml(self):
        try:import yaml
        except ImportError:yaml=None
        original_import=builtins.__import__
        def no_yaml(name,*args,**kwargs):
            if name=='yaml':raise ImportError('Force dependency-free parser')
            return original_import(name,*args,**kwargs)
        fixtures=[]
        for value in (r'C:\EnclaveGateway\spool',r'\\tsclient\C\EnclaveGateway\spool',"C:\\EnclaveGateway\\operator's spool"):
            fixtures.extend((value,spelling) for spelling in (value,"'"+value.replace("'","''")+"'",json.dumps(value)))
        fixtures.extend([(r'quoted " # value\path','"quoted \\\" # value\\\\path"'),('line\ncarriage\rtab\tquote"slash\\',json.dumps('line\ncarriage\rtab\tquote"slash\\'))])
        for value,spelling in fixtures:
            text='path: '+spelling+' # outside comment\n'
            with self.subTest(spelling=spelling),patch('builtins.__import__',side_effect=no_yaml):
                actual=parse_yaml_or_json(text)['path'];self.assertEqual(actual.encode(),value.encode())
            if yaml:
                self.assertEqual(parse_yaml_or_json(text)['path'].encode(),value.encode())
                self.assertEqual(yaml.safe_load(text)['path'].encode(),value.encode())
        for invalid in (r'path: "C:\EnclaveGateway\spool"',r'path: "bad\q"',"path: 'broken'quote'"):
            with self.subTest(invalid=invalid),patch('builtins.__import__',side_effect=no_yaml),self.assertRaises(ValueError):parse_yaml_or_json(invalid)


class AuthenticationSelectionTests(unittest.TestCase):
    def node_config(self,key=True,helper=''):
        return EnclaveConfig.from_dict({'security':{'mode':'standard','askpass_helper_path':helper},'appliance':{'hypervisor':'direct'},'targets':{'app01':{'host':'10.0.20.11','user':'deploy','ssh_key_path':'~/.ssh/id_ed25519' if key else '', 'password_env':'EGW_UNUSED_BACKUP','sudo_password_env':'EGW_SUDO'}}})

    def test_preflight_reports_backup_ignored_but_password_only_unready(self):
        cfg=self.node_config();row=configuration_summary(cfg)['warnings'][0]
        self.assertEqual(row['authentication'],'key-only');self.assertEqual(row['severity'],'warning')
        checks=preflight(cfg)['checks'];self.assertTrue(next(c['ok'] for c in checks if c['check']=='ssh_authentication:app01'))
        cfg=self.node_config(False);self.assertEqual(configuration_summary(cfg)['warnings'][0]['severity'],'error')
        self.assertFalse(next(c['ok'] for c in preflight(cfg)['checks'] if c['check']=='ssh_authentication:app01'))
        self.assertFalse(configuration_summary(self.node_config(helper=r'C:\EnclaveGateway\egw-askpass.exe'))['warnings'])
        self.assertEqual(SecuritySpec(mode='standard').askpass_helper_path,'')
        self.assertTrue(SecuritySpec(mode='custom').askpass_helper_path)

    def test_key_mode_does_not_read_backup_and_keeps_sudo_independent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cfg=self.node_config();vault=SecretVault(env_file=root/'.env')
            envelope=json.dumps({'schema':'egw.ssh-result.v1','exit_code':0,'stdout_b64':'T0s=','stderr_b64':''})
            hop=Mock(return_value=ExecResult(0,envelope,'',1))
            engine=EnclaveEngine(cfg,vault=vault,recorder=FlightRecorder(root/'audit.jsonl'),control_override=Mock())
            engine.bastion_ssh._exec_hop=hop
            with patch.object(vault,'get',return_value='synthetic-sudo') as get:
                self.assertEqual(engine.exec_node('app01','whoami',as_root=True).stdout,'OK')
                get.assert_called_once_with('EGW_SUDO')
            script=hop.call_args.args[0];self.assertIn('BatchMode=yes',script);self.assertNotIn('SSH_ASKPASS',script)

    def test_transport_normalizes_jump_chain_without_changing_enterprise(self):
        node=self.node_config().targets['app01'];hop=Mock();executor=SshHopExecutor(hop,Mock(),Mock(),helper_path='',security_mode='standard')
        password,jumps=executor._authentication(node,'synthetic-backup',[node]);self.assertEqual(password,'');self.assertEqual(jumps[0].password_env,'');self.assertEqual(node.password_env,'EGW_UNUSED_BACKUP')
        executor.security_mode='enterprise';self.assertEqual(executor._authentication(node,'synthetic-backup',None)[0],'synthetic-backup')

    def test_key_only_push_and_pull_build_no_password_helper_script(self):
        node=self.node_config().targets['app01'];payload=b'key-only transfer\x00\xff'
        digest=hashlib.sha256(payload).hexdigest()
        def response(stdout):
            envelope=json.dumps({'schema':'egw.ssh-result.v1','exit_code':0,'stdout_b64':base64.b64encode(stdout.encode()).decode(),'stderr_b64':''})
            return ExecResult(0,envelope,'',1)
        hop=Mock(side_effect=[ExecResult(0,'','',1),response('VERIFIED:'+digest),response('SHA256:'+digest),ExecResult(0,'','',1)])
        def download(stage,destination,timeout):destination.write_bytes(payload)
        executor=SshHopExecutor(hop,Mock(return_value=digest),download,helper_path='',security_mode='standard')
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);source=root/'source.bin';source.write_bytes(payload)
            self.assertEqual(executor.push_file_to_node(node,source,'/tmp/destination.bin',ssh_password='unused-backup'),digest)
            self.assertEqual(executor.pull_file_from_node(node,'/tmp/destination.bin',root/'result.bin',ssh_password='unused-backup'),digest)
            self.assertEqual((root/'result.bin').read_bytes(),payload)
        for call in hop.call_args_list:
            self.assertIn('BatchMode=yes',call.args[0]);self.assertNotIn('SSH_ASKPASS',call.args[0]);self.assertNotIn('unused-backup',call.args[0])


class AutostartCommandTests(unittest.TestCase):
    def test_opt_in_migration_and_replay_flags_stay_separate(self):
        cfg=EnclaveConfig.from_dict({'security':{'mode':'standard'},'bastion':{'spool_protocol':'stream'}})
        normal=agent_bundle(cfg)[3];start=agent_bundle(cfg,execution_policy='RemoteSigned',migrate_legacy_state=True,persist_autostart=True)[3]
        self.assertNotIn('-RegisterAutostart',normal);self.assertIn('-RegisterAutostart',start);self.assertIn('-MigrateLegacyState',start);self.assertIn('-SpoolProtocol Stream',start)
        with redirect_stdout(io.StringIO()) as out,tempfile.TemporaryDirectory() as d:
            path=Path(d)/'enclave.yaml';path.write_text(json.dumps({'security':{'mode':'standard'}}))
            self.assertEqual(_main(['-c',str(path),'agents','command','--persist-autostart']),0)
            self.assertIn('-RegisterAutostart',out.getvalue())
            with self.assertRaises(SystemExit):_main(['-c',str(path),'agents','command','--unregister-autostart'])

    def test_stop_requires_explicit_autostart_ack_and_never_silently_accepts_old_worker(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);engine=EnclaveEngine(EnclaveConfig(),vault=SecretVault(env_file=root/'.env'),recorder=FlightRecorder(root/'audit.jsonl'),control_override=Mock())
            engine.rdp_vfs.exec_bastion=Mock(return_value=ExecResult(0,'WORKER_STOP_ACCEPTED','',0))
            with self.assertRaises(OperationError):engine.stop_worker(unregister_autostart=True)
            self.assertEqual(engine.rdp_vfs.exec_bastion.call_args.kwargs['extra_fields'],{'unregister_autostart':True})
            engine.rdp_vfs.exec_bastion.return_value=ExecResult(0,'WORKER_STOP_ACCEPTED;AUTOSTART_UNREGISTERED','',0)
            self.assertEqual(engine.stop_worker(unregister_autostart=True).exit_code,0)
