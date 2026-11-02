"""Operational contracts: exact SSH outcomes, private support and owned bundle cleanup."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
from enclave_gateway.cli import main
from enclave_gateway.config import EnclaveConfig,TargetNodeSpec
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.diagnostics import support_preview,save_support,diagnostic_code
from enclave_gateway.onboarding import configuration_summary,stage_agents,agent_bundle
from enclave_gateway.agent_maintenance import prune_agent_bundles
from enclave_gateway.operations.context import OperationError
from enclave_gateway.transports.ssh_hop import SshHopExecutor

ROOT=Path(__file__).resolve().parents[1]


def envelope(code,out='',err=''):
    return json.dumps({'schema':'egw.ssh-result.v1','exit_code':code,
                       'stdout_b64':base64.b64encode(out.encode()).decode(),
                       'stderr_b64':base64.b64encode(err.encode()).decode()})


class OperationalTests(unittest.TestCase):
    def test_ssh_results_preserve_status_whitespace_and_channel_failures(self):
        node=TargetNodeSpec('app','10.0.0.10')
        for code in (0,1,42,255):
            channel=ExecResult(0,envelope(code,'\nтест\n\n','warning\n'),'outer warning',7,'tx_fixture',{'ssh':4})
            hop=Mock(return_value=channel);executor=SshHopExecutor(hop,Mock(),Mock())
            result=executor.exec_node(node,'unused')
            self.assertEqual((result.exit_code,result.stdout,result.stderr),(code,'\nтест\n\n','warning\n'))
            self.assertEqual(result.tx_id,'tx_fixture');self.assertEqual(result.timings_ms,{'ssh':4})
        failure=ExecResult(124,'','channel deadline',9)
        self.assertIs(SshHopExecutor(Mock(return_value=failure),Mock(),Mock()).exec_node(node,'unused'),failure)
        for out in ('not json',envelope(True),envelope(-1),envelope(256),'{"schema":"egw.ssh-result.v1"}'):
            with self.subTest(out=out),self.assertRaises(OperationError) as raised:
                SshHopExecutor(Mock(return_value=ExecResult(0,out,'',0)),Mock(),Mock()).exec_node(node,'unused')
            self.assertTrue(raised.exception.indeterminate)
        self.assertEqual(diagnostic_code('publickey',42),'remote_command_failed')
        self.assertEqual(diagnostic_code('',255),'ssh_connection_or_remote_exit')

    def test_no_bastion_guidance_and_heal_do_not_read_credentials_or_reconnect(self):
        from enclave_gateway.engine import EnclaveEngine
        from enclave_gateway.audit.flight_recorder import FlightRecorder
        from enclave_gateway.security.secrets import SecretVault
        cfg=EnclaveConfig.from_dict({'security':{'mode':'standard'},'bastion':{'enabled':False},'targets':{'app':{'host':'10.0.0.10','via':'appliance'}}})
        self.assertNotIn('Bastion',json.dumps(configuration_summary(cfg)['next_steps']))
        self.assertNotIn('agents stage',json.dumps(configuration_summary(cfg)['next_steps']))
        with tempfile.TemporaryDirectory() as folder:
            control=Mock();control.exec_powershell.return_value=ExecResult(0,'APPLIANCE_INIT_OK','',0)
            vault=SecretVault(Path(folder)/'missing.env')
            engine=EnclaveEngine(cfg,control_override=control,vault=vault,recorder=FlightRecorder(Path(folder)/'audit.jsonl'))
            with patch.object(vault,'get',side_effect=AssertionError('No RDP secrets should be read')):
                self.assertEqual(engine.heal().exit_code,0)
            script=control.exec_powershell.call_args.args[0]
            self.assertIn('-SkipBastion:$true',script);self.assertNotIn('-ForceReconnect',script)
            engine._direct_posix=True;control.reset_mock()
            self.assertEqual(engine.heal().exit_code,0);control.exec_powershell.assert_not_called()

    def test_support_snapshot_omits_free_form_data_and_requires_exact_review(self):
        secret='private-fixture-value'
        cfg=EnclaveConfig.from_dict({'profile':secret,'appliance':{'hypervisor':'direct'},'security':{'mode':'standard'},
                                    'bastion':{'enabled':False},'targets':{secret:{'host':'10.0.0.10','via':'appliance'}}})
        raw={'checks':[{'check':'qemu','ok':False,'detail':secret+' /private/path 10.0.0.10'},
                       {'check':secret,'ok':False,'detail':secret}]}
        with patch('enclave_gateway.diagnostics.preflight',return_value=raw),tempfile.TemporaryDirectory() as folder:
            preview,data=support_preview(cfg)
            for value in (secret,'10.0.0.10','/private/path'):self.assertNotIn(value,data.decode())
            output=Path(folder)/'support.json'
            with self.assertRaises(ValueError):save_support(cfg,output,'0'*64)
            self.assertFalse(output.exists())
            result=save_support(cfg,output,preview['sha256'])
            self.assertFalse(result['sent']);self.assertEqual(output.read_bytes(),data)
            self.assertEqual(hashlib.sha256(data).hexdigest(),preview['sha256'])
            if os.name!='nt':self.assertEqual(output.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):save_support(cfg,output,preview['sha256'])
            raw['checks'][0]['ok']=True
            with self.assertRaises(ValueError):save_support(cfg,Path(folder)/'changed.json',preview['sha256'])

    def test_diagnostics_cli_is_offline_and_invalid_prune_has_no_remote_effect(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'enclave.json';file.write_text(json.dumps({'appliance':{'hypervisor':'direct'},'security':{'mode':'standard'},'bastion':{'enabled':False}}))
            with patch('enclave_gateway.cli.EnclaveEngine') as engine,patch('sys.stdout',new_callable=io.StringIO) as out:
                self.assertEqual(main(['-c',str(file),'diagnostics','preview']),0)
                preview=json.loads(out.getvalue());out.seek(0);out.truncate()
                self.assertEqual(main(['-c',str(file),'diagnostics','save','--output',str(Path(folder)/'support.json'),'--sha256',preview['sha256']]),0)
                engine.assert_not_called()
        control=Mock();cfg=EnclaveConfig.from_dict({'security':{'mode':'standard'}})
        for options in ({'apply':True},{'apply':True,'remove':['../bad']},{'remove':['a'*64]},{'min_age_hours':0}):
            with self.assertRaises(ValueError):prune_agent_bundles(control,cfg,**options)
        control.exec_powershell.assert_not_called()

    def test_exec_cli_keeps_output_and_reports_remote_exit_without_setup_advice(self):
        cfg=EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'targets':{'app':{'host':'10.0.0.10'}}})
        with patch('enclave_gateway.cli.EnclaveConfig.load',return_value=cfg),patch('enclave_gateway.cli.EnclaveEngine') as engine,patch('sys.stdout',new_callable=io.StringIO) as out,patch('sys.stderr',new_callable=io.StringIO) as err:
            engine.return_value.exec_node.return_value=ExecResult(42,'\nresult\n\n','failure\n',0,'tx_fixture')
            self.assertEqual(main(['exec','app','unused']),42)
            self.assertEqual(out.getvalue(),'\nresult\n\n')
            metadata=json.loads(err.getvalue().splitlines()[0]);self.assertEqual(metadata['diagnostic_code'],'remote_command_failed')
            self.assertNotIn('Run egw config',err.getvalue())


class LocalPowerShellControl:
    def __init__(self,shell):self.shell=shell
    def exec_powershell(self,script,timeout_sec=60):
        if os.name!='nt':script=script.replace('\\','/')
        started=time.monotonic()
        bootstrap='[Console]::InputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'
        result=subprocess.run([self.shell,'-NoProfile','-NonInteractive','-Command',bootstrap],input=script,
                              encoding='utf-8',capture_output=True,timeout=timeout_sec)
        # PowerShell -Command - emits terminal escapes on some editions.
        import re
        clean=lambda value:re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]','',value)
        return ExecResult(result.returncode,clean(result.stdout),clean(result.stderr),int((time.monotonic()-started)*1000))
    def write_bytes(self,data,path):
        if os.name!='nt':path=path.replace('\\','/')
        Path(path).write_bytes(data)


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
class PowerShellOperationalTests(unittest.TestCase):
    def test_no_bastion_appliance_repair_never_applies_rdp_settings(self):
        control=LocalPowerShellControl(os.environ['EGW_TEST_POWERSHELL'])
        path=str(ROOT/'src/enclave_gateway/agents/appliance_init.ps1').replace("'","''")
        script='''$ErrorActionPreference='Stop'
function Test-Path {return $false}
function Set-ItemProperty {throw 'Unexpected registry change'}
function New-Item {throw 'Unexpected registry creation'}
function powercfg.exe {throw 'Unexpected power policy change'}
function netsh.exe {if(($args -join ' ') -notlike 'interface ipv4 set subinterface *'){throw 'Unexpected portproxy change'}}
& 'PATH' -SkipBastion
'''.replace('PATH',path)
        result=control.exec_powershell(script)
        self.assertEqual(result.exit_code,0,result.stderr);self.assertIn('APPLIANCE_INIT_OK',result.stdout);self.assertFalse(result.stderr)

    def test_real_ssh_envelope_preserves_nonzero_exit_and_unambiguous_output(self):
        if os.name=='nt':self.skipTest('POSIX executable fixture for the Windows-hop launcher')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);fake=root/'ssh.exe'
            fake.write_text('#!'+__import__('sys').executable+"\nimport sys;sys.stdin.buffer.read();sys.stdout.write('\\n{\"exit_code\":0}\\n\\n');sys.stderr.write('warning\\n');sys.exit(42)\n")
            fake.chmod(0o700)
            with patch.dict(os.environ,{'PATH':str(root)+os.pathsep+os.environ.get('PATH','')}):
                control=LocalPowerShellControl(os.environ['EGW_TEST_POWERSHELL'])
                result=SshHopExecutor(control.exec_powershell,Mock(),Mock()).exec_node(TargetNodeSpec('app','127.0.0.1'),'unused')
            self.assertEqual(result.exit_code,42);self.assertEqual(result.stdout,'\n{"exit_code":0}\n\n');self.assertEqual(result.stderr,'warning\n')

    def test_real_bundle_cleanup_preserves_legacy_current_changed_and_active(self):
        shell=os.environ['EGW_TEST_POWERSHELL'];control=LocalPowerShellControl(shell)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';stop=root/'stop';package=root/'package';package.mkdir()
            for name in ('bastion_worker.ps1','bastion_bootstrap.ps1'):
                data=(ROOT/'src/enclave_gateway/agents'/name).read_bytes()
                if name=='bastion_worker.ps1':data+=b'\n# retired fixture generation\n'
                (package/name).write_bytes(data)
            config=lambda source='':EnclaveConfig.from_dict({'security':{'mode':'standard','agent_package_dir':source},'bastion':{'appliance_spool_dir':str(spool),'bastion_spool_dir':str(spool)}})
            current=config();old=config(str(package))
            first=stage_agents(control,current);second=stage_agents(control,old)
            agents=spool/'agents';old_dir=agents/second['bundle_sha256'];old_time=time.time()-3600*200
            os.utime(old_dir,(old_time,old_time))
            legacy=agents/('a'*64);legacy.mkdir();(legacy/'bastion_worker.ps1').write_text('legacy')
            incoming=agents/'.incoming-unrelated';incoming.mkdir();(incoming/'retained').write_text('unrelated')
            rows=prune_agent_bundles(control,current)['bundles']
            reasons={row['bundle_sha256']:row['reason'] for row in rows}
            self.assertEqual(reasons[first['bundle_sha256']],'retained');self.assertEqual(reasons[second['bundle_sha256']],'eligible');self.assertEqual(reasons['a'*64],'legacy-or-unrecognized')
            with self.assertRaises(RuntimeError):prune_agent_bundles(control,current,apply=True,remove=[second['bundle_sha256'],first['bundle_sha256']])
            self.assertTrue(old_dir.exists())
            with self.assertRaises(RuntimeError):prune_agent_bundles(control,current,apply=True,remove=[second['bundle_sha256']],keep=[second['bundle_sha256']])
            worker=old_dir/'bastion_worker.ps1';original=worker.read_bytes();worker.write_bytes(original+b'\n# changed after staging\n')
            with self.assertRaises(RuntimeError):prune_agent_bundles(control,current,apply=True,remove=[second['bundle_sha256']])
            self.assertTrue(old_dir.exists());worker.write_bytes(original)
            command=second['start_command']
            if os.name!='nt':command=command.replace('\\','/')
            quote=lambda v:"'"+str(v).replace("'","''")+"'"
            process=subprocess.Popen([shell,'-NoProfile','-NonInteractive','-Command',command+' -StopFile '+quote(stop)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+30
                while not (spool/'worker_state.json').exists():
                    if process.poll() is not None or time.monotonic()>deadline:self.fail('Managed worker failed to start')
                    time.sleep(.05)
                with self.assertRaisesRegex(RuntimeError,'busy'):prune_agent_bundles(control,current,apply=True,remove=[second['bundle_sha256']])
                self.assertTrue(old_dir.exists())
                self.assertEqual(stage_agents(control,current)['bundle_sha256'],first['bundle_sha256'])
            finally:
                stop.write_text('stop')
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                process.stderr.close()
            result=prune_agent_bundles(control,current,apply=True,remove=[second['bundle_sha256']])
            self.assertEqual(result['removed'],[second['bundle_sha256']]);self.assertFalse(old_dir.exists())
            self.assertTrue((agents/first['bundle_sha256']).is_dir());self.assertTrue(legacy.is_dir())
            self.assertEqual((incoming/'retained').read_text(),'unrelated')
