"""Field regressions without live topology: WAN dispatch, local journals and cleanup."""
import base64
from contextlib import contextmanager
import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
from enclave_gateway.config import ApplianceSpec,BastionSpec,EnclaveConfig,parse_yaml_or_json
from enclave_gateway.control.qga_client import ExecResult,QgaClient
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.onboarding import starter_configuration,starter_yaml,agent_bundle
from enclave_gateway.operations.context import OperationError
from enclave_gateway.spool_cleanup import cleanup_script
from enclave_gateway.worker_channel import require_running_worker
from test_operational_ux import LocalPowerShellControl

ROOT=Path(__file__).resolve().parents[1]


def engine_at(root,control,config=None):
    from enclave_gateway.audit.flight_recorder import FlightRecorder
    from enclave_gateway.security.secrets import SecretVault
    return EnclaveEngine(config or EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'}}),control_override=control,
                         vault=SecretVault(root/'missing.env'),recorder=FlightRecorder(root/'audit.jsonl'))


class FieldContracts(unittest.TestCase):
    def test_explicit_control_paths_preserve_vm_identity_and_never_adopt_endpoint(self):
        from enclave_gateway.hypervisor.driver import ApplianceHypervisor
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);pid=root/'short.pid';pid.write_text('123')
            spec=ApplianceSpec(name='enclave-appliance',qga_socket_path=str(root/'short-qga.sock'),qmp_socket_path=str(root/'short-qmp.sock'),pid_file_path=str(pid))
            self.assertEqual(spec.pid_file,pid);self.assertEqual(spec.qga_socket,root/'short-qga.sock')
            vm=ApplianceHypervisor(spec);vm.qmp=Mock();vm.qmp.query_status.return_value={'return':{'status':'running'}};vm.qmp.execute.return_value={'return':{'name':'other-appliance'}}
            with self.assertRaises(OperationError) as raised:vm.is_running()
            self.assertEqual(raised.exception.code,'vm_identity_mismatch');self.assertIn('enclave-appliance',str(raised.exception));self.assertIn('other-appliance',str(raised.exception))
            pid.unlink()
            with self.assertRaisesRegex(ValueError,'Explicit control paths'):vm._start()
            vm.qmp.execute.assert_called_once()

    def test_starter_yaml_exposes_attachment_paths_and_probe_follows_bastion(self):
        text=starter_yaml();self.assertTrue(text.startswith('#'));data=parse_yaml_or_json(text)
        for name in ('name','runtime_dir','disk_path','efi_vars_path','qga_socket_path','qmp_socket_path','pid_file_path'):self.assertIn(name,data['appliance'])
        data['bastion'].update(host='10.0.1.20',port=3390)
        config=EnclaveConfig.from_dict(data);self.assertEqual((config.provider.probe_host,config.provider.probe_port),('10.0.1.20',3390))
        data['provider'].update(probe_host='10.0.1.30',probe_port=443)
        config=EnclaveConfig.from_dict(data);self.assertEqual((config.provider.probe_host,config.provider.probe_port),('10.0.1.30',443))
        for values in ({'probe_host':False},{'probe_host':None},{'probe_port':False},{'probe_port':None}):
            with self.assertRaises(ValueError):EnclaveConfig.from_dict({'provider':values})
        config=EnclaveConfig.from_dict(starter_configuration())
        command=agent_bundle(config)[3];self.assertNotIn('Bypass',command);self.assertIn('[IO.File]::Copy',command)
        self.assertIn("& (Join-Path $egwLocal 'bastion_bootstrap.ps1')",command)
        explicit=agent_bundle(config,execution_policy='RemoteSigned')[3];self.assertIn('-Scope Process',explicit);self.assertIn("-eq 'AllSigned'",explicit)
        combined=agent_bundle(config,execution_policy='RemoteSigned',migrate_legacy_state=True)[3]
        self.assertIn('-Scope Process',combined);self.assertIn('-MigrateLegacyState',combined)
        self.assertNotIn('-MigrateLegacyState',agent_bundle(config,execution_policy='RemoteSigned')[3])
        config.security.require_signed_agents=True
        with self.assertRaises(ValueError):agent_bundle(config,execution_policy='RemoteSigned')

    def test_fast_fail_precedes_publish_and_accepts_realistic_heartbeat_age(self):
        control=Mock();control.supports_direct_spool_ipc=True;spec=BastionSpec()
        stamp=lambda age:datetime.datetime.fromtimestamp(time.time()-age,datetime.timezone.utc).isoformat()
        for age in (0.1,28,44):
            control.try_read_bytes.return_value=json.dumps({'status':'running','last_heartbeat_utc':stamp(age)}).encode();require_running_worker(control,spec)
        for raw in (None,json.dumps({'status':'stopped','last_heartbeat_utc':stamp(0)}).encode(),json.dumps({'status':'running','last_heartbeat_utc':stamp(46)}).encode()):
            control.try_read_bytes.return_value=raw
            with tempfile.TemporaryDirectory() as folder:
                engine=engine_at(Path(folder),control)
                with self.assertRaises(OperationError) as raised:engine.exec_node('@bastion',"Write-Output 'never'",tx_id='not_dispatched')
                self.assertEqual(raised.exception.code,'session_pending_worker');self.assertFalse(raised.exception.indeterminate)
        control.publish_bytes.assert_not_called()

    def test_clean_reaches_appliance_when_bastion_times_out_and_no_vfs_cleanup_flood(self):
        from enclave_gateway.transports.ssh_hop import SshHopExecutor
        with tempfile.TemporaryDirectory() as folder:
            control=Mock();control.exec_powershell.return_value=ExecResult(0,'APPLIANCE_CLEAN_OK:{"removed":2,"deferred_processing":1,"errors":0}','',1)
            engine=engine_at(Path(folder),control)
            engine.rdp_vfs.close_mux_sessions=Mock(side_effect=TimeoutError('worker unavailable'))
            result=engine.clean_session();self.assertTrue(result['appliance_cleaned']);self.assertFalse(result['bastion_cleaned']);self.assertEqual(result['details']['removed'],2)
        hop=Mock(return_value=ExecResult(1,'','transfer fixture failure',0));cleanup=Mock()
        executor=SshHopExecutor(hop,Mock(return_value='a'*64),Mock(),cleanup_hop_fn=cleanup)
        with self.assertRaises(RuntimeError):executor.push_file_to_node(__import__('enclave_gateway.config',fromlist=['TargetNodeSpec']).TargetNodeSpec('app','10.0.0.10'),Path('unused'),'/tmp/result')
        self.assertEqual(hop.call_count,1);cleanup.assert_called_once()

    def test_clean_after_verified_stop_skips_bastion_and_cli_reports_actual_scope(self):
        from enclave_gateway.cli import main
        with tempfile.TemporaryDirectory() as folder:
            control=Mock();control.exec_powershell.return_value=ExecResult(0,'APPLIANCE_CLEAN_OK:{"removed":2,"stopped_worker_verified":true}','',1)
            engine=engine_at(Path(folder),control)
            engine.rdp_vfs.close_mux_sessions=Mock(side_effect=AssertionError('Stopped worker must not receive cleanup'))
            engine.rdp_vfs.exec_bastion=Mock(side_effect=AssertionError('Stopped worker must not receive cleanup'))
            result=engine.clean_session()
            self.assertTrue(result['ok']);self.assertTrue(result['appliance_cleaned']);self.assertFalse(result['bastion_cleaned'])
            self.assertEqual(result['bastion_cleanup'],'skipped_worker_stopped');self.assertEqual(result['errors'],[])
            engine.rdp_vfs.exec_bastion.assert_not_called();engine.rdp_vfs.close_mux_sessions.assert_not_called()
            with patch('enclave_gateway.cli.EnclaveConfig.load',return_value=engine.config),patch('enclave_gateway.cli.EnclaveEngine',return_value=engine),patch('sys.stdout',new_callable=io.StringIO) as output:
                engine.clean_session=Mock(return_value=result)
                self.assertEqual(main(['clean']),0)
                self.assertFalse(json.loads(output.getvalue())['bastion_cleaned'])

    def test_cleanup_unavailable_or_unverified_is_not_relabelled_as_success(self):
        for code,proof in ((1,True),(0,False),(0,'true'),(0,None)):
            with self.subTest(code=code,proof=proof),tempfile.TemporaryDirectory() as folder:
                control=Mock();control.exec_powershell.return_value=ExecResult(code,'APPLIANCE_CLEAN_OK:'+json.dumps({'stopped_worker_verified':proof}),'',1)
                engine=engine_at(Path(folder),control);engine.rdp_vfs.close_mux_sessions=Mock(side_effect=TimeoutError('WAN unavailable'))
                result=engine.clean_session()
                self.assertFalse(result['ok']);self.assertFalse(result['bastion_cleaned']);self.assertEqual(result['bastion_cleanup'],'failed')
                self.assertIn('bastion_cleanup_unavailable',result['errors']);engine.rdp_vfs.close_mux_sessions.assert_called_once()
        for response in (ExecResult(0,'APPLIANCE_CLEAN_OK:{broken','',1),RuntimeError('Appliance unavailable')):
            with self.subTest(response=response),tempfile.TemporaryDirectory() as folder:
                control=Mock()
                if isinstance(response,Exception):control.exec_powershell.side_effect=response
                else:control.exec_powershell.return_value=response
                engine=engine_at(Path(folder),control);engine.rdp_vfs.close_mux_sessions=Mock()
                engine.rdp_vfs.exec_bastion=Mock(return_value=ExecResult(0,'BASTION_CLEAN_OK','',1))
                result=engine.clean_session()
                self.assertFalse(result['ok']);self.assertFalse(result['appliance_cleaned']);self.assertTrue(result['bastion_cleaned'])
                self.assertIn('appliance_cleanup_unavailable',result['errors'])

    def test_doctor_and_active_cleanup_allow_slow_round_trip_without_hiding_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            control=Mock();control.exec_powershell.return_value=ExecResult(0,'DIAG_CLOCK:'+str(int(time.time()))+':UDP:1','',1)
            config=EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'targets':{'app01':{'host':'10.0.0.10'}}})
            engine=engine_at(Path(folder),control,config)
            engine.status=Mock(return_value={'appliance':{'running':True,'hypervisor':'direct'},'provider':{'tunnel_up':True,'probe_host':'10.0.0.10','probe_port':3389},'bastion':{'worker_healthy':True}})
            def ping(*args,timeout_sec,**kwargs):
                if timeout_sec<30:raise TimeoutError('Synthetic 30-second round trip exceeds budget')
                return ExecResult(0,'VFS_PONG','',30000)
            engine.rdp_vfs.exec_bastion=Mock(side_effect=ping)
            engine.exec_node=Mock(return_value=ExecResult(0,'TARGET_SSH_OK','',30000))
            self.assertTrue(engine.doctor(probe_targets=True)['healthy'])
            self.assertGreaterEqual(engine.exec_node.call_args.kwargs['timeout_sec'],30)
            engine.rdp_vfs.exec_bastion=Mock(return_value=ExecResult(1,'','genuine failure',30000))
            report=engine.doctor(probe_targets=True)
            self.assertFalse(report['healthy']);self.assertTrue(any(row['check']=='bastion_rdp_vfs_ipc' and not row['ok'] for row in report['checks']))
            control.exec_powershell.return_value=ExecResult(0,'APPLIANCE_CLEAN_OK:{"stopped_worker_verified":false}','',1)
            engine.rdp_vfs.close_mux_sessions=Mock()
            engine.rdp_vfs.exec_bastion=Mock(return_value=ExecResult(0,'BASTION_CLEAN_OK','',30000))
            result=engine.clean_session();self.assertTrue(result['ok']);self.assertEqual(result['bastion_cleanup'],'completed')
            self.assertGreaterEqual(engine.rdp_vfs.close_mux_sessions.call_args.kwargs['timeout_sec'],30)
            self.assertGreaterEqual(engine.rdp_vfs.exec_bastion.call_args.kwargs['timeout_sec'],30)

    def test_mux_wan_budgets_preserve_explicit_deadlines_and_errors(self):
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        from enclave_gateway.operations.context import OperationContext,activate,budget
        transport=RdpVfsTransport(Mock(),BastionSpec())
        waits=[]
        def execute(*args,timeout_sec,extra_fields=None,**kwargs):
            waits.append(budget(timeout_sec))
            action=(extra_fields or {}).get('mux_action')
            return ExecResult(0,'MUX_OPEN_OK:'+extra_fields['conn_id'] if action=='open' else 'MUX_DATA:' if action=='io' else '','',0)
        transport.exec_bastion=Mock(side_effect=execute)
        conn=transport.mux_open('127.0.0.1',22);transport.mux_io(conn);transport.mux_shutdown_write(conn);transport.mux_close(conn);transport.close_mux_sessions()
        self.assertTrue(all(wait>=60 for wait in waits))
        context=OperationContext('tx_mux_deadline','@bastion','local',time.monotonic()+.25)
        with activate(context):transport.mux_io(conn,timeout_sec=.1)
        self.assertLessEqual(waits[-1],.1)
        with activate(context):
            context.deadline=time.monotonic()-1
            with self.assertRaises(OperationError):transport.mux_io(conn)
        transport.exec_bastion=Mock(return_value=ExecResult(1,'','network denied',0))
        with self.assertRaises(ConnectionError):transport.mux_io(conn)

    def test_qga_suppresses_progress_without_discarding_error_stream(self):
        client=QgaClient('/tmp/enclave-gateway-test-qga.sock')
        with patch.object(client,'exec_guest',return_value=ExecResult(1,'','genuine error',0)) as execute:
            result=client.exec_powershell("Write-Error 'genuine error'")
        code=base64.b64decode(execute.call_args.args[1][-1]).decode('utf-16le')
        self.assertTrue(code.startswith("$ProgressPreference='SilentlyContinue'"));self.assertEqual(result.stderr,'genuine error')

    def test_field_measurement_receipt_excludes_raw_output_and_topology(self):
        import argparse,sys
        sys.path.insert(0,str(ROOT/'scripts/qualification'))
        from field_probe import run
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);launcher=root/'egw';launcher.write_text('fixture launcher')
            config=root/'config.json';config.write_text(json.dumps(starter_configuration()))
            args=argparse.Namespace(egw=launcher,config=config,node='app01',source_sha='a'*40,output=root/'output',samples=1,parallel=2,timeout=30,copy_root='')
            def command(argv,**kwargs):
                return subprocess.CompletedProcess(argv,0,b'EGW_FIELD_PROBE\n',b'private-fixture-output\n')
            with patch('field_probe.subprocess.run',side_effect=command):report=run(args)
            self.assertEqual(report['status'],'passed')
            text=(args.output/'result.json').read_text()
            for value in ('private-fixture-output','10.0.1.10','app01','EGW_FIELD_PROBE'):self.assertNotIn(value,text)
            with self.assertRaises(FileExistsError):run(args)


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'),'Real PowerShell is opt-in')
class FieldWorkerTests(unittest.TestCase):
    def test_status_extracts_cim_and_native_source_addresses(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';spool.mkdir()
            config=EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'},'bastion':{'enabled':False,'appliance_spool_dir':str(spool)}})
            native=LocalPowerShellControl(os.environ['EGW_TEST_POWERSHELL'],translate_paths=False)
            for expression in ("([pscustomobject]@{IPAddress='127.0.0.1'})","([Net.IPAddress]::Parse('127.0.0.1'))"):
                prefix="function Get-NetAdapter {[pscustomobject]@{Name='Infotecs';Status='Up';InterfaceDescription='Infotecs'}};function Test-NetConnection {[pscustomobject]@{TcpTestSucceeded=$true;InterfaceAlias='Infotecs';SourceAddress="+expression+"}};"
                control=Mock();control.exec_powershell.side_effect=lambda text,**kwargs:native.exec_powershell(prefix+text,**kwargs)
                engine=engine_at(root,control,config)
                self.assertEqual(engine.status()['provider']['source_ip'],'127.0.0.1')

    @unittest.skipUnless(os.name=='nt','Windows RemoteSigned and NTFS alternate-stream fixture')
    def test_local_script_copy_preserves_internet_zone_and_execution_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';spool.mkdir();local=root/'local';stop=root/'stop';stop.touch()
            config=EnclaveConfig.from_dict({'security':{'mode':'standard'},'bastion':{'bastion_spool_dir':str(spool)}})
            files,_,identity,command=agent_bundle(config);bundle=spool/'agents'/identity;bundle.mkdir(parents=True);(bundle.parent/'.bundle-lease').touch()
            for name,data in files.items():(bundle/name).write_bytes(data)
            Path(str(bundle/'bastion_bootstrap.ps1')+':Zone.Identifier').write_text('[ZoneTransfer]\nZoneId=3\n')
            invocation=command+" -StopFile '"+str(stop).replace("'","''")+"'"
            result=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-Command',invocation],capture_output=True,timeout=30,env={**os.environ,'LOCALAPPDATA':str(local)})
            self.assertNotEqual(result.returncode,0)
            copied=local/'EnclaveGateway'/'agents'/identity/'bastion_bootstrap.ps1'
            self.assertIn('ZoneId=3',Path(str(copied)+':Zone.Identifier').read_text())
            self.assertFalse((spool/'.worker-session').exists())

    def test_queue_hint_loss_and_parallel_requests_preserve_delivery(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';spool.mkdir();transport=self.transport(spool)
            with self.worker(root,spool,no_provider=True):
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results=list(pool.map(lambda number:transport.exec_bastion("Write-Output 'parallel-"+str(number)+"'",timeout_sec=10),range(8)))
                self.assertEqual([result.stdout for result in results],['parallel-'+str(i) for i in range(8)])
                self.assertTrue(all(result.exit_code==0 for result in results))
                # A malformed advisory index must not lose an unindexed request.
                (spool/'request_index.json').write_text('{"revision":1,"files":null}')
                request={'tx_id':'tx_unindexed','op':'exec','payload_b64':base64.b64encode(b"Write-Output 'recovered'").decode(),'timeout_ms':10000,'expires_unix_ms':int((time.time()+10)*1000)}
                with patch('enclave_gateway.control.published.publish_queue_hint',return_value=None):
                    result=transport._dispatch_envelope(request,timeout_sec=10)
                self.assertEqual(result.stdout,'recovered');self.assertEqual(result.exit_code,0)

    @contextmanager
    def worker(self,root,spool,*,state_root=None,migrate=False,no_provider=False):
        shell=os.environ['EGW_TEST_POWERSHELL'];stop=root/('stop-'+str(time.monotonic_ns()));logpath=root/('worker-'+str(time.monotonic_ns())+'.log')
        quote=lambda value:"'"+str(value).replace("'","''")+"'"
        code='& '+quote(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1')+' -Mode Standard -SpoolDir '+quote(spool)+' -StopFile '+quote(stop)
        if state_root:code+=' -StateRoot '+quote(state_root)
        if migrate:code+=' -MigrateLegacyState'
        if no_provider:
            code="function Join-Path {throw 'Provider path resolution is forbidden'};function Get-ChildItem {throw 'FileSystemProvider enumeration is forbidden'};function Move-Item {throw 'FileSystemProvider move is forbidden'};function Remove-Item {throw 'FileSystemProvider delete is forbidden'};"+code
        log=logpath.open('wb');process=subprocess.Popen([shell,'-NoProfile','-NonInteractive','-Command',code],stdout=log,stderr=log)
        try:
            end=time.monotonic()+20
            while True:
                if process.poll() is not None:self.fail(logpath.read_text(errors='replace'))
                try:
                    state=json.loads((spool/'worker_state.json').read_text(encoding='utf-8-sig'))
                    if state.get('status')=='running' and state['pid']==process.pid:break
                except (OSError,ValueError):pass
                if time.monotonic()>end:self.fail('No worker heartbeat: '+logpath.read_text(errors='replace'))
                time.sleep(.02)
            yield process,logpath
        finally:
            stop.touch()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            log.close()

    def transport(self,spool):
        import sys
        sys.path.insert(0,str(ROOT/'scripts/qualification'))
        from worker_loopback import FileChannel
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        return RdpVfsTransport(FileChannel(spool,os.environ['EGW_TEST_POWERSHELL']),BastionSpec(appliance_spool_dir=str(spool),bastion_spool_dir=str(spool)))

    def test_provider_free_dispatch_singleton_stop_and_local_journal_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';spool.mkdir();storage=root/'state';transport=self.transport(spool)
            with self.worker(root,spool,state_root=storage,no_provider=True) as (process,log):
                result=transport.exec_bastion("Write-Output 'field-ready'",timeout_sec=5)
                self.assertEqual(result.stdout,'field-ready');self.assertEqual(result.exit_code,0)
                state=json.loads((spool/'worker_state.json').read_text());self.assertEqual(state['journal_location'],'bastion-local')
                self.assertFalse((spool/'.transactions').exists())
                duplicate=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-File',str(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1'),'-Mode','Standard','-SpoolDir',str(spool)],capture_output=True,timeout=10)
                self.assertNotEqual(duplicate.returncode,0);self.assertIn(b'WORKER_ALREADY_RUNNING',duplicate.stderr)
                self.assertEqual(transport.exec_bastion("Write-Output 'still-running'",timeout_sec=5).stdout,'still-running')
                from concurrent.futures import ThreadPoolExecutor
                active=root/'active-job'
                text="[IO.File]::WriteAllText('"+str(active).replace("'","''")+"','active');Start-Sleep -Milliseconds 1500;Write-Output 'finished'"
                with ThreadPoolExecutor(max_workers=1) as pool:
                    running=pool.submit(transport.exec_bastion,text,timeout_sec=8)
                    deadline=time.monotonic()+5
                    while not active.exists():
                        if time.monotonic()>deadline:self.fail('Long job did not start')
                        time.sleep(.01)
                    busy=transport.exec_bastion('',op='stop',timeout_sec=5)
                    self.assertEqual(busy.exit_code,75);self.assertIn('WORKER_BUSY',busy.stderr)
                    self.assertEqual(running.result(timeout=5).stdout,'finished')
                stopped=transport.exec_bastion('',op='stop',timeout_sec=5);self.assertEqual(stopped.stdout,'WORKER_STOP_ACCEPTED');process.wait(timeout=10)
            self.assertEqual(json.loads((spool/'worker_state.json').read_text())['status'],'stopped')
            binding=json.loads((spool/'worker_storage.json').read_text());local=storage/binding['storage_id']
            self.assertTrue(list(local.glob('tx_*.json')))
            with self.worker(root,spool,state_root=storage):self.assertEqual(transport.exec_bastion("Write-Output 'restart-ready'",timeout_sec=5).stdout,'restart-ready')
            (local/'storage.json').unlink()
            failed=subprocess.run([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-File',str(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1'),'-Mode','Standard','-SpoolDir',str(spool),'-StateRoot',str(storage)],capture_output=True,timeout=10)
            self.assertNotEqual(failed.returncode,0);self.assertIn(b'WORKER_JOURNAL_MISSING',failed.stderr)

    def test_explicit_legacy_migration_retains_old_identity_and_refuses_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';legacy=spool/'.transactions';legacy.mkdir(parents=True);storage=root/'state'
            record=json.dumps({'tx_id':'tx_legacy','state':'running'});(legacy/'tx_legacy.json').write_text(record)
            script=ROOT/'src/enclave_gateway/agents/bastion_worker.ps1';shell=os.environ['EGW_TEST_POWERSHELL']
            failed=subprocess.run([shell,'-NoProfile','-File',str(script),'-Mode','Standard','-SpoolDir',str(spool),'-StateRoot',str(storage)],capture_output=True,timeout=10)
            self.assertNotEqual(failed.returncode,0);self.assertIn(b'LEGACY_STATE_MIGRATION_REQUIRED',failed.stderr)
            with self.worker(root,spool,state_root=storage,migrate=True):
                marker=root/'must-not-exist';payload="[IO.File]::WriteAllText('"+str(marker).replace("'","''")+"','replayed')"
                request={'tx_id':'tx_legacy','op':'exec','payload_b64':base64.b64encode(payload.encode()).decode(),'timeout_ms':5000,'expires_unix_ms':int((time.time()+5)*1000)}
                (spool/'req_tx_legacy.json').write_text(json.dumps(request))
                end=time.monotonic()+5
                while not(spool/'res_tx_legacy.json').exists():
                    if time.monotonic()>end:self.fail('No retained transaction response')
                    time.sleep(.01)
                reply=json.loads((spool/'res_tx_legacy.json').read_text());self.assertEqual(reply['state'],'indeterminate');self.assertFalse(marker.exists())
            self.assertEqual((legacy/'tx_legacy.json').read_text(),record)

    def test_local_cleanup_removes_only_expired_unclaimed_requests(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';spool.mkdir();control=LocalPowerShellControl(os.environ['EGW_TEST_POWERSHELL'],translate_paths=False)
            request=lambda tx,delta:json.dumps({'tx_id':tx,'expires_unix_ms':int((time.time()+delta)*1000)})
            (spool/'req_tx_expired.json').write_text(request('tx_expired',-10));(spool/'cancel_tx_expired.json').write_text('{}')
            (spool/'req_tx_future.json').write_text(request('tx_future',100));(spool/'req_tx_busy.json.processing').write_text(request('tx_busy',-10))
            (spool/'unrelated.tmp').write_text('retained')
            result=control.exec_powershell(cleanup_script(str(spool)));self.assertEqual(result.exit_code,0,result.stderr)
            report=json.loads(result.stdout.split(':',1)[1]);self.assertEqual(report['removed'],1);self.assertEqual(report['deferred_processing'],1)
            self.assertTrue((spool/'req_tx_future.json').exists());self.assertTrue((spool/'req_tx_busy.json.processing').exists());self.assertTrue((spool/'unrelated.tmp').exists())
            self.assertFalse((spool/'cancel_tx_expired.json').exists())

    def test_cleanup_distinguishes_live_lease_from_stopped_worker_without_heartbeat_guess(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';spool.mkdir()
            control=LocalPowerShellControl(os.environ['EGW_TEST_POWERSHELL'],translate_paths=False)
            config=EnclaveConfig.from_dict({'security':{'mode':'standard'},'appliance':{'hypervisor':'direct'},'bastion':{'appliance_spool_dir':str(spool)}})
            engine=engine_at(root,control,config)
            engine.rdp_vfs.close_mux_sessions=Mock()
            engine.rdp_vfs.exec_bastion=Mock(return_value=ExecResult(0,'BASTION_CLEAN_OK','',1))
            with self.worker(root,spool,state_root=root/'state'):
                live=engine.clean_session()
                self.assertTrue(live['ok']);self.assertFalse(live['details']['stopped_worker_verified'])
                self.assertEqual(live['bastion_cleanup'],'completed');engine.rdp_vfs.close_mux_sessions.assert_called_once()
            engine.rdp_vfs.close_mux_sessions.reset_mock();engine.rdp_vfs.exec_bastion.reset_mock()
            # A stale "running" heartbeat is not the stopped-worker authority.
            (spool/'worker_state.json').write_text(json.dumps({'status':'running'}))
            stopped=engine.clean_session()
            self.assertTrue(stopped['ok']);self.assertTrue(stopped['details']['stopped_worker_verified'])
            self.assertFalse(stopped['bastion_cleaned']);self.assertEqual(stopped['bastion_cleanup'],'skipped_worker_stopped')
            engine.rdp_vfs.close_mux_sessions.assert_not_called();engine.rdp_vfs.exec_bastion.assert_not_called()
