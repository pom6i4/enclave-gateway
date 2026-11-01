#!/usr/bin/env python3
"""Kill only a newly launched disposable worker and corrupt its observed reply."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(Path(__file__).resolve().parent)]
from worker_loopback import Worker
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.security.secrets import SecretVault
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.operations.context import OperationError


def run(args):
    if os.name!='nt':raise RuntimeError('Use a disposable Windows guest')
    report={'status':'running','scope':'disposable-signed-worker-faults','checks':[]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    try:
        with TemporaryDirectory(prefix='egw-worker-faults-') as folder:
            root=Path(folder);worker=Worker(args.powershell,root,args.runtime,False,args.trusted_signer,startup_timeout_sec=120)
            try:
                worker.start()
                cfg=EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'},
                    'bastion':{'appliance_spool_dir':str(worker.spool),'bastion_spool_dir':str(worker.spool)},
                    'security':{'worker_sha256':hashlib.sha256((ROOT/'src/enclave_gateway/agents/bastion_worker.ps1').read_bytes()).hexdigest(),
                        'runtime_sha256':hashlib.sha256(args.runtime.read_bytes()).hexdigest(),'trusted_signers':[args.trusted_signer],
                        'enforce_worker_attestation':True,'require_process_isolation':True}})
                engine=EnclaveEngine(cfg,control_override=worker.transport.control,vault=SecretVault(env_file=root/'absent.env'),recorder=FlightRecorder(root/'audit.jsonl'))
                marker=root/'crash-marker';script='[IO.File]::AppendAllText('+ps_quote(str(marker))+",'x'); Start-Sleep -Seconds 6; Write-Output 'finished'"
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending=pool.submit(engine.exec_node,'@bastion',script,tx_id='owned_worker_crash',timeout_sec=12)
                    deadline=time.monotonic()+10
                    while not marker.exists():
                        if pending.done() or time.monotonic()>deadline:raise AssertionError('Actual crash marker not observed')
                        time.sleep(.02)
                    trust_pid=engine.rdp_vfs._verified_worker.get('trust_host_pid')
                    worker.process.kill();worker.process.wait(5)
                    if trust_pid:
                        from enclave_gateway.hypervisor.driver import process_running
                        limit=time.monotonic()+5
                        while process_running(trust_pid) and time.monotonic()<limit:time.sleep(.05)
                        assert not process_running(trust_pid),'Read-only trust host survived its worker'
                    try:pending.result(timeout=15)
                    except OperationError as error:assert error.indeterminate
                    else:raise AssertionError('Lost worker outcome reported as terminal')
                assert engine.transaction_status('owned_worker_crash')['state']=='indeterminate'
                worker.close();worker.start()
                try:engine.exec_node('@bastion',script,tx_id='owned_worker_crash',timeout_sec=12)
                except OperationError as error:assert error.indeterminate
                else:raise AssertionError('Indeterminate operation was replayed')
                assert marker.read_text()=='x'
                report['checks'].append('actual-worker-process-kill:indeterminate-without-replay')
                if trust_pid:report['checks'].append('native-trust-host-stops-after-worker-kill')
                original=engine.control.try_read_bytes;corrupted=[]
                def corrupt(path,**options):
                    raw=original(path,**options)
                    if raw:
                        value=json.loads(raw.decode('utf-8-sig'))
                        if value.get('stdout_b64')=='Y29ycnVwdC1maXh0dXJl':
                            value['exit_code']='invalid';corrupted.append(1)
                            return json.dumps(value).encode()
                    return raw
                engine.control.try_read_bytes=corrupt
                second=root/'corrupt-marker';script='[IO.File]::AppendAllText('+ps_quote(str(second))+",'x'); Write-Output 'corrupt-fixture'"
                # A restarted instance must be freshly attested.
                engine.rdp_vfs._verified_worker=None;engine.rdp_vfs._verified_until=0
                try:engine.exec_node('@bastion',script,tx_id='owned_corrupt_reply',timeout_sec=30)
                except OperationError as error:assert error.indeterminate
                else:raise AssertionError('Corrupted reply reported as terminal')
                assert len(corrupted)==1 and engine.transaction_status('owned_corrupt_reply')['state']=='indeterminate'
                engine.control.try_read_bytes=original
                try:engine.exec_node('@bastion',script,tx_id='owned_corrupt_reply',timeout_sec=30)
                except OperationError as error:assert error.indeterminate
                else:raise AssertionError('Corrupted response caused a replay')
                assert second.read_text()=='x'
                report['checks'].append('actual-execution-corrupted-reply:indeterminate-without-replay')
                third=root/'native-output-marker'
                script='[IO.File]::AppendAllText('+ps_quote(str(third))+",'x'); [Console]::WriteLine('invalid-native-output'); Write-Output 'finished'"
                try:engine.exec_node('@bastion',script,tx_id='owned_native_output',timeout_sec=30)
                except OperationError as error:assert error.indeterminate
                else:raise AssertionError('Damaged native output reported as terminal')
                assert engine.transaction_status('owned_native_output')['state']=='indeterminate'
                try:engine.exec_node('@bastion',script,tx_id='owned_native_output',timeout_sec=30)
                except OperationError as error:assert error.indeterminate
                else:raise AssertionError('Damaged native output caused a replay')
                assert third.read_text()=='x'
                report['checks'].append('actual-child-stdout-corruption:indeterminate-without-replay')
            finally:worker.close()
        report['status']='passed'
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:args.output.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--powershell',required=True);p.add_argument('--runtime',required=True,type=Path)
    p.add_argument('--trusted-signer',required=True);p.add_argument('--output',required=True,type=Path)
    print(json.dumps(run(p.parse_args()),indent=2))
