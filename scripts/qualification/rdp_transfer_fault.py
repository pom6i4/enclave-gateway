#!/usr/bin/env python3
"""Observe an actual interrupted RDPDR transfer in an already connected lab."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PureWindowsPath
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'src'),str(Path(__file__).resolve().parent)]
from worker_loopback import FileChannel
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.security.secrets import SecretVault
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.operations.context import OperationError


def run(args):
    value=json.loads(args.configuration.read_text(encoding='utf-8-sig'))
    if value.get('scope')!='disposable-rdp-transfer-fault':raise ValueError('Explicit disposable scope required')
    remote=PureWindowsPath(value['remote_path'])
    if not remote.is_absolute() or remote.drive.startswith('\\\\'):raise ValueError('Dedicated local-drive guest file required')
    folder=args.output.resolve();folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    status=folder/(args.phase+'.json');report={'status':'running','phase':args.phase,'scope':value['scope']}
    status.write_text(json.dumps(report)+'\n')
    cfg=EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'},
        'bastion':{'appliance_spool_dir':value['spool'],'bastion_spool_dir':value['remote_spool'],'block_size_bytes':65536,'parallel_streams':2,'compress':False},
        'security':{'worker_sha256':value['worker_sha256'],'runtime_sha256':value['runtime_sha256'],'worker_account':value['sid'],
                    'trusted_signers':[value['signer']],'enforce_worker_attestation':True,'require_process_isolation':True}})
    control=FileChannel(Path(value['spool']),'')
    engine=EnclaveEngine(cfg,control_override=control,vault=SecretVault(env_file=folder/'absent.env'),recorder=FlightRecorder(folder/'audit.jsonl'))
    source=folder/'source.bin'
    try:
        evidence=engine.attest_worker();assert evidence['spool_kind']=='redirected' and evidence['session_id']>0
        report['worker_instance']=evidence['instance_id']
        if args.phase=='before':
            if source.exists():raise FileExistsError('Use a new fault workspace')
            source.write_bytes(secrets.token_bytes(64*1024*1024+1))
            response=engine.exec_node('@bastion','[IO.File]::WriteAllText('+ps_quote(str(remote)) + ",'original-target')",timeout_sec=30)
            assert response.exit_code==0
            ready=threading.Event();original=control.publish_bytes;staged=[]
            def publish(data,path):
                original(data,path)
                if str(path).replace('\\','/').rsplit('/',1)[-1].startswith('req_'):
                    envelope=json.loads(data)
                    script=base64.b64decode(envelope.get('payload_b64','')).decode()
                    match=re.search(r'\$tmp = "\$dst\.tmp_([A-Za-z0-9_]+)"',script)
                    if match:
                        staged.extend(Path(value['spool']).glob('chunk_'+match.group(1)+'_*.bin'));ready.set()
            control.publish_bytes=publish
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending=pool.submit(engine.transfer_file,'push',str(source),'@bastion',str(remote),use_delta=False,timeout_sec=60,tx_id=value['tx_id'])
                assert ready.wait(30),'Assembly did not dispatch'
                deadline=time.monotonic()+30
                while True:
                    remaining=sum(p.exists() for p in staged)
                    if 0<remaining<len(staged):break
                    if pending.done() or time.monotonic()>deadline:raise AssertionError('No actual partial RDPDR consumption observed')
                    time.sleep(.01)
                report.update(status='ready_for_disconnect',staged_blocks=len(staged),remaining_blocks=remaining)
                status.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
                try:pending.result(timeout=65)
                except OperationError as error:assert error.indeterminate
                else:raise AssertionError('Transfer completed instead of being interrupted')
            assert engine.transaction_status(value['tx_id'])['state']=='indeterminate'
            report.update(status='passed',result='interrupted-after-actual-remote-block-consumption',operation_state='indeterminate')
        else:
            before=json.loads((folder/'before.json').read_text());assert before['status']=='passed'
            assert report['worker_instance']!=before['worker_instance'],'Reconnect must restart the disposable worker'
            try:engine.transfer_file('push',str(source),'@bastion',str(remote),use_delta=False,timeout_sec=60,tx_id=value['tx_id'])
            except OperationError as error:assert error.indeterminate
            else:raise AssertionError('Interrupted transfer was replayed')
            result=engine.exec_node('@bastion','(Get-FileHash -LiteralPath '+ps_quote(str(remote))+" -Algorithm SHA256).Hash.ToLowerInvariant()",timeout_sec=30)
            previous=hashlib.sha256(b'original-target').hexdigest();complete=hashlib.sha256(source.read_bytes()).hexdigest()
            # A disconnect can lose the reply after a complete commit. Either
            # complete generation is valid; a partial destination is forbidden.
            assert result.exit_code==0 and result.stdout in (previous,complete)
            if value.get('expect_previous_target'):assert result.stdout==previous
            report.update(status='passed',result='reconnect-keeps-complete-target-and-blocks-replay',source_sha256=complete,
                          destination_generation='previous' if result.stdout==previous else 'complete-new')
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:status.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--configuration',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--phase',choices=['before','after'],required=True);print(json.dumps(run(p.parse_args()),indent=2))
