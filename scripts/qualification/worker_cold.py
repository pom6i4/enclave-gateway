#!/usr/bin/env python3
"""First challenge per new signed worker, without an attestation warm-up."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from worker_loopback import Worker
from enclave_gateway.security.attestation import verify
from enclave_gateway.security.isolation import process_identity


def run(args):
    if os.name!='nt':raise RuntimeError('Use a disposable native Windows account')
    report={'status':'running','scope':'first-challenge-per-new-worker','challenge_timeout_sec':10,'runs':[]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    try:
        for index in range(args.count):
            with tempfile.TemporaryDirectory(prefix='egw-first-challenge-') as folder:
                worker=Worker(args.powershell,Path(folder),args.runtime,False,args.trusted_signer,startup_timeout_sec=120,worker_path=args.worker)
                try:
                    launch=time.monotonic();worker.start();startup=time.monotonic()-launch;nonce=secrets.token_hex(32);started=time.monotonic()
                    evidence=worker.transport.attest(nonce,timeout_sec=10)
                    elapsed=time.monotonic()-started
                    checked=verify(evidence,nonce,expected_sha256=hashlib.sha256(args.worker.read_bytes()).hexdigest(),trusted_signers=[args.trusted_signer],require_signed=True,
                                   expected_account=process_identity().removeprefix('sid:'),require_process_isolation=True,
                                   expected_runtime_sha256=hashlib.sha256(args.runtime.read_bytes()).hexdigest())
                    if checked.get('trust_probe')!='native-winverifytrust':raise RuntimeError('Wrong trust probe')
                    if checked.get('trust_policy')!='cache-only-chain-revocation-excluding-root':raise RuntimeError('Wrong nonce trust policy')
                    if checked.get('trust_probe_sequence')!=1:raise RuntimeError('A previous trust challenge warmed this host')
                    report['runs'].append({'attempts':1,'elapsed_sec':round(elapsed,3),'instance_id':checked['instance_id'],'trust_probe_ms':checked['trust_probe_ms'],
                                           'startup_sec':round(startup,3),'launch_through_challenge_sec':round(startup+elapsed,3),
                                           'trust_host_pid':checked['trust_host_pid'],'trust_probe_sequence':checked['trust_probe_sequence'],'status':'passed'})
                finally:
                    worker.close()
                    if len(report['runs'])<=index:
                        shutil.copytree(Path(folder),args.output.with_name(args.output.stem+'-failed-'+str(index)),dirs_exist_ok=False)
        report['status']='passed'
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:args.output.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--powershell',default=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
    p.add_argument('--worker',type=Path,required=True);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--trusted-signer',required=True)
    p.add_argument('--count',type=int,choices=range(1,11),default=3);p.add_argument('--output',type=Path,required=True)
    print(json.dumps(run(p.parse_args()),indent=2))
