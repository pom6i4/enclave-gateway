#!/usr/bin/env python3
"""Bounded-duration mixed load against a new, disposable loopback worker."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(Path(__file__).resolve().parent),str(ROOT/'src')]
from worker_loopback import EchoServer, Worker, read_shared
from lab_artifacts import worker_artifact
from enclave_gateway.security.attestation import verify


def write_report(path, report):
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    temporary.replace(path)


def run(args):
    report={'status':'running','scope':'disposable-loopback-long-soak','duration_requested_sec':args.seconds,
            'fast_streams':args.streams,'slow_streams':32,'samples':[],'iterations':0}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    write_report(args.output,report)
    with TemporaryDirectory(prefix='egw-long-soak-') as folder:
        artifact=worker_artifact(getattr(args,'worker',None))
        root=Path(folder);worker=Worker(args.powershell,root,args.runtime,False,args.trusted_signer,startup_timeout_sec=120,worker_path=artifact)
        fast,slow=EchoServer(),EchoServer(silent=True)
        try:
            worker.start();transport=worker.transport
            worker_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
            runtime_hash=hashlib.sha256(args.runtime.read_bytes()).hexdigest()
            def guard():
                nonce=secrets.token_hex(32)
                return verify(transport.attest(nonce),nonce,expected_sha256=worker_hash,
                              expected_runtime_sha256=runtime_hash,trusted_signers=[args.trusted_signer],
                              require_signed=True,require_process_isolation=True)
            transport.attestation_guard=guard;guard()
            connections=[transport.mux_open('127.0.0.1',fast.port) for _ in range(args.streams)]
            silent=[transport.mux_open('127.0.0.1',slow.port) for _ in range(32)]
            started=time.monotonic();next_sample=0;next_file=0;next_exec=0;batch=0;max_fast_ms=0
            def io(index):
                payload=secrets.token_bytes(1024)
                tick=time.monotonic()
                data,eof=transport.mux_io(connections[index],payload,read_wait_ms=100)
                assert data==payload and not eof,'Echo mismatch'
                return (time.monotonic()-tick)*1000
            with ThreadPoolExecutor(max_workers=10) as pool:
                while time.monotonic()-started<args.seconds:
                    tick=time.monotonic()
                    futures=[pool.submit(io,(batch*8+n)%len(connections)) for n in range(8)]
                    pending=pool.submit(transport.mux_io,silent[batch%len(silent)],b'silent',read_wait_ms=500)
                    max_fast_ms=max(max_fast_ms,*(future.result() for future in futures))
                    assert pending.result()[0]==b''
                    elapsed=time.monotonic()-started
                    if elapsed>=next_file:
                        data=secrets.token_bytes(131073);source=root/'input.bin';source.write_bytes(data)
                        target=str(root/'remote.bin');digest=transport.push_file(source,target)
                        assert transport.pull_file(target,root/'received.bin')==digest
                        assert (root/'received.bin').read_bytes()==data
                        next_file=elapsed+60
                    if elapsed>=next_exec:
                        response=transport.exec_bastion("Write-Output 'long-soak-alive'",timeout_sec=120)
                        assert response.exit_code==0 and response.stdout=='long-soak-alive'
                        next_exec=elapsed+30
                    report['iterations']+=9;batch+=1
                    if elapsed>=next_sample:
                        state=json.loads(read_shared(worker.spool/'worker_state.json'))
                        state['observed_elapsed_sec']=round(elapsed,3)
                        report['samples'].append(state)
                        report.update(elapsed_sec=round(elapsed,3),maximum_fast_io_ms=round(max_fast_ms))
                        warm=[s for s in report['samples'] if s['observed_elapsed_sec']>=120]
                        if len(warm)>1:
                            for field,limit in [('working_set_bytes',256*1024*1024),('threads',64),('handles',64)]:
                                growth=max(s[field] for s in warm)-warm[0][field]
                                report[field+'_growth']=growth
                                assert growth<=limit,(field,growth)
                        write_report(args.output,report)
                        print(json.dumps({k:report[k] for k in ('status','elapsed_sec','iterations','maximum_fast_io_ms')}),flush=True)
                        next_sample=elapsed+60
                    time.sleep(max(0,1-(time.monotonic()-tick)))
            for connection in connections+silent:transport.mux_close(connection)
            time.sleep(2.1)
            state=json.loads(read_shared(worker.spool/'worker_state.json'))
            assert not any(state[k] for k in ('active_mux_streams','active_tx_jobs','pending_mux'))
            if state.get('powershell_edition')=='Desktop':
                assert state['native_cleanup_cycles']>0,'Framework native-resource cleanup was not exercised'
            report.update(status='passed',elapsed_sec=round(time.monotonic()-started,3),worker_sha256=worker_hash,
                          runtime_sha256=runtime_hash,final_queues='empty',signing='trusted-lab-signer',
                          native_cleanup_cycles=state.get('native_cleanup_cycles',0))
        except BaseException as error:
            report.update(status='failed',error_type=type(error).__name__)
            raise
        finally:
            worker.close();fast.close();slow.close();write_report(args.output,report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--powershell',required=True);p.add_argument('--runtime',required=True,type=Path)
    p.add_argument('--trusted-signer',required=True);p.add_argument('--seconds',type=int,default=7200)
    p.add_argument('--worker',type=Path,help='Signed lab copy with the exact current source body')
    p.add_argument('--streams',type=int,default=128);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    if os.name!='nt':p.error('Use an isolated Windows guest')
    if not 180<=a.seconds<=7200 or not 8<=a.streams<=128:p.error('seconds must be 180..7200 and streams 8..128')
    run(a)
