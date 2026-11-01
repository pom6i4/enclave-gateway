#!/usr/bin/env python3
"""Inject control failures only into an explicitly identified disposable Linux VM."""
from __future__ import annotations
import argparse
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.control.qmp_client import QmpClient
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.security.secrets import SecretVault
from enclave_gateway.operations.context import mark_dispatched


class ShellFixture(QgaClient):
    def __init__(self,socket_path,*,lose_ack=False):
        super().__init__(socket_path);self.dispatches=0;self.ack=threading.Event();self.lose_ack=lose_ack
    def _request(self,sock,reader,command,arguments=None):
        if command=='guest-exec':
            self.dispatches+=1
            if self.lose_ack:
                # The guest has acknowledged the real dispatch, but the caller
                # loses that acknowledgement before learning the PID. This
                # precisely injects delivery failure at the API boundary.
                QgaClient._request(sock,reader,command,arguments)
                raise ConnectionResetError('Disposable fixture lost the acknowledged PID before delivery')
        value=QgaClient._request(sock,reader,command,arguments)
        if command=='guest-exec':self.ack.set()
        return value
    def exec_powershell(self,script,timeout_sec=120):
        # Fixture adapter only; it does not claim that Linux is a Windows Appliance.
        return self.exec_guest('/bin/sh',['-c','eval "$(cat)"'],input_data=script.encode(),timeout_sec=timeout_sec)


def run(args):
    options=json.loads(args.configuration.read_text())
    if options.get('scope')!='disposable-linux-lab':raise ValueError('Explicit disposable scope required')
    qmp=QmpClient(options['qmp_socket'])
    if qmp.execute('query-name').get('return',{}).get('name')!=options['qmp_name']:raise ValueError('VM ownership mismatch')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    local=args.output.parent/('qga-fault-state-'+secrets.token_hex(8));local.mkdir(mode=0o700)
    guest='/home/lab/egw-fault-'+secrets.token_hex(8)
    def ssh(script):
        result=subprocess.run(options['ssh_argv']+['sh','-s'],input=script.encode(),capture_output=True,timeout=30)
        if result.returncode:raise RuntimeError('Disposable guest observer failed')
        return result.stdout.decode().strip()
    ssh('mkdir -m 700 '+guest)
    report={'status':'running','scope':'disposable-linux-qga-faults','checks':[]}
    try:
        for mode in ('agent-restart','lost-dispatch-ack'):
            marker=guest+'/'+mode;channel=ShellFixture(options['qga_socket'],lose_ack=mode=='lost-dispatch-ack')
            recorder=FlightRecorder(local/(mode+'.jsonl'))
            engine=EnclaveEngine(EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'}}),
                                 control_override=channel,vault=SecretVault(env_file=local/'absent.env'),recorder=recorder)
            script='printf x >> '+marker+'; sleep 5; printf done';tx='fault_'+mode.replace('-','_')
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(engine.exec_node,'@appliance',script,tx_id=tx,timeout_sec=20)
                if mode=='agent-restart':
                    assert channel.ack.wait(10),'Guest dispatch was not acknowledged'
                    until=time.monotonic()+10
                    while ssh('test -s '+marker+' && printf written || true')!='written':
                        if time.monotonic()>until:raise TimeoutError('Side-effect marker not observed')
                        time.sleep(.1)
                    ssh('sudo -n systemctl restart qemu-guest-agent')
                failed=False
                try:future.result(timeout=30)
                except Exception:failed=True
                assert failed,'Fault did not interrupt observation'
            assert engine.transaction_status(tx)['state']=='indeterminate'
            try:engine.exec_node('@appliance',script,tx_id=tx,timeout_sec=20)
            except Exception:pass
            else:raise AssertionError('Indeterminate operation was replayed')
            assert channel.dispatches==1,'Repeated guest-exec after uncertainty'
            until=time.monotonic()+10
            while ssh('test -s '+marker+' && cat '+marker+' || true')!='x':
                if time.monotonic()>until:raise TimeoutError('Lost acknowledgement effect not observed')
                time.sleep(.1)
            report['checks'].append(mode+':indeterminate-without-replay')
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__);raise
    finally:args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--configuration',type=Path,required=True);p.add_argument('--output',type=Path,required=True);run(p.parse_args())
