#!/usr/bin/env python3
"""Run QEMU/TCG and both control protocols from an explicitly disposable Windows Host."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.hypervisor.driver import ApplianceHypervisor


def run(configuration,output):
    if os.name!='nt':raise RuntimeError('Use a separate disposable Windows Host')
    raw=json.loads(configuration.read_text(encoding='utf-8-sig'))
    if raw.get('scope')!='disposable-windows-host':raise ValueError('Explicit disposable Host scope required')
    cfg=EnclaveConfig.from_dict(raw['config']);spec=cfg.appliance
    if spec.hypervisor!='tcg' or not spec.network_restrict:raise ValueError('Use restricted software emulation')
    h=ApplianceHypervisor(spec);report={'status':'running','scope':'windows-host-tcg-qmp-qga','whpx':'not_qualified'}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report)+'\n')
    try:
        pid=h.start();report['qmp_name']=h.qmp.execute('query-name')['return']['name']
        assert report['qmp_name']==spec.name and h.qmp.query_status()['return']['running']
        agent=QgaClient(spec.qga_socket);deadline=time.monotonic()+240
        while time.monotonic()<deadline:
            try:
                with agent._connect_synced(5) as(sock,reader):agent._request(sock,reader,'guest-ping')
                break
            except (OSError,ValueError,RuntimeError):time.sleep(1)
        else:raise TimeoutError('Nested disposable guest QGA did not become ready')
        reply=agent.exec_guest('/usr/bin/uname',['-sm'],timeout_sec=30)
        assert reply.exit_code==0 and reply.stdout.startswith('Linux ')
        data=secrets.token_bytes(1048577);guest='/home/lab/egw-windows-host-'+secrets.token_hex(12)
        agent.write_bytes(data,guest);assert agent.read_bytes(guest)==data
        clean=agent.exec_guest('/usr/bin/rm',['--',guest],timeout_sec=10);assert clean.exit_code==0
        assert agent.sync_guest_clock()
        report.update(status='passed',guest_uname=reply.stdout,roundtrip_bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                      qmp='actual-qemu',qga='actual-nested-linux-agent',host_private_state_dacl='enforced')
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        try:
            if h.is_running()[0]:h.stop(timeout_sec=120)
            report['guest_final_state']='stopped'
        finally:output.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--configuration',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();print(json.dumps(run(a.configuration,a.output),indent=2))
