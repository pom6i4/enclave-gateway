#!/usr/bin/env python3
"""Seeded framing/dispatch models and real process-crash publication checks."""
from __future__ import annotations
import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.control.wire import SocketLineReader
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.operations.journal import TransactionJournal
from enclave_gateway.operations.context import OperationError,identity,mark_dispatched
from enclave_gateway.operations.runner import tracked
from enclave_gateway.security.secrets import SecretScrubber


class Subject:
    def __init__(self,root):
        self.root=root;self.journal=TransactionJournal(root/'journal.sqlite');self.vault=SimpleNamespace(scrubber=SecretScrubber())
        self._operations_lock=threading.RLock();self._operations={};self._pending_cancels=set()
    @tracked('fixture-effect')
    def effect(self,node='app01',timeout_sec=5):
        mark_dispatched()
        with (self.root/'effects').open('ab') as f:f.write(b'once\n');f.flush();os.fsync(f.fileno())
        return {'observed':'once'}


def frame_models(seed,count):
    rng=random.Random(seed)
    for case in range(count):
        values=[{'case':case,'value':''.join(rng.choices('abcтест😀\n\\"',k=rng.randrange(1,80)))} for _ in range(rng.randrange(1,6))]
        data=b''.join(json.dumps(v,ensure_ascii=False).encode()+b'\n' for v in values);chunks=[]
        while data:
            n=rng.randrange(1,19);chunks.append(data[:n]);data=data[n:]
        class Sock:
            def settimeout(self,*_):pass
            def recv(self,*_):return chunks.pop(0) if chunks else b''
        reader=SocketLineReader(Sock(),time.monotonic()+3,max_bytes=8192)
        assert [json.loads(reader.readline()) for _ in values]==values,(seed,case)
        try:reader.readline()
        except ConnectionError:pass
        else:raise AssertionError(('EOF accepted',seed,case))
    for data,error,limit in [(b'\xff\n',UnicodeDecodeError,32),(b'x'*33,ValueError,32)]:
        class Sock:
            def settimeout(self,*_):pass
            def recv(self,*_):return data
        try:SocketLineReader(Sock(),time.monotonic()+1,max_bytes=limit).readline()
        except error:pass
        else:raise AssertionError('Invalid frame accepted')


def dispatch_models(seed,count):
    rng=random.Random(seed)
    for case in range(count):
        pid=rng.randrange(1,100000);lost_ack=rng.randrange(5)==0;denied=rng.randrange(5)==0
        statuses=[rng.choice((TimeoutError,ConnectionResetError))('fixture') for _ in range(rng.randrange(7))]
        responses=[TimeoutError('dispatch acknowledgement lost')] if lost_ack else [{'pid':pid},*statuses,PermissionError('denied') if denied else {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'once').decode()}]
        client=QgaClient('unused');calls=[]
        @contextlib.contextmanager
        def connect(*_):yield None,None
        def request(s,r,command,arguments):
            calls.append((command,arguments));value=responses.pop(0)
            if isinstance(value,Exception):raise value
            return value
        client._connect_synced=connect;client._request=request
        try:
            with patch('enclave_gateway.control.qga_client.time.sleep',lambda _:None):result=client.exec_guest('fixture',timeout_sec=3)
            assert not lost_ack and not denied and result.stdout=='once',(seed,case)
        except (TimeoutError,PermissionError):assert lost_ack or denied,(seed,case)
        assert sum(c[0]=='guest-exec' for c in calls)==1,(seed,case)
        assert all(arguments=={'pid':pid} for command,arguments in calls if command=='guest-exec-status'),(seed,case)


def journal_models(root,seed,count):
    rng=random.Random(seed);root.mkdir();expected={};subject=Subject(root)
    for case in range(count):
        tx='generated_'+str(rng.randrange(20));owner=rng.choice(('alice','bob'));node=rng.choice(('app01','app02'))
        with identity(owner):
            if tx not in expected:
                subject.effect(node,tx_id=tx);expected[tx]=(owner,node)
            elif expected[tx]==(owner,node):assert subject.effect(node,tx_id=tx)['observed']=='once'
            else:
                try:subject.effect(node,tx_id=tx)
                except OperationError as e:assert e.code=='transaction_conflict'
                else:raise AssertionError(('Conflict accepted',seed,case))
        subject=Subject(root)
        assert len((root/'effects').read_bytes().splitlines())==len(expected),(seed,case)


def child_journal(root,barrier):
    subject=Subject(root);reserve=subject.journal.reserve;update=subject.journal.update
    def reservation(*a,**kw):
        value=reserve(*a,**kw)
        if barrier=='reserved':os._exit(73)
        return value
    def publication(tx,owner,state,**kw):
        if state=='completed' and barrier=='before-result':os._exit(73)
        value=update(tx,owner,state,**kw)
        if (state,barrier) in (('running','running'),('completed','after-result')):os._exit(73)
        return value
    subject.journal.reserve=reservation;subject.journal.update=publication;subject.effect(tx_id='crash')


def crash_checks(root):
    records=[];env={**os.environ,'PYTHONPATH':str(ROOT/'src')}
    for barrier in ('reserved','running','before-result','after-result'):
        folder=root/('journal-'+barrier);folder.mkdir()
        p=subprocess.run([sys.executable,str(Path(__file__)), '--child-journal',str(folder),barrier],env=env,capture_output=True,timeout=20)
        assert p.returncode==73,(barrier,p.stderr)
        subject=Subject(folder)
        try:value=subject.effect(tx_id='crash');assert barrier=='after-result' and value['observed']=='once'
        except OperationError as e:assert barrier!='after-result' and e.code=='transaction_in_progress'
        count=len((folder/'effects').read_bytes().splitlines()) if (folder/'effects').exists() else 0
        assert count==(1 if barrier in ('before-result','after-result') else 0)
        records.append('journal-'+barrier)
    if os.name=='nt' or not shutil.which('qemu-img'):raise RuntimeError('VM-state crash checks require POSIX and qemu-img')
    from enclave_gateway.config import ApplianceSpec
    from enclave_gateway.hypervisor.state import StateStore,inventory
    for barrier in range(1,9):
        folder=root/('vm-'+str(barrier));folder.mkdir();disk=folder/'disk.qcow2'
        subprocess.run(['qemu-img','create','-f','qcow2',str(disk),'8M'],check=True,capture_output=True)
        (folder/'vars.fd').write_bytes(b'golden-vars');(folder/'code.fd').write_bytes(b'code');(folder/'tpm').mkdir();(folder/'tpm/state').write_bytes(b'golden-tpm')
        store=StateStore(ApplianceSpec(arch='arm64',disk_path=str(disk),efi_vars_path=str(folder/'vars.fd'),tpm_state_dir=str(folder/'tpm')),folder/'code.fd')
        with store.locked():store.create('golden')
        golden={k:inventory(p) for k,p in store.targets.items()}
        (folder/'vars.fd').write_bytes(b'previous-vars');(folder/'tpm/state').write_bytes(b'previous-tpm')
        before={k:inventory(p) for k,p in store.targets.items()}
        script='''import os,sys
from pathlib import Path
from enclave_gateway.config import ApplianceSpec
from enclave_gateway.hypervisor.state import StateStore
r=Path(sys.argv[1]);barrier=int(sys.argv[2]);s=StateStore(ApplianceSpec(arch='arm64',disk_path=str(r/'disk.qcow2'),efi_vars_path=str(r/'vars.fd'),tpm_state_dir=str(r/'tpm')),r/'code.fd')
replace=os.replace;unlink=Path.unlink;count=0
def rename(a,b):
 global count
 replace(a,b);count+=1
 if count==barrier:os._exit(73)
def remove(p,*a,**kw):
 unlink(p,*a,**kw)
 if p==s.pending and barrier==8:os._exit(73)
os.replace=rename;Path.unlink=remove
with s.locked():s.restore('golden')
'''
        p=subprocess.run([sys.executable,'-c',script,str(folder),str(barrier)],env=env,capture_output=True,timeout=30)
        assert p.returncode==73,(barrier,p.stderr)
        with store.locked():recovered=store.recover()
        assert recovered==(barrier<8)
        assert {k:inventory(p) for k,p in store.targets.items()}==(before if barrier<8 else golden),barrier
        records.append('vm-publication-'+str(barrier))
    return records


def run(output,seeds=(17,9173,65537),cases=200,crashes=False):
    if output.exists():raise FileExistsError('Preserve the previous generated run')
    output.mkdir(parents=True,mode=0o700);report={'status':'running','seeds':list(seeds),'cases_per_model_per_seed':cases,'crashes':[]}
    try:
        for seed in seeds:
            report['active_seed']=seed;frame_models(seed,cases);dispatch_models(seed,cases);journal_models(output/('journal-'+str(seed)),seed,cases)
        if crashes:report['crashes']=crash_checks(output)
        report['status']='passed'
    except BaseException as e:report.update(status='failed',error_type=type(e).__name__);raise
    finally:(output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child-journal':child_journal(Path(sys.argv[2]),sys.argv[3]);raise SystemExit(1)
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--seed',type=int,action='append');p.add_argument('--cases',type=int,default=200);p.add_argument('--crashes',action='store_true');a=p.parse_args()
    if not 1<=a.cases<=10000:p.error('cases must be 1..10000')
    print(json.dumps(run(a.output,a.seed or (17,9173,65537),a.cases,a.crashes),indent=2))
