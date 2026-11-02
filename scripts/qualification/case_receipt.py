#!/usr/bin/env python3
"""Execute one trusted lab command and bind its actual reports to source inputs."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'src'),str(Path(__file__).resolve().parent)]
from full_acceptance import cohort_sources
from enclave_gateway.hypervisor.state import atomic_json


def stop_owned(process):
    if process.poll() is not None:return
    if os.name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],check=True,capture_output=True,timeout=15)
    else:os.killpg(process.pid,signal.SIGKILL)
    process.wait(timeout=15)


def run(output,argv,reports,timeout=900,role='lab-case'):
    output=output.resolve()
    if output.exists():raise FileExistsError('Preserve previous case evidence')
    if not argv or not 1<=timeout<=14400:raise ValueError('Explicit command and bounded deadline required')
    reports=[Path(p).resolve() for p in reports]
    if not reports or len(set(reports))!=len(reports):raise ValueError('Distinct case reports required')
    if any(p.exists() for p in reports):raise FileExistsError('Do not reuse case reports')
    output.mkdir(parents=True,mode=0o700);sources=cohort_sources();process=None
    report={'status':'running','scope':'executed-lab-case','role':role,'sources':sources,'reports':{},'timeout_sec':timeout}
    started=time.monotonic();atomic_json(output/'result.json',report)
    try:
        with (output/'stdout.log').open('xb') as stdout,(output/'stderr.log').open('xb') as stderr:
            process=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=os.name!='nt')
            report['exit_code']=process.wait(timeout=timeout)
        if process.returncode:raise RuntimeError('Lab command failed')
        for index,p in enumerate(reports):
            value=json.loads(p.read_text(encoding='utf-8-sig'))
            if value.get('status')!='passed':raise ValueError('Case did not pass')
            if 'sources' in value and value['sources']!=sources:raise ValueError('Case source inputs differ')
            data=p.read_bytes();name='case-'+str(index)+'.json';(output/name).write_bytes(data)
            report['reports'][name]=hashlib.sha256(data).hexdigest()
        if cohort_sources()!=sources:raise RuntimeError('Source changed during case')
        report['status']='passed'
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        try:
            if process:stop_owned(process)
        finally:
            report['elapsed_sec']=round(time.monotonic()-started,3);atomic_json(output/'result.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--report',type=Path,action='append',required=True)
    p.add_argument('--role',required=True);p.add_argument('--timeout-sec',type=int,default=900);p.add_argument('command',nargs=argparse.REMAINDER);a=p.parse_args()
    command=a.command[1:] if a.command[:1]==['--'] else a.command
    print(json.dumps(run(a.output,command,a.report,a.timeout_sec,a.role),indent=2))
