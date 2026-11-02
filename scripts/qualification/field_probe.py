#!/usr/bin/env python3
"""Operator-run measurements with no topology, command output or credentials in receipts."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.operations.retention import private_directory


def run(args):
    if not re.fullmatch('[a-f0-9]{40}',args.source_sha):raise ValueError('Supply the exact tested source commit')
    if not 1<=args.samples<=30 or not 1<=args.parallel<=16 or not 30<=args.timeout<=900:raise ValueError('Invalid observer limits')
    executable=args.egw.resolve(strict=True);config=EnclaveConfig.load(args.config)
    if args.node not in config.targets:raise ValueError('Select a configured TargetNode')
    if args.output.exists():raise FileExistsError('Preserve earlier measurement output')
    private_directory(args.output);output=args.output.resolve()
    windows=config.targets[args.node].os in ('windows','win','powershell')
    marker='EGW_FIELD_PROBE';target_script="Write-Output '"+marker+"'" if windows else 'printf %s '+shlex.quote(marker)
    command=[str(executable),'-c',str(args.config.resolve()),'--state-dir',str(output/'state')]
    report={'status':'running','source_binding':'operator-supplied-commit; launcher hash does not attest installed package',
            'source_sha':args.source_sha,'launcher_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
            'scope':'operator-invoked functional timing; no automatic bridge replacement or RDP disconnect',
            'samples':[],'limits':{'samples':args.samples,'parallel':args.parallel,'observer_timeout_sec':args.timeout}}
    def invoke(label,arguments,expected=None):
        started=time.monotonic();row={'case':label}
        try:
            result=subprocess.run(command+arguments,capture_output=True,timeout=args.timeout+30)
            row.update(exit_code=result.returncode,elapsed_ms=round((time.monotonic()-started)*1000,1),stdout_bytes=len(result.stdout))
            if expected is not None:row['expected_output']=result.stdout.decode('utf-8','replace').strip()==expected
            # Extract only structural metadata, never stdout/stderr text.
            for line in result.stderr.decode('utf-8','replace').splitlines():
                try:data=json.loads(line)
                except ValueError:continue
                if isinstance(data,dict):
                    timings=data.get('timings_ms')
                    if isinstance(timings,dict):row['timings_ms']={key:value for key,value in timings.items() if re.fullmatch('[a-z_.]+',key) and type(value) in (int,float)}
                    code=data.get('diagnostic_code')
                    if not code and isinstance(data.get('error'),dict):code=data['error'].get('code')
                    if isinstance(code,str) and re.fullmatch('[a-z_]+',code):row['diagnostic_code']=code
            return row,result.stdout
        except subprocess.TimeoutExpired:
            row.update(exit_code=None,elapsed_ms=round((time.monotonic()-started)*1000,1),observer_timeout=True)
            return row,b''
    def record(label,arguments,expected=None):
        row,out=invoke(label,arguments,expected);report['samples'].append(row)
        return row,out
    try:
        record('status',['status'])
        for _ in range(args.samples):
            record('appliance_exec',['exec','@appliance',"Write-Output '"+marker+"'",'--timeout',str(args.timeout)],marker)
            record('bastion_exec',['exec','@bastion',"Write-Output '"+marker+"'",'--timeout',str(args.timeout)],marker)
            record('target_exec',['exec',args.node,target_script,'--timeout',str(args.timeout)],marker)
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            rows=list(pool.map(lambda _:invoke('parallel_target_exec',['exec',args.node,target_script,'--timeout',str(args.timeout)],marker),range(args.parallel)))
        report['samples'].extend(row for row,_ in rows)
        if args.copy_root:
            name='egw-field-'+uuid.uuid4().hex+'.bin'
            remote=args.copy_root.rstrip('\\/')+('\\' if windows else '/')+name
            source=output/name;source.write_bytes(bytes(range(256))*256);destination=output/'received.bin'
            try:
                push,_=record('copy_push',['cp',str(source),args.node+':'+remote])
                if push['exit_code']==0:
                    pull,_=record('copy_pull',['cp',args.node+':'+remote,str(destination)])
                    report['copy_sha256_matches']=pull['exit_code']==0 and destination.is_file() and hashlib.sha256(source.read_bytes()).digest()==hashlib.sha256(destination.read_bytes()).digest()
            finally:
                cleanup='[IO.File]::Delete('+ps_quote(remote)+')' if windows else 'rm -f -- '+shlex.quote(remote)
                record('copy_cleanup',['exec',args.node,cleanup,'--timeout',str(args.timeout)])
        report['status']='passed' if all(row['exit_code']==0 and row.get('expected_output',True) for row in report['samples']) and report.get('copy_sha256_matches',True) else 'failed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        path=output/'result.json';descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'w',encoding='utf-8') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--egw',type=Path,required=True);parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--source-sha',required=True);parser.add_argument('--node',required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--samples',type=int,default=5)
    parser.add_argument('--parallel',type=int,default=4);parser.add_argument('--timeout',type=float,default=300)
    parser.add_argument('--copy-root',default='',help='Explicit approved target scratch directory; enables write/copy/delete checks.')
    result=run(parser.parse_args());print(json.dumps({'status':result['status'],'measurements':len(result['samples'])}));raise SystemExit(0 if result['status']=='passed' else 1)
