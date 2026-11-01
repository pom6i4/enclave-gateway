#!/usr/bin/env python3
"""Run an explicit private local acceptance plan and stop its owned lab VMs."""
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

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.hypervisor.driver import ApplianceHypervisor
from enclave_gateway.hypervisor.state import atomic_json,private_dir


def run(plan_path,output):
    plan=json.loads(plan_path.read_text(encoding='utf-8'))
    if plan.get('revision')!=1 or plan.get('scope')!='isolated-local-qualification':raise ValueError('Explicit local laboratory plan required')
    if not isinstance(plan.get('steps'),list) or not plan['steps']:raise ValueError('At least one acceptance step is required')
    if output.exists():raise FileExistsError('Use a new run directory; previous evidence is immutable')
    output=output.resolve();private_dir(output)
    report={'revision':1,'status':'running','scope':plan['scope'],'steps':[],'cleanup':[],
            'plan_sha256':hashlib.sha256(plan_path.read_bytes()).hexdigest()}
    report['sources']={str(item.relative_to(ROOT)):hashlib.sha256(item.read_bytes()).hexdigest()
                       for folder in ('src','scripts','tests','native') for item in (ROOT/folder).rglob('*')
                       if item.is_file() and item.suffix in ('.py','.ps1','.cs','.csproj')
                       and not any(part in ('bin','obj','__pycache__') for part in item.parts)}
    def persist():atomic_json(output/'result.json',report)
    def path(value):
        result=Path(value.replace('{run_dir}',str(output))).resolve()
        if not result.is_relative_to(output):raise ValueError('Managed resource must belong to this run directory')
        return result
    resources=[path(value) for value in plan.get('managed_vm_configs',[])]
    if len(set(resources))!=len(resources):raise ValueError('Duplicate managed VM')
    environment={key:value for key,value in os.environ.items() if not key.startswith(('ENCLAVE_','EGW_','SSH_'))}
    environment['PYTHONPATH']=str(ROOT/'src');environment['PYTHONNOUSERSITE']='1'
    persist();failed=False
    try:
        for index,step in enumerate(plan['steps']):
            args=step.get('argv');timeout=step.get('timeout_sec',300)
            if not isinstance(args,list) or not args or not all(isinstance(value,str) and '\0' not in value for value in args):raise ValueError('Invalid step arguments')
            if type(timeout) not in (int,float) or not 1<=timeout<=14400:raise ValueError('Invalid step deadline')
            args=[value.replace('{python}',sys.executable).replace('{repo}',str(ROOT)).replace('{run_dir}',str(output)) for value in args]
            log=output/f'step-{index:03}.log';started=time.monotonic();process=None
            row={'name':step.get('name',str(index)),'status':'running','log':log.name};report['steps'].append(row);persist()
            try:
                with log.open('wb') as stream:
                    process=subprocess.Popen(args,cwd=ROOT,env=environment,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=os.name!='nt')
                    process.wait(timeout=timeout)
                row.update(status='passed' if process.returncode==0 else 'failed',exit_code=process.returncode)
            except BaseException as error:
                row.update(status='timed_out' if isinstance(error,subprocess.TimeoutExpired) else 'interrupted',error_type=type(error).__name__)
                raise
            finally:
                if process and process.poll() is None:
                    if os.name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=15,check=True)
                    else:os.killpg(process.pid,signal.SIGKILL)
                    process.wait(timeout=15)
                row.update(elapsed_sec=round(time.monotonic()-started,3),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest() if log.exists() else '')
                persist()
            if row['status']!='passed':raise RuntimeError('Acceptance step failed')
    except BaseException as error:
        failed=True;report['error_type']=type(error).__name__
        if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
    finally:
        for configuration in reversed(resources):
            row={'configuration':str(configuration.relative_to(output)),'status':'not_created'}
            try:
                if configuration.exists():
                    cfg=EnclaveConfig.load(configuration);spec=cfg.appliance
                    if not spec.name.startswith('egw-lab-') or not spec.network_restrict or cfg.provider.type!='custom' or cfg.provider.dst_key_path or cfg.provider.installer_path:
                        raise ValueError('Resource is not an owned isolated fixture')
                    for owned in (spec.resolved_disk_path,spec.resolved_efi_vars_path):
                        if not owned.is_relative_to(output):raise ValueError('Resource storage is outside this run')
                    if spec.tpm_state_dir and not Path(spec.tpm_state_dir).expanduser().resolve().is_relative_to(output):
                        raise ValueError('Resource TPM state is outside this run')
                    h=ApplianceHypervisor(spec)
                    if h.is_running()[0]:
                        blocks=h.qmp.execute('query-block').get('return',[])
                        images=[row.get('inserted',{}).get('image',{}).get('filename','') for row in blocks]
                        if not any(Path(image).resolve()==spec.resolved_disk_path for image in images if image):raise ValueError('Running VM disk does not belong to this run')
                        h.stop(timeout_sec=180)
                    if spec.pid_file.exists():raise RuntimeError('Ambiguous VM ownership; state preserved')
                    h._stop_tpm();row['status']='stopped'
            except BaseException as error:failed=True;row.update(status='failed',error_type=type(error).__name__)
            report['cleanup'].append(row);persist()
        evidence={str(item.relative_to(output)):hashlib.sha256(item.read_bytes()).hexdigest() for item in output.rglob('*')
                  if item.is_file() and not item.is_symlink() and item.suffix in ('.json','.log') and item.name not in ('credentials.json','result.json','inventory.json')
                  and 'seed' not in item.parts and 'driver-media' not in item.parts and 'controller' not in item.parts}
        atomic_json(output/'inventory.json',{'revision':1,'files':evidence})
        report.update(status='failed' if failed else 'passed',inventory_sha256=hashlib.sha256((output/'inventory.json').read_bytes()).hexdigest());persist()
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--plan',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    args=p.parse_args();result=run(args.plan,args.output);print(json.dumps(result,indent=2));raise SystemExit(0 if result['status']=='passed' else 1)
