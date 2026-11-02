#!/usr/bin/env python3
"""Execute a complete extended profile; never import old acceptance receipts."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'src'),str(Path(__file__).resolve().parent)]
from full_acceptance import cohort_sources
from case_receipt import stop_owned
from evidence import report_inventory
from enclave_gateway.hypervisor.state import atomic_json

REQUIRED={'windows-arm64-source','windows-x64-source','windows-accounts','posix-accounts',
          'qga-faults','worker-faults','storage-faults','rdp-transfer-disconnect','long-soak','generated-security'}


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_receipt(path,role,sources,expected_tests=None):
    value=json.loads(path.read_text(encoding='utf-8-sig'))
    if value.get('status')!='passed' or value.get('role')!=role or value.get('sources')!=sources:raise ValueError('Invalid or stale case receipt')
    if value.get('scope')!='executed-lab-case' or value.get('exit_code')!=0 or not value.get('reports'):raise ValueError('Case was not executed successfully')
    cases=[]
    for name,expected in value['reports'].items():
        if not re.fullmatch(r'case-[0-9]+\.json',name):raise ValueError('Invalid nested case path')
        p=path.parent/name
        if p.is_symlink() or digest(p)!=expected:raise ValueError('Nested case evidence changed')
        case=json.loads(p.read_text(encoding='utf-8-sig'))
        if case.get('status')!='passed':raise ValueError('Nested case failed')
        cases.append(case)
    if role.startswith('windows-') and role.endswith('-source'):
        expected='arm64' if 'arm64' in role else 'x86_64'
        case=cases[0]
        platform=case['platform'];arch=platform['machine'].lower();arch={'amd64':'x86_64','aarch64':'arm64'}.get(arch,arch)
        if case.get('sources')!=sources or case.get('scope')!='ordinary-source-suite' or platform['system'].lower()!='windows' or arch!=expected:raise ValueError('Wrong source-suite platform')
        if type(case.get('tests')) is not int or case['tests']<160 or (expected_tests is not None and case['tests']!=expected_tests) or not isinstance(case.get('skips'),list):raise ValueError('Incomplete ordinary source suite')
    if role=='long-soak':
        case=cases[0]
        if case.get('scope')!='disposable-loopback-long-soak' or case.get('duration_requested_sec',0)<7200 or case.get('elapsed_sec',0)<7200:raise ValueError('Two-hour soak required')
        if case.get('fast_streams')!=128 or case.get('slow_streams')!=32 or case.get('final_queues')!='empty':raise ValueError('Incomplete soak')
        for field,limit in [('working_set_bytes',256*1024*1024),('threads',64),('handles',64)]:
            if type(case.get(field+'_growth')) is not int or case[field+'_growth']>limit:raise ValueError('Soak resource bound missing or exceeded')
    if role=='rdp-transfer-disconnect':
        if len(cases)!=2 or cases[0].get('result')!='interrupted-after-actual-remote-block-consumption' or cases[1].get('result')!='reconnect-keeps-complete-target-and-blocks-replay':raise ValueError('Incomplete RDP interruption/reconnect')
        if not 0<cases[0].get('remaining_blocks',0)<cases[0].get('staged_blocks',0):raise ValueError('No actual partial RDP consumption')
    if role in ('qga-faults','storage-faults','posix-accounts','worker-faults'):
        minimum={'qga-faults':2,'storage-faults':4,'posix-accounts':6,'worker-faults':4}[role]
        if len(cases[0].get('checks',[]))<minimum:raise ValueError('Incomplete fault/isolation case')
    if role=='windows-accounts':
        if cases[0].get('cross_sid_backends')!=2 or any(cases[0].get(k)!='passed' for k in ('cross_account_acl_denial','private_environment_acl_denial','wrong_sid_launch_denial','scoped_windows_sync','explicit_environment_without_broker_leak','invalid_environment_rejected')):raise ValueError('Incomplete cross-SID qualification')
    if role=='generated-security':
        case=cases[0]
        if case.get('sources')!=sources or set(case.get('models',[]))!={'paths','destinations','rpc','proxy-fragments','http','mux-half-close'} or len(case.get('seeds',[]))<3 or case.get('cases_per_model_per_seed',0)<200:raise ValueError('Incomplete generated security models')
    return value


def run(manifest_path,output):
    manifest_path=manifest_path.resolve();output=output.resolve()
    if output.exists():raise FileExistsError('Preserve previous extended runs')
    manifest=json.loads(manifest_path.read_text())
    if manifest.get('revision')!=1 or manifest.get('scope')!='isolated-extended-acceptance':raise ValueError('Explicit isolated extended scope required')
    steps=manifest.get('steps',[]);roles=[s['role'] for s in steps]
    if set(roles)!=REQUIRED or len(roles)!=len(REQUIRED):raise ValueError('All distinct extended roles are required')
    expected_tests=manifest.get('expected_source_tests')
    if type(expected_tests) is not int or expected_tests<160:raise ValueError('Explicit current source test count required')
    cleanup=manifest.get('cleanup',[])
    if not cleanup:raise ValueError('Owned-resource cleanup commands required')
    inputs={Path(p).resolve():v for p,v in manifest.get('inputs_sha256',{}).items()}
    if not inputs or any(p.is_symlink() or digest(p)!=v for p,v in inputs.items()):raise ValueError('Unapproved lab inputs')
    for step in steps+cleanup:
        if not re.fullmatch('[a-z][a-z0-9-]{0,63}',step['role']) or not isinstance(step.get('argv'),list) or not step['argv']:raise ValueError('Invalid step')
        if not 1<=step.get('timeout_sec',900)<=14400:raise ValueError('Invalid step deadline')
    output.mkdir(parents=True,mode=0o700);sources=cohort_sources()
    report={'status':'running','scope':'isolated-extended-acceptance','sources':sources,'manifest_sha256':digest(manifest_path),'steps':[],'cleanup':[],
            'client_environment':'not_used','production_keys':'not_used','actions':'not_used'}
    def persist():atomic_json(output/'result.json',report)
    def execute(step,clean=False):
        role=step['role'];folder=output/role;folder.mkdir();process=None
        argv=[str(a).replace('{run_dir}',str(output)).replace('{repo}',str(ROOT)).replace('{python}',sys.executable) for a in step['argv']]
        row={'role':role,'status':'running'};report['cleanup' if clean else 'steps'].append(row);persist();started=time.monotonic()
        try:
            with (folder/'stdout.log').open('xb') as stdout,(folder/'stderr.log').open('xb') as stderr:
                process=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=os.name!='nt')
                row['exit_code']=process.wait(timeout=step.get('timeout_sec',900))
            if process.returncode:raise RuntimeError('Extended step failed: '+role)
            receipt=folder/'receipt/result.json'
            if clean:
                value=json.loads(receipt.read_text())
                if value.get('status')!='passed' or value.get('cleanup')!='passed':raise ValueError('Resource cleanup not confirmed')
            else:verify_receipt(receipt,role,sources,expected_tests)
            row['status']='passed'
        except BaseException as error:row.update(status='failed',error_type=type(error).__name__);raise
        finally:
            try:
                if process:stop_owned(process)
            finally:row['elapsed_sec']=round(time.monotonic()-started,3);persist()
    persist()
    try:
        for step in steps:
            if cohort_sources()!=sources or any(digest(p)!=v for p,v in inputs.items()):raise ValueError('Source or approved input drift')
            execute(step)
        report['status']='passed'
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        failures=[]
        for step in cleanup:
            try:execute(step,True)
            except BaseException as error:failures.append(type(error).__name__)
        if failures:report.update(status='failed',cleanup_errors=failures)
        if cohort_sources()!=sources or any(digest(p)!=v for p,v in inputs.items()):report.update(status='failed',source_or_input_drift=True)
        files=report_inventory(output);atomic_json(output/'inventory.json',{'files':files});report['inventory_sha256']=digest(output/'inventory.json');persist()
    if report['status']!='passed':raise RuntimeError('Extended acceptance incomplete')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(run(a.manifest,a.output),indent=2))
