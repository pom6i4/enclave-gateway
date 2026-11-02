#!/usr/bin/env python3
"""Require passing installed-package reports for the current exact inputs."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path,PurePosixPath

ROOT=Path(__file__).resolve().parents[2]


def inputs(root):
    files=[root/n for n in ('README.md','LICENSE','pyproject.toml')]+[p for p in (root/'src/enclave_gateway').rglob('*') if p.is_file() and p.suffix in ('.py','.ps1','.xml') and '__pycache__' not in p.parts]
    if any(p.is_symlink() for p in files):raise ValueError('Package source links rejected')
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def normalize(values):
    result={}
    for name,value in values.items():
        name=name.replace('\\','/');path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or ':' in name or name in result:raise ValueError('Ambiguous package input path')
        result[name]=value
    return result


def compare(reports,output,required=(),root=ROOT):
    if output.exists():raise FileExistsError('Preserve the old matrix receipt')
    expected=inputs(root);record={'status':'running','platforms':[],'source_sha256':expected}
    try:
        labels=set()
        for path in reports:
            data=json.loads(path.read_text(encoding='utf-8-sig'))
            if data.get('status')!='passed' or normalize(data.get('source_sha256',{}))!=expected:raise ValueError('Report is not acceptance of current package inputs')
            platform=data['platform'];arch=platform['machine'].lower();arch={'amd64':'x86_64','aarch64':'arm64'}.get(arch,arch)
            label=platform['system'].lower()+':'+arch
            if label in labels:raise ValueError('Duplicate platform is not additional acceptance')
            labels.add(label);record['platforms'].append({'label':label,'python':platform['python'],'report_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'artifacts':data['artifacts']})
        if not set(required)<=labels or not labels:raise ValueError('Required installed-package platforms missing')
        record['status']='passed'
    except BaseException as e:record.update(status='failed',error_type=type(e).__name__);raise
    finally:output.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    return record


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--report',type=Path,action='append',required=True);p.add_argument('--require-platform',action='append',default=[]);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(compare(a.report,a.output,a.require_platform),indent=2))
