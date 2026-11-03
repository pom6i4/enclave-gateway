#!/usr/bin/env python3
"""Read every stored Git blob/commit; never print matched secret material."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[2]
_spec=importlib.util.spec_from_file_location('repository_hygiene',ROOT/'scripts/verify_hygiene.py')
policy=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(policy)
MAX_TEXT=8*1024*1024
PATTERNS={
    'github-token':re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b'),
    'cloud-access-id':re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'private-key-material':re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]{32,20000}?-----END (?:[A-Z]+ )?PRIVATE KEY-----'),
    'credential-uri':re.compile(r'\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@'),
}
FORBIDDEN=policy.FORBIDDEN_EXTENSION_SUFFIXES|{'.exe','.dll','.iso','.img','.vhdx','.vmdk'}


def git(repo,*args):
    return subprocess.check_output(['git','-C',str(repo),*args])


def inventory(repo):
    refs=git(repo,'for-each-ref','--format=%(refname) %(objectname)').decode().splitlines()
    head=git(repo,'rev-parse','HEAD').decode().strip()
    objects=sorted(git(repo,'cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)').decode().splitlines())
    value={'refs':refs,'head':head,'objects':objects}
    return value,hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def _finding(rule,oid,line,paths,matched=''):
    fingerprint=hashlib.sha256(matched.encode('utf-8','surrogateescape')).hexdigest()
    identity=json.dumps([rule,oid,line,paths,fingerprint],sort_keys=True).encode()
    return {'id':hashlib.sha256(identity).hexdigest(),'rule':rule,'object':oid,
            'line':line,'paths':paths,'match_sha256':fingerprint}


def scan(repo):
    repo=Path(repo).resolve();before,binding=inventory(repo);entries=[row.split() for row in before['objects']]
    paths={}
    for oid,kind,_ in entries:
        if kind!='commit':continue
        for row in git(repo,'ls-tree','-r','-z',oid).split(b'\0'):
            if not row:continue
            metadata,path=row.split(b'\t',1);_,typ,child=metadata.split()
            if typ==b'blob':paths.setdefault(child.decode(),set()).add(os.fsdecode(path))
    findings=[];blobs=commits=0
    process=subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    try:
        for oid,kind,size in entries:
            if kind not in ('blob','commit'):continue
            blobs+=kind=='blob';commits+=kind=='commit'
            names=sorted(paths.get(oid,()))
            for name in names:
                p=Path(name)
                if (p.suffix.lower() in FORBIDDEN or p.name=='.env' or (p.name.startswith('.env.') and p.name!='.env.example')
                        or any(part in ('.agents','.cursor') for part in p.parts)):
                    findings.append(_finding('forbidden-path',oid,0,[name],name))
            process.stdin.write((oid+'\n').encode());process.stdin.flush()
            header=process.stdout.readline().decode().split();assert header==[oid,kind,size]
            remaining=int(size);body=bytearray()
            while remaining:
                data=process.stdout.read(min(remaining,65536))
                if not data:raise EOFError('Incomplete Git object')
                body.extend(data[:max(0,MAX_TEXT+1-len(body))]);remaining-=len(data)
            if process.stdout.read(1)!=b'\n':raise ValueError('Invalid Git object framing')
            if int(size)>MAX_TEXT:
                findings.append(_finding('oversize-object-needs-review',oid,0,names));continue
            try:text=body.decode('utf-8')
            except UnicodeError:
                findings.append(_finding('binary-object-needs-review',oid,0,names));continue
            if '\0' in text:
                findings.append(_finding('binary-object-needs-review',oid,0,names));continue
            patterns={**PATTERNS,**{'attribution-'+str(i):p for i,p in enumerate(policy.ATTRIBUTION_PATTERNS)}}
            for rule,pattern in patterns.items():
                for match in pattern.finditer(text):
                    findings.append(_finding(rule,oid,text.count('\n',0,match.start())+1,names,match.group()))
            for match in policy.IPV4_PATTERN.finditer(text):
                if not match.group().startswith(policy.ALLOWED_IPV4_PREFIXES):
                    findings.append(_finding('non-example-private-ip',oid,text.count('\n',0,match.start())+1,names,match.group()))
            for match in re.finditer(r'[A-Za-z0-9_-]{4,}',text):
                if hashlib.sha256(match.group().lower().encode()).hexdigest() in policy.BLOCKED_TOKEN_HASHES:
                    findings.append(_finding('blocked-identifier',oid,text.count('\n',0,match.start())+1,names,match.group()))
    finally:
        process.stdin.close();process.stdout.close()
        if process.wait(timeout=10):raise RuntimeError('Git object reader failed')
    if inventory(repo)[1]!=binding:raise RuntimeError('Git object inventory changed during audit')
    return {'revision':1,'status':'passed' if not findings else 'review_required','head':before['head'],
            'inventory_sha256':binding,'refs':before['refs'],'stored_objects':len(entries),
            'commits_scanned':commits,'blobs_scanned':blobs,'findings':findings,
            'scope':'all stored blobs and commit metadata, including unreachable objects; all paths in stored commits',
            'limits':'Pattern/policy audit, not proof of absence of every secret. Matched values are never emitted.'}


def review(report,document):
    if (type(document) is not dict or set(document)!={'revision','inventory_sha256','decisions'}
            or type(document['revision']) is not int or document['revision']!=1
            or document['inventory_sha256']!=report['inventory_sha256'] or type(document['decisions']) is not list):
        raise ValueError('Review must bind the exact audited Git inventory')
    findings={row['id'] for row in report['findings']};accepted={}
    for item in document['decisions']:
        if (type(item) is not dict or set(item)!={'id','disposition','reason'} or not isinstance(item['id'],str) or item['id'] not in findings
                or item['id'] in accepted or not isinstance(item['disposition'],str) or item['disposition'] not in ('synthetic-test-fixture','documentation-placeholder','public-test-vector')
                or not isinstance(item['reason'],str) or not item['reason'].strip()):
            raise ValueError('Invalid explicit history review decision')
        accepted[item['id']]=item
    unresolved=[row['id'] for row in report['findings'] if row['id'] not in accepted]
    return {**report,'status':'passed' if not unresolved else 'review_required','reviewed':list(accepted.values()),'unresolved':unresolved}


def write_report(path,value):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'w',encoding='utf-8') as stream:json.dump(value,stream,indent=2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,default=ROOT);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--review',type=Path);parser.add_argument('--review-sha256')
    args=parser.parse_args()
    if bool(args.review)!=bool(args.review_sha256):parser.error('Review file and SHA-256 must be supplied together')
    report=scan(args.repo)
    if args.review:
        raw=args.review.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=args.review_sha256:raise ValueError('History review digest changed')
        report=review(report,json.loads(raw))
    write_report(args.output,report)
    print(json.dumps({k:report[k] for k in ('status','head','commits_scanned','blobs_scanned')}))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
