#!/usr/bin/env python3
"""Exercise native trust framing with UTF-8 BOM, Unicode paths and invalid input."""
from __future__ import annotations
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time


def run(args):
    if os.name!='nt':raise RuntimeError('Use a disposable Windows fixture')
    workspace=args.output.with_suffix('')
    if workspace.exists() or args.output.exists():raise FileExistsError('Use a new framing fixture directory')
    workspace.mkdir(parents=True);worker=workspace/'подписанный.ps1';shutil.copyfile(args.worker,worker)
    worker_hash=hashlib.sha256(worker.read_bytes()).hexdigest();runtime_hash=hashlib.sha256(args.runtime.read_bytes()).hexdigest()
    report={'status':'running','checks':[]};process=None;pool=ThreadPoolExecutor(max_workers=1)
    def frame(value):return base64.b64encode(json.dumps(value,ensure_ascii=False).encode('utf-8'))+b'\n'
    def read():
        try:raw=pool.submit(process.stdout.readline,2*1024*1024).result(timeout=120)
        except BaseException:
            process.kill();process.wait(timeout=5);raise
        return json.loads(raw)
    def check(value,nonce,sequence,online=False):
        if value.get('ExitCode')!=0:raise RuntimeError('Native trust response failed')
        evidence=json.loads(value['Stdout'])
        if (evidence['nonce']!=nonce or evidence['current_sha256']!=worker_hash or evidence['runtime_current_sha256']!=runtime_hash or
            evidence['signature_status']!='Valid' or evidence['runtime_signature_status']!='Valid' or evidence['signer']!=args.trusted_signer or
            evidence['runtime_signer']!=args.trusted_signer or evidence['trust_probe_sequence']!=sequence or
            evidence.get('trust_policy')!=('online-chain-revocation-excluding-root' if online else 'cache-only-chain-revocation-excluding-root')):raise RuntimeError('Native trust identity or policy mismatch')
    try:
        config={'worker_path':str(worker),'runtime_path':str(args.runtime),'worker_sha256':worker_hash,'runtime_sha256':runtime_hash,'require_signed':True}
        process=subprocess.Popen([str(args.runtime),'attest-server',str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        # .NET Framework StreamWriter can prefix UTF-8 when Console CP is 65001.
        process.stdin.write(b'\xef\xbb\xbf'+frame(config));process.stdin.flush()
        ready=read();report['initialization']=ready
        if ready.get('ready')!=1:raise RuntimeError('UTF-8 preamble was not accepted')
        report['checks'].append('bom-prefixed-initialization')
        nonce=secrets.token_hex(32);query={'worker_path':str(worker),'runtime_path':str(args.runtime),'process_isolation':True,'evidence':{'nonce':nonce}}
        process.stdin.write(frame(query));process.stdin.flush();check(read(),nonce,1)
        report['checks'].append('unicode-path-first-challenge')
        original=worker.read_bytes()
        worker.write_bytes(original+b'\r\n# changed after initialization\r\n')
        process.stdin.write(frame(query));process.stdin.flush();changed=read()
        evidence=json.loads(changed['Stdout'])
        if (changed.get('ExitCode')!=0 or evidence['signature_status']=='Valid' or
            evidence['current_sha256']==worker_hash or evidence['trust_probe_sequence']!=2):
            raise RuntimeError('Startup trust was reused after file modification')
        worker.write_bytes(original)
        report['checks'].append('post-initialization-tamper-rejected')
        process.stdin.write(b'not-base64\n');process.stdin.flush()
        if read().get('ExitCode')!=1:raise RuntimeError('Malformed frame was accepted')
        nonce=secrets.token_hex(32);query['evidence']['nonce']=nonce
        process.stdin.write(frame(query));process.stdin.flush();check(read(),nonce,3)
        report['checks'].append('malformed-frame-rejected-without-desynchronization')
        try:process.stdin.write(b'A'*(1024*1024+1)+b'\n');process.stdin.flush()
        except BrokenPipeError:pass
        process.wait(timeout=10)
        if process.returncode==0:raise RuntimeError('Oversize frame was accepted')
        report['checks'].append('oversize-frame-rejected')
        result=subprocess.run([str(args.runtime),'attest'],input=b'\xef\xbb\xbf'+json.dumps(query,ensure_ascii=False).encode('utf-8'),capture_output=True,timeout=120)
        if result.returncode:raise RuntimeError('UTF-8 one-shot request failed')
        check(json.loads(result.stdout),nonce,1,online=True);report['checks'].append('bom-and-unicode-one-shot-request')
        report['status']='passed'
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        if process:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            for stream in (process.stdin,process.stdout,process.stderr):
                try:stream.close()
                except BrokenPipeError:pass
        pool.shutdown(wait=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--worker',required=True,type=Path);p.add_argument('--runtime',required=True,type=Path)
    p.add_argument('--trusted-signer',required=True);p.add_argument('--output',required=True,type=Path)
    print(json.dumps(run(p.parse_args()),indent=2))
