#!/usr/bin/env python3
"""Exercise the real native runtime only in a separate disposable Windows lab."""
from __future__ import annotations
import argparse
import base64
import concurrent.futures
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path


def run(runtime):
    if os.name!='nt': raise RuntimeError('Windows runtime qualification requires Windows')
    shell=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
    def request(mode,value,expect_success=True):
        process=subprocess.run([runtime,mode],input=json.dumps(value),capture_output=True,text=True,encoding='utf-8',timeout=15)
        if expect_success and process.returncode: raise AssertionError(process.stdout)
        return process
    with tempfile.TemporaryDirectory(prefix='egw-native-lab-') as temporary:
        outer=Path(temporary); root=outer/'root';root.mkdir()
        def fs(action,**values): return request('fs',{'root':str(root),'action':action,**values})
        payload=bytes(range(256))*500
        fs('mkdir',path='sub')
        fs('write',path="sub/стадия '.bin",offset=0,data=base64.b64encode(payload).decode())
        fs('commit',path="sub/стадия '.bin",target='sub/result.bin',sha256=hashlib.sha256(payload).hexdigest())
        read=json.loads(fs('read',path='sub/result.bin',offset=0,size=len(payload)).stdout)
        assert base64.b64decode(read['data'])==payload
        blocked=request('fs',{'root':str(root),'action':'read','path':'../outside','offset':0,'size':1},False)
        assert blocked.returncode!=0
        outside=outer/'outside';outside.write_bytes(b'unchanged')
        os.link(outside,root/'hardlink')
        assert request('fs',{'root':str(root),'action':'read','path':'hardlink','offset':0,'size':1},False).returncode!=0
        link_test='not_available'
        try:
            (root/'link').symlink_to(outside)
            assert request('fs',{'root':str(root),'action':'read','path':'link','offset':0,'size':1},False).returncode!=0
            link_test='passed'
        except OSError: pass
        assert outside.read_bytes()==b'unchanged'
        # Capture a descendant handle before cancellation so PID reuse cannot
        # turn an exit check into a claim about an unrelated process.
        token=secrets.token_hex(32)
        script="$child=Start-Process -FilePath '"+shell.replace("'","''")+"' -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 30' -PassThru -NoNewWindow; [Console]::Out.WriteLine($child.Id); Start-Sleep -Seconds 30"
        encoded=base64.b64encode(script.encode('utf-16le')).decode()
        process=subprocess.Popen([runtime,'run'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
        process.stdin.write(json.dumps({'command':[shell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],'timeout_ms':10000,'cancel_token':token})); process.stdin.close()
        handle=None
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_uint];kernel.OpenProcess.restype=ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint];kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pid=int(pool.submit(process.stdout.readline).result(timeout=8).strip())
            handle=kernel.OpenProcess(0x100000,False,pid)
            assert handle,'Cannot retain owned descendant handle'
            request('cancel',{'cancel_token':token})
            assert process.wait(timeout=5)==125
            assert kernel.WaitForSingleObject(handle,3000)==0,'Descendant survived Job termination'
        finally:
            if process.poll() is None: process.kill();process.wait(5)
            if handle: kernel.CloseHandle(handle)
            process.stdout.close();process.stderr.close()
    return {'status':'passed','scope':'disposable-windows-native-runtime','fs':'passed','hardlink_denial':'passed',
            'symlink_denial':link_test,'job_descendant_cancellation':'passed','vpn_keys':'not_used','signing':'not_qualified'}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime',required=True)
    parser.add_argument('--allow-unsigned-lab',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not args.allow_unsigned_lab: parser.error('Run only in a disposable lab with explicit --allow-unsigned-lab; this does not qualify signing')
    result=run(str(Path(args.runtime).resolve()))
    text=json.dumps(result,indent=2)
    if args.output: args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(text+'\n')
    print(text)
