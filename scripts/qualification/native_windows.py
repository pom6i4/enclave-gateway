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
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path


def run(runtime,time_scale=1):
    if os.name!='nt': raise RuntimeError('Windows runtime qualification requires Windows')
    shell=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
    def request(mode,value,expect_success=True):
        process=subprocess.run([runtime,mode],input=json.dumps(value),capture_output=True,text=True,encoding='utf-8',timeout=15*time_scale)
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
        replacement=b'replacement-payload'
        fs('mkdir',path='other')
        fs('write',path='other/stage.bin',offset=0,data=base64.b64encode(replacement).decode())
        rejected=request('fs',{'root':str(root),'action':'commit','path':'other/stage.bin','target':'sub/result.bin','sha256':'0'*64},False)
        assert rejected.returncode!=0
        assert (root/'sub/result.bin').read_bytes()==payload
        fs('commit',path='other/stage.bin',target='sub/result.bin',sha256=hashlib.sha256(replacement).hexdigest())
        assert (root/'sub/result.bin').read_bytes()==replacement
        assert not (root/'other/stage.bin').exists()
        entries=json.loads(fs('list',path='').stdout)['entries']
        assert any(entry['path']=='sub/result.bin' and entry['sha256']==hashlib.sha256(replacement).hexdigest() for entry in entries)
        fs('commit',path='sub/result.bin',target='x',sha256=hashlib.sha256(replacement).hexdigest())
        assert (root/'x').read_bytes()==replacement
        fs('remove',path='x')
        assert not (root/'x').exists()
        # Exercise the stdin pipe used by the worker, including Unicode input.
        bootstrap='[Console]::InputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'
        command="[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); Write-Output 'проверка'"
        result=request('run',{'command':[shell,'-NoProfile','-NonInteractive','-Command',bootstrap],
                              'stdin_b64':base64.b64encode(command.encode()).decode(),'timeout_ms':15000*time_scale})
        assert result.stdout.strip()=='проверка',result.stdout
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
        arguments=['','plain','/qn','quote"value','trailing\\','space trailing\\','тест']
        code='import json,sys;print(json.dumps(sys.argv[1:]))'
        result=request('run',{'command':[sys.executable,'-c',code,*arguments],'timeout_ms':15000*time_scale})
        assert json.loads(result.stdout)==arguments,result.stdout
        # Capture a descendant handle before cancellation so PID reuse cannot
        # turn an exit check into a claim about an unrelated process.
        token=secrets.token_hex(32)
        sleep_seconds=30*time_scale
        script="$child=Start-Process -FilePath '"+shell.replace("'","''")+"' -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 30' -PassThru -NoNewWindow; [Console]::Out.WriteLine($child.Id); Start-Sleep -Seconds 30"
        script=script.replace('Seconds 30','Seconds '+str(sleep_seconds))
        encoded=base64.b64encode(script.encode('utf-16le')).decode()
        process=subprocess.Popen([runtime,'run'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
        process.stdin.write(json.dumps({'command':[shell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],'timeout_ms':10000*time_scale,'cancel_token':token})); process.stdin.close()
        handle=None
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_uint];kernel.OpenProcess.restype=ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint];kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pid=int(pool.submit(process.stdout.readline).result(timeout=8*time_scale).strip())
            handle=kernel.OpenProcess(0x100000,False,pid)
            assert handle,'Cannot retain owned descendant handle'
            request('cancel',{'cancel_token':token})
            assert process.wait(timeout=5*time_scale)==125
            assert kernel.WaitForSingleObject(handle,3000*time_scale)==0,'Descendant survived Job termination'
        finally:
            if process.poll() is None: process.kill();process.wait(5)
            if handle: kernel.CloseHandle(handle)
            process.stdout.close();process.stderr.close()
    return {'status':'passed','scope':'disposable-windows-native-runtime','fs':'passed','hardlink_denial':'passed',
            'symlink_denial':link_test,'cross_directory_replace':'passed','wrong_digest_preserves_destination':'passed','unicode_stdin':'passed','argv_roundtrip':'passed','job_descendant_cancellation':'passed','vpn_keys':'not_used','signing':'not_qualified','timing_scale':time_scale,'signature_stage_cap_sec':15*time_scale}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime',required=True)
    trust=parser.add_mutually_exclusive_group(required=True)
    trust.add_argument('--allow-unsigned-lab',action='store_true')
    trust.add_argument('--trusted-signer')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--time-scale',type=int,default=1,choices=range(1,9),help='Explicit software-emulation timing multiplier; production verification remains 15 seconds')
    args=parser.parse_args()
    if args.trusted_signer:
        import sys
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
        from enclave_gateway.security.native import verified_runtime
        verified_runtime(str(args.runtime),[args.trusted_signer],verification_timeout_sec=15*args.time_scale)
    result=run(str(Path(args.runtime).resolve()),args.time_scale)
    if args.trusted_signer: result['signing']='trusted-lab-signer'
    text=json.dumps(result,indent=2)
    if args.output: args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(text+'\n')
    print(text)
