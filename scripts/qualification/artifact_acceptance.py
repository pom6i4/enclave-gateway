#!/usr/bin/env python3
"""Accept exact wheel/native bytes in a disposable Windows or Linux environment."""
from __future__ import annotations
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import tempfile
import venv
import zipfile
from email.parser import BytesParser


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_receipt(path,value):
    """A failed write must not truncate the last useful diagnostic receipt."""
    pending=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,delete=False) as stream:
            pending=Path(stream.name);json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        deadline=time.monotonic()+2
        while True:
            try:
                os.replace(pending,path);break
            except PermissionError as error:
                if getattr(error,'winerror',None) not in (5,32,33) or time.monotonic()>=deadline:raise
                time.sleep(.025)
    finally:
        if pending is not None:pending.unlink(missing_ok=True)


def check_pe(path,arch):
    """Do not mistake x64 emulation on ARM64 for native ARM64 acceptance."""
    with path.open('rb') as stream:
        if stream.read(2)!=b'MZ':raise ValueError('Native helper lacks a PE header')
        stream.seek(0x3c);offset=stream.read(4)
        if len(offset)!=4:raise ValueError('Truncated native helper header')
        stream.seek(int.from_bytes(offset,'little'));header=stream.read(6)
    if len(header)!=6 or header[:4]!=b'PE\0\0' or int.from_bytes(header[4:],'little')!={'arm64':0xaa64,'x86_64':0x8664}[arch]:
        raise ValueError('Native helper architecture differs from the Windows OS')


def machine():
    if os.name=='nt':
        from ctypes import wintypes
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.GetCurrentProcess.restype=wintypes.HANDLE
        kernel.IsWow64Process2.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.USHORT),ctypes.POINTER(wintypes.USHORT)]
        process=wintypes.USHORT();native=wintypes.USHORT()
        if not kernel.IsWow64Process2(kernel.GetCurrentProcess(),ctypes.byref(process),ctypes.byref(native)):raise ctypes.WinError()
        return {0xaa64:'arm64',0x8664:'x86_64'}[native.value]
    value=platform.machine().lower()
    if value not in ('aarch64','arm64','x86_64','amd64'):raise RuntimeError('Unsupported acceptance architecture')
    return 'arm64' if value in ('aarch64','arm64') else 'x86_64'


def run(args):
    if platform.system() not in ('Windows','Linux'):raise RuntimeError('Use a disposable Windows/Linux environment')
    if args.output.exists() or args.work_dir.exists():raise FileExistsError('Preserve earlier acceptance outputs')
    os.umask(0o077);args.work_dir.mkdir(parents=True,mode=0o700);args.output.parent.mkdir(parents=True,exist_ok=True)
    work=args.work_dir.resolve();logs=work/'logs';logs.mkdir();arch=machine();windows=os.name=='nt'
    with zipfile.ZipFile(args.wheel) as wheel:
        names=[n for n in wheel.namelist() if n.endswith('.dist-info/METADATA')]
        if len(names)!=1:raise ValueError('Ambiguous wheel metadata')
        metadata=BytesParser().parsebytes(wheel.read(names[0]))
        if metadata['Name']!='enclave-gateway':raise ValueError('Wrong wheel identity')
        version=metadata['Version']
    report={'revision':1,'status':'running','scope':'release-artifact-acceptance','qualifier_sha256':digest(__file__),
            'platform':{'system':platform.system(),'machine':arch,'process_machine':platform.machine(),'python':platform.python_version()},
            'artifacts':{args.wheel.name:digest(args.wheel)},'checks':{},'commands':[],
            'environment_scope':'Windows disposable local VM; no RDP/VPN acceptance' if windows else 'Linux isolated userspace/kernel environment; no provider acceptance'}
    save=lambda:write_receipt(args.output,report)
    save();environment={k:v for k,v in os.environ.items() if not k.startswith(('EGW_','ENCLAVE_','SSH_','PYTHON','PIP_'))};environment.update(PYTHONDONTWRITEBYTECODE='1',PIP_CONFIG_FILE=os.devnull,PIP_DISABLE_PIP_VERSION_CHECK='1')
    def command(name,argv,*,input=None,env=None,timeout=90,success=True):
        started=time.monotonic()
        try:
            result=subprocess.run([str(x) for x in argv],cwd=work,env=env or environment,input=input,capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (logs/(name+'.log')).write_bytes((error.stdout or b'')+(error.stderr or b''))
            report['commands'].append({'name':name,'status':'timed_out','limit_sec':timeout,'elapsed_ms':round((time.monotonic()-started)*1000)});save();raise
        (logs/(name+'.log')).write_bytes(result.stdout+result.stderr);report['commands'].append({'name':name,'exit_code':result.returncode});save()
        if success and result.returncode:raise RuntimeError('Artifact check failed: '+name)
        return result
    try:
        client=work/'client';venv.EnvBuilder(with_pip=args.pip_wheel is None,symlinks=not windows).create(client)
        binary=client/('Scripts' if windows else 'bin');python=binary/('python.exe' if windows else 'python');entry=binary/('egw.exe' if windows else 'egw')
        installer=[python,'-m','pip']
        if args.pip_wheel:
            report['pip_wheel_sha256']=digest(args.pip_wheel)
            installer=[python,'-I','-c',"import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')",args.pip_wheel]
        command('install-wheel',[*installer,'--disable-pip-version-check','install','--no-index','--no-deps',args.wheel],timeout=120);report['checks']['wheel_install']=True
        result=command('isolated-import',[python,'-I','-c',"import enclave_gateway,sys,json,pathlib;assert 'site-packages' in pathlib.Path(enclave_gateway.__file__).parts;assert pathlib.Path(enclave_gateway.__file__).resolve().is_relative_to(pathlib.Path(sys.prefix));print(json.dumps({'version':enclave_gateway.__version__}))"])
        report['checks']['isolated_import']=json.loads(result.stdout)['version']==version
        if not report['checks']['isolated_import']:raise RuntimeError('Installed wheel version mismatch')
        command('cli-help',[entry,'--help']);command('config-init',[entry,'config','init']);summary=json.loads(command('config-check',[entry,'config','check']).stdout)
        if summary['security_mode']!='standard' or summary['provider_type']!='custom':raise RuntimeError('Wrong installed startup defaults')
        command('startup-command',[entry,'agents','command']);command('mcp-schema',[entry,'mcp','--export-openapi']);report['checks']['cli']=True
        if windows:
            if not args.allow_unsigned_lab or not args.runtime or not args.askpass:raise ValueError('Explicit disposable unsigned Windows artifacts required')
            rid='win-arm64' if arch=='arm64' else 'win-x64'
            for name,path in [('egw-runtime.exe',args.runtime),('egw-askpass.exe',args.askpass)]:
                check_pe(path,arch);report['artifacts'][rid+'/'+name]=digest(path)
            no_sdk={**environment,'PATH':str(Path(os.environ['SystemRoot'])/'System32')+os.pathsep+str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0'),
                    'DOTNET_ROOT':str(work/'absent-dotnet'),'DOTNET_ROOT_ARM64':str(work/'absent-dotnet'),'DOTNET_ROOT_X64':str(work/'absent-dotnet'),'DOTNET_BUNDLE_EXTRACT_BASE_DIR':str(work/'bundle-cache')}
            if shutil.which('dotnet',path=no_sdk['PATH']):raise RuntimeError('SDK visible in acceptance PATH')
            value='synthetic literal тест';result=command('askpass-unicode',[args.askpass,'ignored prompt'],env={**no_sdk,'EGW_ASKPASS_B64':base64.b64encode(value.encode()).decode()})
            if result.stdout.decode().strip()!=value:raise RuntimeError('Askpass Unicode mismatch')
            bad=command('askpass-invalid',[args.askpass],env={**no_sdk,'EGW_ASKPASS_B64':'!invalid'},success=False)
            if bad.returncode!=2 or bad.stdout or bad.stderr:raise RuntimeError('Askpass invalid-input disclosure')
            report['checks']['askpass']=True
            helper=Path(__file__).with_name('native_windows.py');report['native_qualifier_sha256']=digest(helper)
            result=command('native-runtime',[python,'-I',helper,'--runtime',args.runtime,'--allow-unsigned-lab','--output',work/'native-result.json'],env=no_sdk,timeout=180)
            native=json.loads((work/'native-result.json').read_text())
            if (native['status']!='passed' or native['timing_scale']!=1 or native['signature_stage_cap_sec']!=15
                    or native['symlink_denial']!='passed' or native['job_descendant_cancellation']!='passed'):raise RuntimeError('Incomplete native runtime acceptance')
            report['checks'].update(native_filesystem=True,native_cancellation=native['job_descendant_cancellation']=='passed',sdk_independent=True)
            _signatures(work,command,python,args.runtime,no_sdk,report)
        else:
            config={'security':{'mode':'standard'},'appliance':{'hypervisor':'direct','runtime_dir':str(work/'runtime')},'provider':{'type':'custom','installer_path':'','dst_key_path':''},'bastion':{'enabled':False}}
            (work/'direct.json').write_text(json.dumps(config));base=[entry,'-c',work/'direct.json','--state-dir',work/'state']
            result=command('posix-exec',[*base,'exec','@appliance',"printf 'ARTIFACT_POSIX_OK'",'--timeout','10'])
            if result.stdout!=b'ARTIFACT_POSIX_OK':raise RuntimeError('Installed POSIX execution mismatch')
            report['checks']['posix_execution']=True
            script=r'''import base64,hashlib,os,pathlib
from enclave_gateway.agents.rooted_fs import request
root=pathlib.Path('rooted').resolve();root.mkdir();outside=root.parent/'outside';outside.write_bytes(b'untouched');data=bytes(range(256))*512
def fs(action,**kw):return request({'root':str(root),'action':action,**kw})
fs('mkdir',path='sub');fs('write',path='sub/stage',offset=0,data=base64.b64encode(data).decode());fs('commit',path='sub/stage',target='sub/data',sha256=hashlib.sha256(data).hexdigest());assert (root/'sub/data').read_bytes()==data
for name,method in [('link',lambda:os.symlink(outside,root/'link')),('hard',lambda:os.link(outside,root/'hard'))]:
 method()
 try:fs('read',path=name,offset=0,size=1)
 except (ValueError,OSError):pass
 else:raise AssertionError('Link escaped rooted filesystem')
try:fs('read',path='../outside',offset=0,size=1)
except (ValueError,OSError):pass
else:raise AssertionError('Traversal escaped root')
assert outside.read_bytes()==b'untouched'
'''
            command('rooted-files',[python,'-I','-c',script]);report['checks']['rooted_files']=True
            _cancel_posix(work,base,environment,logs);report['checks']['owned_cancellation']=True
            messages=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'artifact-check','version':'1'}}},
                      {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
                      {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'node_exec','arguments':{'node':'@appliance','script':'touch '+str(work/'must-not-exist')}}}]
            result=command('read-only-mcp',[*base,'mcp','--read-only'],input=('\n'.join(json.dumps(x) for x in messages)+'\n').encode())
            responses=[json.loads(x) for x in result.stdout.splitlines()];last=next(x for x in responses if x.get('id')==3)
            if 'blocked' not in json.dumps(last).lower() or (work/'must-not-exist').exists():raise RuntimeError('MCP read-only dispatch was not denied')
            report['checks']['mcp_read_only']=True
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__);raise
    finally:save()
    return report


def _cancel_posix(work,base,environment,logs):
    import select
    marker=work/'descendant.pid';process=subprocess.Popen([str(x) for x in [*base,'exec','@appliance','sleep 30 & echo $! > '+str(marker)+'; wait','--timeout','2']],cwd=work,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    handle=None
    try:
        deadline=time.monotonic()+5
        while not marker.exists():
            if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Owned child did not start')
            time.sleep(.01)
        handle=os.pidfd_open(int(marker.read_text().strip()));poll=select.poll();poll.register(handle,select.POLLIN)
        out,err=process.communicate(timeout=8);(logs/'posix-cancel.log').write_bytes(out+err)
        if not process.returncode or not poll.poll(3000):raise RuntimeError('Owned descendant survived cancellation')
    finally:
        if process.poll() is None:process.kill();process.communicate(timeout=5)
        if handle is not None:os.close(handle)


def _signatures(work,command,python,runtime,environment,report):
    shell=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe';folder=work/'signing';folder.mkdir();copy=folder/'egw-runtime.exe';shutil.copyfile(runtime,copy)
    quote=lambda value:"'"+str(value).replace("'","''")+"'"
    before=r"@{stores=@(foreach($n in 'My','Root','TrustedPublisher'){@{name=$n;thumbprints=@(Get-ChildItem ('Cert:\LocalMachine\'+$n)|ForEach-Object Thumbprint|Sort-Object)}})}|ConvertTo-Json -Depth 5 -Compress"
    original=json.loads(command('trust-before',[shell,'-NoProfile','-Command',before]).stdout.decode('utf-8-sig'))
    meta=folder/'owned-cert.json'
    script=r'''$ErrorActionPreference='Stop';$p=FOLDER
$c=New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=EGW Artifact Lab '+[Guid]::NewGuid().ToString('N')) -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' -HashAlgorithm SHA256 -NotAfter (Get-Date).AddHours(6)
@{thumbprint=$c.Thumbprint}|ConvertTo-Json|Set-Content ($p+'\owned-cert.json') -Encoding UTF8
try {foreach($n in 'Root','TrustedPublisher'){$s=New-Object Security.Cryptography.X509Certificates.X509Store($n,'LocalMachine');try{$s.Open('ReadWrite');$s.Add($c)}finally{$s.Close()}}
if((Set-AuthenticodeSignature -LiteralPath ($p+'\egw-runtime.exe') -Certificate $c -HashAlgorithm SHA256).Status -ne 'Valid'){throw 'Lab signature failed'}
"if((Get-ExecutionPolicy) -ne 'AllSigned'){throw 'Wrong execution policy'};Write-Output 'SIGNED_LAB_OK'"|Set-Content ($p+'\signed.ps1') -Encoding UTF8
if((Set-AuthenticodeSignature -LiteralPath ($p+'\signed.ps1') -Certificate $c -HashAlgorithm SHA256).Status -ne 'Valid'){throw 'Lab script signature failed'}
"Write-Output 'UNSIGNED_MUST_NOT_RUN'"|Set-Content ($p+'\unsigned.ps1') -Encoding UTF8
} finally {$c.Dispose()}
'''.replace('FOLDER',quote(folder))
    try:
        command('create-lab-signature',[shell,'-NoProfile','-Command',script],timeout=90)
        thumb=json.loads(meta.read_text(encoding='utf-8-sig'))['thumbprint']
        code="from enclave_gateway.security.native import verified_runtime;verified_runtime("+repr(str(copy))+",["+repr(thumb)+"],True);print('VERIFIED')"
        command('verify-lab-signer',[python,'-I','-c',code],env=environment,timeout=20)
        wrong=command('reject-other-signer',[python,'-I','-c',code.replace(thumb,'0'*40)],env=environment,timeout=20,success=False)
        if not wrong.returncode:raise RuntimeError('Wrong signer accepted')
        signed=command('allsigned-positive',[shell,'-NoProfile','-NonInteractive','-ExecutionPolicy','AllSigned','-File',folder/'signed.ps1'],env=environment)
        if b'SIGNED_LAB_OK' not in signed.stdout:raise RuntimeError('Signed script did not run')
        unsigned=command('allsigned-negative',[shell,'-NoProfile','-NonInteractive','-ExecutionPolicy','AllSigned','-File',folder/'unsigned.ps1'],env=environment,success=False)
        if not unsigned.returncode or b'UNSIGNED_MUST_NOT_RUN' in unsigned.stdout:raise RuntimeError('Unsigned script was accepted under AllSigned')
        report['checks'].update(lab_signatures=True,unsigned_policy_denied=True)
    finally:
        cleanup=r'''$ErrorActionPreference='Stop';$p=META
if([IO.File]::Exists($p)){
 $t=([IO.File]::ReadAllText($p)|ConvertFrom-Json).thumbprint
 if($t -cnotmatch '^[A-F0-9]{40}$'){throw 'Own signer identity invalid'}
 foreach($n in 'Root','TrustedPublisher'){
  $path='Cert:\LocalMachine\'+$n+'\'+$t
  if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}
 }
 $path='Cert:\LocalMachine\My\'+$t
 if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -DeleteKey -Force}
}
'''.replace('META',quote(meta))
        command('remove-own-lab-key',[shell,'-NoProfile','-Command',cleanup])
        after=json.loads(command('trust-after',[shell,'-NoProfile','-Command',before]).stdout.decode('utf-8-sig'))
        if original!=after:raise RuntimeError('Trust stores changed after laboratory cleanup')
        report['lab_trust_cleanup']='own key/trust removed; original stores preserved'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--wheel',type=Path,required=True);parser.add_argument('--pip-wheel',type=Path)
    parser.add_argument('--runtime',type=Path);parser.add_argument('--askpass',type=Path);parser.add_argument('--allow-unsigned-lab',action='store_true')
    parser.add_argument('--work-dir',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    value=run(parser.parse_args());print(json.dumps({'status':value['status'],'platform':value['platform'],'checks':value['checks']},indent=2))
