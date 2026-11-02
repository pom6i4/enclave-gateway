#!/usr/bin/env python3
"""Public local acceptance: tools, builds, models, installation and lab PKI."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid
import zipfile

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(Path(__file__).resolve().parent))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.hypervisor.state import atomic_json
from windows_lifecycle import owned_hypervisor,owned_tpm_pid,wait_tpm_exit
from toolchain import preflight,release
from compare_installed import compare as compare_installed
from evidence import report_inventory


def cohort_sources():
    files=[]
    for top in ('src','scripts','native','tests'):
        files += [p for p in (ROOT/top).rglob('*') if p.is_file() and p.suffix in ('.py','.ps1','.cs','.csproj') and not set(p.relative_to(ROOT).parts)&{'obj','bin','__pycache__'}]
    files += [ROOT/n for n in ('README.md','LICENSE','pyproject.toml')]
    if any(p.is_symlink() for p in files):raise ValueError('Source links rejected')
    return {p.relative_to(ROOT).as_posix():release.digest(p) for p in sorted(files)}


def source_archive(destination,package=None,pki=None):
    files={'source/'+name:ROOT/name for name in cohort_sources()}
    if package:
        for p in package.iterdir():
            if p.is_file():files['package/'+p.name]=p
    if pki:files['PkiLab.exe']=pki
    records=[]
    with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED) as out:
        for name,p in sorted(files.items()):out.write(p,name);records.append({'path':name,'sha256':release.digest(p)})
        out.writestr('inputs.json',json.dumps({'files':records},sort_keys=True))
    return {name:release.digest(p) for name,p in files.items()}


def guest_ready(agent,timeout=420):
    deadline=time.monotonic()+timeout
    while True:
        try:
            with agent._connect_synced(3) as(s,r):agent._request(s,r,'guest-ping')
            return
        except (OSError,ValueError,RuntimeError):
            if time.monotonic()>deadline:raise TimeoutError('Guest QGA readiness deadline')
            time.sleep(2)


def stage(agent,archive):
    folder='C:\\EnclaveGateway\\Qualification\\'+uuid.uuid4().hex
    check=agent.exec_powershell("$ErrorActionPreference='Stop';if(Test-Path '"+folder+"'){throw 'Namespace exists'};[void][IO.Directory]::CreateDirectory('"+folder+"')",timeout_sec=120)
    if check.exit_code:raise RuntimeError('Guest namespace creation failed')
    agent.write_file(archive,folder+'\\input.zip',timeout_sec=600)
    command="$ErrorActionPreference='Stop';if((Get-FileHash '"+folder+"\\input.zip' -Algorithm SHA256).Hash.ToLowerInvariant() -ne '"+release.digest(archive)+"'){throw 'Transfer hash mismatch'};Expand-Archive -LiteralPath '"+folder+"\\input.zip' -DestinationPath '"+folder+"\\input'"
    result=agent.exec_powershell(command,timeout_sec=600)
    if result.exit_code:raise RuntimeError('Guest source staging failed')
    return folder


def build_pki(manifest,output,rid):
    output.mkdir();src=output/'source';src.mkdir()
    for name in ('Program.cs','PkiLab.csproj'):
        (src/name).write_bytes((ROOT/'scripts/qualification/pki_lab'/name).read_bytes())
    nuget=release.build_config(src,manifest['dotnet']['version'])
    env=release.tool_environment(manifest);dotnet=manifest['dotnet']['path'];dest=output/'publish'
    common=['-r',rid,'-p:SelfContained=true','-p:PublishSingleFile=true','-p:RuntimeFrameworkVersion='+manifest['runtime_version']]
    for label,args in [('restore',['restore','PkiLab.csproj','--configfile',str(nuget),'--use-lock-file']),('locked',['restore','PkiLab.csproj','--configfile',str(nuget),'--locked-mode']),('publish',['publish','PkiLab.csproj','--no-restore','-c','Release','-o',str(dest)])]:
        with (output/(label+'.log')).open('xb') as log:r=subprocess.run([dotnet,*args,*common],cwd=src,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600)
        if r.returncode:raise RuntimeError('PKI fixture build failed: '+label)
    helper=dest/'PkiLab.exe';atomic_json(output/'result.json',{'status':'passed','sha256':release.digest(helper),'source_sha256':{p.name:release.digest(p) for p in src.glob('*.cs*')}})
    return helper


def verify_guest_results(output):
    values={name:json.loads((output/name).read_text(encoding='utf-8-sig')) for name in ('windows-suite.json','preparation.json','migration.json','pki.json')}
    if any(v.get('status')!='passed' for v in values.values()) or values['windows-suite.json'].get('cleanup')!='passed':raise RuntimeError('Guest acceptance evidence failed')
    for name,count in (('preparation.json',2),('migration.json',9),('pki.json',12)):
        if len(values[name].get('checks',[]))!=count:raise ValueError('Incomplete guest acceptance checks')
    pki=values['pki.json'];times=pki.get('nonce_elapsed_ms',[])
    if pki.get('nonce_deadline_ms')!=10000 or len(times)!=9 or any(type(n) is not int or not 0<=n<10000 for n in times):raise ValueError('PKI challenge budget violated')
    for case,flag in (('revoked','Revoked'),('ocsp-revoked','Revoked'),('expired','NotTimeValid'),('cache','RevocationStatusUnknown'),('stale','RevocationStatusUnknown')):
        if flag not in pki.get('chain_status',{}).get(case,[]):raise ValueError('Missing causal PKI evidence')


def windows_checks(folder,package,pki,output):
    h=owned_hypervisor(folder);h.start();agent=QgaClient(h.spec.qga_socket)
    try:
        guest_ready(agent);archive=output/'windows-input.zip';inputs=source_archive(archive,package,pki);atomic_json(output/'windows-inputs.json',inputs)
        guest=stage(agent,archive);script=guest+'\\input\\source\\scripts\\qualification\\windows_acceptance.ps1'
        result=agent.exec_guest('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script,'-InputRoot',guest+'\\input','-Workspace',guest+'\\results'],timeout_sec=3600)
        (output/'windows-suite.out.log').write_text(result.stdout);(output/'windows-suite.err.log').write_text(result.stderr)
        for name,path in [('windows-suite.json','result.json'),('preparation.json','preparation/result.json'),('migration.json','migration/result.json'),('pki.json','pki/result.json')]:
            agent.read_file(guest+'\\results\\'+path.replace('/','\\'),output/name,timeout_sec=600)
        if result.exit_code:raise RuntimeError('Disposable Windows acceptance failed')
        verify_guest_results(output)
    finally:
        pid=owned_tpm_pid(h.spec) if h.is_running()[0] and h.spec.tpm_state_dir else None
        if h.is_running()[0]:h.stop(timeout_sec=300)
        h._stop_tpm();wait_tpm_exit(pid)
        if h.is_running()[0] or h.spec.pid_file.exists():raise RuntimeError('Final Windows cleanup failed')
        atomic_json(output/'windows-final-cleanup.json',{'status':'passed','vm':'stopped','software_tpm':'stopped','storage':'retained'})


def run(manifest_path,output,host_only=False,extended_manifest=None):
    if host_only and extended_manifest:raise ValueError('Extended acceptance requires the full profile')
    manifest_path=manifest_path.resolve();output=output.resolve()
    if output.exists():raise FileExistsError('Preserve previous acceptance runs')
    output.mkdir(parents=True,mode=0o700);output.chmod(0o700)
    manifest=json.loads(manifest_path.read_text());toolchain=manifest['toolchain']
    if manifest.get('revision')!=1 or manifest.get('scope')!='isolated-full-acceptance':raise ValueError('Explicit isolated acceptance manifest required')
    report={'status':'running','scope':'host-only' if host_only else 'full-isolated-acceptance','steps':[],'sources':cohort_sources(),'source_binding':'working-tree-hashes','manifest_sha256':release.digest(manifest_path),'actions':'not_used','client_environment':'not_used','production_keys':'not_used'}
    def persist():atomic_json(output/'result.json',report)
    def step(name,fn):
        row={'name':name,'status':'running'};report['steps'].append(row);persist();start=time.monotonic()
        try:result=fn();row['status']='passed';return result
        except BaseException as e:row.update(status='failed',error_type=type(e).__name__);raise
        finally:row['elapsed_sec']=round(time.monotonic()-start,3);persist()
    def command(name,argv,env,timeout=600):
        process=None
        try:
            with (output/(name+'.log')).open('xb') as log:
                process=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=os.name!='nt');process.wait(timeout=timeout)
            if process.returncode:raise RuntimeError('Acceptance command failed: '+name)
        finally:
            if process and process.poll() is None:
                if os.name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],check=True,capture_output=True,timeout=15)
                else:os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=15)
    try:
        if not host_only:
            options=manifest['windows']
            allowed={'windows_iso','virtio_directory','virtio_iso','guest_agent_msi','firmware_code','firmware_vars','arch','accelerator','port_base','vnc_display','cpus','memory_mb'}
            if set(options)-allowed:raise ValueError('Unknown Windows fixture option')
            for key in ('windows_iso','guest_agent_msi','firmware_code','firmware_vars'):
                if release.digest(Path(options[key]))!=manifest['media_sha256'][key]:raise ValueError('Unapproved Windows fixture media')
            if ('win-arm64' if options.get('arch','x86_64')=='arm64' else 'win-x64') not in toolchain['runtimes']:raise ValueError('Windows architecture has no release build target')
        env=step('preflight',lambda:preflight(toolchain,output/'preflight'))
        toolfile=output/'toolchain.json';atomic_json(toolfile,toolchain)
        step('independent-release-builds',lambda:release.build(toolfile,output/'builds'))
        python=toolchain['python']['path']
        step('source-tests',lambda:command('source-tests',[python,'-m','unittest','discover','-s','tests','-v'],env))
        step('installed-package',lambda:command('installed-package',[python,str(ROOT/'scripts/qualification/installed_package.py'),'--output',str(output/'installed-package')],env))
        if manifest.get('installed_reports'):
            step('cross-platform-installed-packages',lambda:compare_installed([output/'installed-package/result.json',*[Path(p) for p in manifest['installed_reports']]],output/'installed-platforms.json',manifest.get('required_installed_platforms',[])))
        step('generated-models-and-real-crashes',lambda:command('generated',[python,str(ROOT/'scripts/qualification/generated_faults.py'),'--output',str(output/'generated'),'--crashes'],env))
        if not host_only:
            options=manifest['windows'];arch=options.get('arch','x86_64');rid='win-arm64' if arch=='arm64' else 'win-x64'
            args=[python,str(ROOT/'scripts/qualification/disposable_windows.py'),'--output',str(output/'windows'),'--full-lifecycle','--tpm','--secure-boot','--deadline-sec','7200']
            for key in ('windows_iso','guest_agent_msi','firmware_code','firmware_vars'):
                if release.digest(Path(options[key]))!=manifest['media_sha256'][key]:raise ValueError('Windows media changed during host acceptance')
            for k,v in options.items():args+=['--'+k.replace('_','-'),str(v)]
            pki=step('build-disposable-authority',lambda:build_pki(toolchain,output/'pki-build',rid))
            step('new-disk-full-lifecycle',lambda:command('windows-install',args,env,timeout=9000))
            step('windows-pki-migration-and-crash-recovery',lambda:windows_checks(output/'windows',output/'builds/first/artifacts'/rid,pki,output))
        if extended_manifest:
            step('extended-runtime-acceptance',lambda:command('extended-runtime',[python,str(ROOT/'scripts/qualification/extended_acceptance.py'),'--manifest',str(Path(extended_manifest).resolve()),'--output',str(output/'extended')],env,timeout=14400))
        step('hygiene',lambda:command('hygiene',[python,str(ROOT/'scripts/verify_hygiene.py')],env))
        report['status']='passed'
    except BaseException as e:report.update(status='failed',error_type=type(e).__name__);raise
    finally:
        # An interrupted provisioning command can leave its newly owned VM up.
        try:
            folder=output/'windows'
            if (folder/'config.json').exists():
                h=owned_hypervisor(folder)
                pid=owned_tpm_pid(h.spec) if h.is_running()[0] and h.spec.tpm_state_dir else None
                if h.is_running()[0]:h.stop(timeout_sec=300)
                h._stop_tpm();wait_tpm_exit(pid)
                if h.spec.pid_file.exists():raise RuntimeError('VM cleanup incomplete')
                report['cleanup']='passed'
        except BaseException as e:report.update(status='failed',cleanup='failed',cleanup_error_type=type(e).__name__);raise
        finally:
            drift=None
            if report['status']=='passed':
                try:
                    if cohort_sources()!=report['sources']:raise RuntimeError('Source cohort changed during acceptance')
                except Exception as e:drift=e;report.update(status='failed',error_type=type(e).__name__)
            files=report_inventory(output)
            atomic_json(output/'inventory.json',{'files':files});report['inventory_sha256']=release.digest(output/'inventory.json');persist()
            if drift:raise drift
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--host-only',action='store_true');p.add_argument('--extended-manifest',type=Path);a=p.parse_args()
    print(json.dumps(run(a.manifest,a.output,a.host_only,a.extended_manifest),indent=2))
