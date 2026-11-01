"""Evidence and lifecycle operations scoped to one newly created Windows lab."""
from __future__ import annotations
import hashlib
import json
import shlex
import subprocess
import time
from pathlib import Path
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.hypervisor.driver import ApplianceHypervisor,process_running
from enclave_gateway.hypervisor.state import atomic_json

ROOT=Path(__file__).resolve().parents[2]


def digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):value.update(chunk)
    return value.hexdigest()


def blank_disk(folder,args):
    disk=folder/'disk.qcow2'
    info=json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(disk)],timeout=30))
    extents=json.loads(subprocess.check_output(['qemu-img','map','--output=json',str(disk)],timeout=30))
    if (info.get('format')!='qcow2' or info.get('virtual-size')!=32*1024**3 or info.get('backing-filename')
            or not extents or any(row.get('data') is not False or row.get('zero') is not True for row in extents)):
        raise RuntimeError('Disk is not a blank standalone 32 GiB qcow2 image')
    source=ROOT/'src/enclave_gateway/agents/machine_prepare.ps1'
    source_hash=digest(source)
    if digest(folder/'seed/machine_prepare.ps1')!=source_hash:raise RuntimeError('Seed preparation source mismatch')
    inventory={str(p.relative_to(ROOT)):digest(p) for top in ('src','scripts','native') for p in (ROOT/top).rglob('*')
               if p.is_file() and p.suffix in ('.py','.ps1','.cs','.csproj') and not any(v in ('obj','bin','__pycache__') for v in p.parts)}
    try:head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True,timeout=15).strip()
    except (OSError,subprocess.CalledProcessError):head=None
    proof={'status':'passed','source_commit':head,'sources':inventory,'machine_prepare_sha256':source_hash,
           'source_binding':'sha256-working-tree','format':info['format'],'virtual_size':info['virtual-size'],
           'backing_file':None,'guest_data_allocated':False,'extents':extents,'completion_mode':args.completion_mode,
           'inputs_sha256':{name:digest(getattr(args,name)) for name in ('windows_iso','guest_agent_msi','firmware_code','firmware_vars')}}
    if args.virtio_iso:proof['inputs_sha256']['virtio_iso']=digest(args.virtio_iso)
    if args.virtio_directory:
        proof['driver_sources']={str(p.relative_to(args.virtio_directory)):digest(p) for p in args.virtio_directory.rglob('*') if p.is_file()}
    atomic_json(folder/'blank-disk-and-source.json',proof)
    return proof


def owned_hypervisor(folder):
    folder=folder.resolve();cfg=EnclaveConfig.load(folder/'config.json');s=cfg.appliance
    if (not s.name.startswith('egw-lab-') or not s.network_restrict or cfg.provider.type!='custom'
            or cfg.provider.installer_path or cfg.provider.dst_key_path or cfg.bastion.enabled):
        raise ValueError('Not an isolated owned Windows fixture')
    for path in (s.resolved_disk_path,s.resolved_efi_vars_path):
        if not path.is_relative_to(folder):raise ValueError('Fixture storage escapes this run')
    if s.tpm_state_dir and not Path(s.tpm_state_dir).resolve().is_relative_to(folder):raise ValueError('TPM storage escapes this run')
    h=ApplianceHypervisor(s)
    if h.is_running()[0]:
        images=h.qmp.execute('query-block').get('return',[])
        if not any(Path(row.get('inserted',{}).get('image',{}).get('filename','')).resolve()==s.resolved_disk_path for row in images):
            raise ValueError('Running disk is not owned by this fixture')
    elif s.pid_file.exists():raise RuntimeError('Ambiguous fixture identity; resources preserved')
    return h


def cleanup(folder):
    h=owned_hypervisor(folder)
    tpm_pid=owned_tpm_pid(h.spec) if h.is_running()[0] and h.spec.tpm_state_dir else None
    if h.is_running()[0]:h.stop(timeout_sec=300)
    if h.spec.pid_file.exists():raise RuntimeError('VM did not stop')
    h._stop_tpm()
    wait_tpm_exit(tpm_pid)
    atomic_json(folder/'cleanup.json',{'status':'passed','vm':'stopped','software_tpm':'stopped','storage':'retained'})


def owned_tpm_pid(spec):
    rows=subprocess.check_output(['ps','-ax','-o','pid=,command='],text=True,timeout=15)
    matches=[]
    for row in rows.splitlines():
        fields=row.strip().split(None,1)
        if len(fields)!=2:continue
        prefix=fields[1].split(None,2)
        if len(prefix)<2 or Path(prefix[0]).name!='swtpm' or prefix[1]!='socket':continue
        argv=shlex.split(fields[1])
        if (len(argv)>1 and Path(argv[0]).name=='swtpm' and argv[1]=='socket'
                and 'type=unixio,path='+str(spec.tpm_socket) in argv and 'dir='+str(Path(spec.tpm_state_dir)) in argv):
            matches.append(int(fields[0]))
    if len(matches)!=1:raise RuntimeError('Cannot establish exact owned TPM process identity')
    return matches[0]


def wait_tpm_exit(pid):
    deadline=time.monotonic()+15
    while pid and process_running(pid):
        if time.monotonic()>deadline:raise TimeoutError('Owned TPM process remains alive')
        time.sleep(.1)


def readback(agent,proof):
    script=r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$r='C:\EnclaveGateway';$m=Get-Content "$r\provision-machine.json" -Raw -Encoding UTF8|ConvertFrom-Json
if($m.revision -ne 2 -or $m.status -ne 'machine_ready' -or $m.completion_mode -ne '__MODE__'){throw 'Invalid readiness record'}
if($m.completion_mode -eq 'StartupTask' -and (-not $m.completion_task_removed -or (Get-ScheduledTask EnclaveGatewayMachinePreparation -ErrorAction SilentlyContinue))){throw 'Preparation task remains'}
if(Test-Path "$r\machine-prepare-failed.json"){throw 'Preparation failure remains'}
$phase=Get-Content "$r\machine-progress.json" -Raw|ConvertFrom-Json;if($phase.phase -ne 'complete'){throw 'Preparation incomplete'}
$setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup';if($setup.SystemSetupInProgress -or $setup.OOBEInProgress -or $setup.SetupType){throw 'Setup incomplete'}
$login=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if($login.AutoAdminLogon -eq '1' -or $login.PSObject.Properties.Name -contains 'DefaultPassword'){throw 'Autologon credential remains'}
$source=(Get-FileHash "$r\machine_prepare.ps1" -Algorithm SHA256).Hash.ToLowerInvariant()
if($source -ne '__SOURCE__'){throw 'Installed preparation source mismatch'}
@{status='passed';source_sha256=$source;boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');
 ready_hash=(Get-FileHash "$r\provision-machine.json" -Algorithm SHA256).Hash;ready_time=(Get-Item "$r\provision-machine.json").LastWriteTimeUtc.ToString('o');
 progress_hash=(Get-FileHash "$r\machine-progress.json" -Algorithm SHA256).Hash;progress_time=(Get-Item "$r\machine-progress.json").LastWriteTimeUtc.ToString('o')}|ConvertTo-Json
'''.replace('__SOURCE__',proof['machine_prepare_sha256']).replace('__MODE__',proof['completion_mode'])
    result=agent.exec_powershell(script,timeout_sec=180)
    if result.exit_code:raise RuntimeError('Installed source and readiness readback failed')
    return json.loads(result.stdout)


def powercycle(folder,proof,verify_security):
    h=owned_hypervisor(folder);s=h.spec;agent=QgaClient(s.qga_socket)
    if not h.is_running()[0]:raise RuntimeError('Installed fixture is not running')
    before=readback(agent,proof);atomic_json(folder/'final-first-boot.json',before)
    # stop() waits for the exact QEMU process to exit and stops the owned TPM.
    tpm_pid=owned_tpm_pid(s) if s.tpm_state_dir else None
    h.stop(timeout_sec=300);wait_tpm_exit(tpm_pid)
    if h.is_running()[0] or s.pid_file.exists():raise RuntimeError('Full poweroff failed')
    atomic_json(folder/'full-poweroff.json',{'status':'passed','vm':'stopped','software_tpm':'stopped'})
    h.start();deadline=time.monotonic()+420
    while True:
        try:
            with agent._connect_synced(3) as(sock,reader):agent._request(sock,reader,'guest-ping')
            break
        except (OSError,ValueError,RuntimeError):
            if time.monotonic()>=deadline:raise TimeoutError('Powercycled guest did not expose QGA')
            time.sleep(2)
    after=readback(agent,proof)
    if before['boot']==after['boot']:raise RuntimeError('Guest did not boot again')
    for key in ('source_sha256','ready_hash','ready_time','progress_hash','progress_time'):
        if before[key]!=after[key]:raise RuntimeError('Preparation reran after powercycle: '+key)
    atomic_json(folder/'final-after-powercycle.json',after)
    record={'status':'running','attempts':1,'deadline_sec':120};started=time.monotonic()
    try:
        record['evidence']=verify_security(agent,secure_boot=s.secure_boot,tpm=bool(s.tpm_state_dir));record['status']='passed'
    finally:
        record['elapsed_sec']=round(time.monotonic()-started,3);atomic_json(folder/'powercycle-security.json',record)
    result={'status':'passed','blank_disk':'verified-before-first-boot','source_binding':'sha256-working-tree',
            'first_boot':'ready','full_poweroff':'passed','next_boot':'readiness-and-progress-unchanged','security_attempts':1}
    atomic_json(folder/'lifecycle-result.json',result)
    return result
