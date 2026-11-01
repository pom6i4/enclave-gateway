#!/usr/bin/env python3
"""Provision only a newly created Windows lab through the public CLI."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.provision.builder import ProvisionOptions
from enclave_gateway.hypervisor.state import atomic_json


def seed_iso(seed,destination,volume='EGWSEED'):
    if destination.exists():raise FileExistsError('Seed media already exists')
    if sys.platform=='darwin':command=['hdiutil','makehybrid','-iso','-joliet','-default-volume-name',volume,'-o',str(destination),str(seed)]
    elif shutil.which('xorriso'):command=['xorriso','-as','mkisofs','-J','-R','-V',volume,'-o',str(destination),str(seed)]
    elif shutil.which('genisoimage'):command=['genisoimage','-J','-R','-V',volume,'-o',str(destination),str(seed)]
    else:raise FileNotFoundError('Install an ISO mastering tool (hdiutil, xorriso or genisoimage)')
    subprocess.run(command,check=True,capture_output=True,timeout=120);destination.chmod(0o600)


def verify_guest_security(agent,*,secure_boot=False,tpm=False):
    """Read back requested firmware/TPM properties from the disposable guest."""
    source=Path(__file__).with_name('windows_security.ps1').read_text(encoding='utf-8')
    script='& {\n'+source+'\n} -SecureBoot:'+('$true' if secure_boot else '$false')+' -Tpm:'+('$true' if tpm else '$false')
    result=agent.exec_powershell(script,timeout_sec=120)
    if result.exit_code:raise RuntimeError('Guest security readback failed')
    value=json.loads(result.stdout)
    if not isinstance(value,dict) or type(value.get('query_revision')) is not int or value['query_revision']!=2 or type(value.get('attempts')) is not int or value['attempts']!=1:
        raise RuntimeError('Invalid guest security evidence')
    if secure_boot and value.get('secure_boot') is not True:raise RuntimeError('Guest Secure Boot is not enabled')
    if tpm and (value.get('tpm_present') is not True or value.get('tpm_ready') is not True):
        raise RuntimeError('Guest software TPM is not ready')
    return value


def run(args):
    folder=args.output.resolve()
    if folder.exists() and any(folder.iterdir()):raise FileExistsError('Use a new disposable lab directory')
    folder.mkdir(parents=True,exist_ok=True,mode=0o700);folder.chmod(0o700)
    atomic_json(folder/'supervisor.json',{'pid':os.getpid()})
    agent_sha256=hashlib.sha256(args.guest_agent_msi.read_bytes()).hexdigest()
    completion_mode=getattr(args,'completion_mode','StartupTask')
    opts=ProvisionOptions(arch=args.arch,admin_user='EGWLab',guest_agent_sha256=agent_sha256,completion_mode=completion_mode)
    atomic_json(folder/'credentials.json',{'username':opts.admin_user,'password':opts.admin_password})
    runtime=Path(tempfile.mkdtemp(prefix='egw-provision-',dir='/tmp' if os.name!='nt' else None))
    config={'profile':'isolated-provision','appliance':{'name':'egw-lab-'+hashlib.sha256(str(folder).encode()).hexdigest()[:6],'arch':args.arch,'hypervisor':args.accelerator,
        'cpus':args.cpus,'memory_mb':args.memory_mb,'disk_path':str(folder/'disk.qcow2'),'efi_vars_path':str(folder/'efi_vars.fd'),
        'efi_code_path':str(args.firmware_code.resolve()),'efi_vars_template_path':str(args.firmware_vars.resolve()),
        'runtime_dir':str(runtime),'network_restrict':True,'display_device':'virtio-gpu-pci' if args.arch=='arm64' else 'ramfb',
        'tpm_state_dir':str(folder/'tpm') if args.tpm else '', 'secure_boot':args.secure_boot,
        'rdp_forward_port':args.port_base,'vm_rdp_forward_port':args.port_base+1,'socks5_port':args.port_base+2,'vnc_display':args.vnc_display},
        'provider':{'type':'custom','installer_path':'','dst_key_path':''},'bastion':{'enabled':False}}
    atomic_json(folder/'config.json',config)
    cfg=EnclaveConfig.from_dict(config)
    environment={**os.environ,'PYTHONPATH':str(ROOT/'src'),'ENCLAVE_APPLIANCE_PASSWORD':opts.admin_password}
    virtio=args.virtio_iso
    if args.virtio_directory:
        media=folder/'driver-media';media.mkdir(mode=0o700)
        drivers=args.virtio_directory/'Drivers' if (args.virtio_directory/'Drivers').is_dir() else args.virtio_directory
        if not all((drivers/name).is_dir() for name in ('NetKVM','vioserial')):raise ValueError('Matching VirtIO driver folders are required')
        shutil.copytree(drivers,media/'Drivers')
        shutil.copyfile(args.guest_agent_msi,media/args.guest_agent_msi.name)
        virtio=folder/'drivers.iso';seed_iso(media,virtio,'EGWDRIVERS')
    base=[sys.executable,'-m','enclave_gateway.cli','-c',str(folder/'config.json'),'--state-dir',str(folder/'controller'),
          'init','--arch',args.arch,'--admin-user',opts.admin_user,'--disk-size-gb','32','--output-dir',str(folder/'seed'),
          '--win-iso',str(args.windows_iso.resolve()),'--virtio-iso',str(virtio.resolve()),'--guest-agent-sha256',agent_sha256,'--completion-mode',completion_mode]
    def cli(arguments,label):
        result=subprocess.run(base+arguments,cwd=ROOT,env=environment,capture_output=True,timeout=180)
        (folder/(label+'.out.log')).write_bytes(result.stdout);(folder/(label+'.err.log')).write_bytes(result.stderr)
        if result.returncode:raise RuntimeError('Public CLI '+label+' failed; inspect its private log')
    report={'status':'running','scope':'new-isolated-public-cli-provision','actions':'not_used','client_environment':'not_used','guest_agent_sha256':agent_sha256}
    atomic_json(folder/'result.json',report)
    try:
        cli(['--create-disk'],'prepare')
        shutil.copyfile(args.guest_agent_msi,folder/'seed'/args.guest_agent_msi.name)
        seed_iso(folder/'seed',folder/'seed.iso')
        cli(['--seed-iso',str(folder/'seed.iso'),'--launch-installer','--detach-installer'],'launch')
        agent=QgaClient(cfg.appliance.qga_socket);deadline=time.monotonic()+args.deadline_sec
        probe=r"""$s=Get-ItemProperty 'HKLM:\SYSTEM\Setup';$m=$null
if(Test-Path 'C:\EnclaveGateway\provision-machine.json'){$m=Get-Content 'C:\EnclaveGateway\provision-machine.json' -Raw -Encoding UTF8|ConvertFrom-Json}
$complete=($m.revision -eq 2 -and $m.status -eq 'machine_ready' -and $m.completion_mode -eq '__COMPLETION_MODE__')
if($m.completion_mode -eq 'StartupTask'){$complete=($complete -and $m.completion_task_removed -eq $true -and -not (Get-ScheduledTask -TaskName EnclaveGatewayMachinePreparation -ErrorAction SilentlyContinue))}
@{ready=(-not ($s.OOBEInProgress -or $s.SystemSetupInProgress -or $s.SetupType));machine=$complete}|ConvertTo-Json -Compress""".replace('__COMPLETION_MODE__',completion_mode)
        while time.monotonic()<deadline:
            try:
                with agent._connect_synced(5) as(s,r):agent._request(s,r,'guest-ping')
                status=agent.exec_powershell(probe,timeout_sec=90)
                value=json.loads(status.stdout) if not status.exit_code else {}
                if value.get('ready') and value.get('machine'):break
            except (OSError,ValueError,RuntimeError):pass
            report['elapsed_sec']=round(args.deadline_sec-max(0,deadline-time.monotonic()),1)
            atomic_json(folder/'result.json',report)
            time.sleep(5)
        else:raise TimeoutError('Windows installation readiness deadline expired')
        report.update(setup='complete',phase='post-install')
        atomic_json(folder/'result.json',report)
        post=(folder/'seed/post_install.ps1').read_text(encoding='utf-8')
        result=agent.exec_powershell(post,timeout_sec=120)
        if result.exit_code:raise RuntimeError('Machine post-install failed')
        cleanup=r"""
$reg='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$v=Get-ItemProperty $reg
if($v.AutoAdminLogon -eq '1' -or $v.PSObject.Properties.Name -contains 'DefaultPassword'){throw 'Unexpected autologon credential'}
foreach($p in @('C:\Windows\Panther\unattend.xml','C:\Windows\Panther\Unattend\unattend.xml','C:\Autounattend.xml')){
 if(Test-Path $p){if((Get-Content $p -Raw) -notmatch 'EGWLab'){throw 'Unrecognized answer file'};Remove-Item -LiteralPath $p -Force}
}
Get-Content C:\EnclaveGateway\provision-machine.json -Raw
"""
        result=agent.exec_powershell(cleanup,timeout_sec=90)
        if result.exit_code:raise RuntimeError('Setup credential cleanup failed')
        machine=json.loads(result.stdout)
        if machine.get('status')!='machine_ready':raise RuntimeError('Machine stage did not report readiness')
        if not agent.sync_guest_clock():raise RuntimeError('Guest clock sync failed')
        with agent._connect_synced(15) as(s,r):osinfo=agent._request(s,r,'guest-get-osinfo')
        report.update(machine=machine,os=osinfo,autologon='not_configured',clock_sync='passed',phase='cold-security-readback',security_attempts=1,
                      entry_points=['egw init --create-disk','egw init --launch-installer --detach-installer'])
        atomic_json(folder/'result.json',report)
        started=time.monotonic()
        try:report['guest_security']=verify_guest_security(agent,secure_boot=args.secure_boot,tpm=args.tpm)
        finally:report['security_elapsed_sec']=round(time.monotonic()-started,3)
        report.update(status='passed',phase='complete')
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__)
        raise
    finally:atomic_json(folder/'result.json',report)
    print(json.dumps(report,indent=2));return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path)
    for name in ('windows-iso','guest-agent-msi','firmware-code','firmware-vars'):p.add_argument('--'+name,required=True,type=Path)
    media=p.add_mutually_exclusive_group(required=True);media.add_argument('--virtio-iso',type=Path);media.add_argument('--virtio-directory',type=Path)
    p.add_argument('--arch',choices=['arm64','x86_64'],default='x86_64');p.add_argument('--accelerator',choices=['tcg','hvf'],default='tcg')
    p.add_argument('--cpus',type=int,default=2);p.add_argument('--memory-mb',type=int,default=4096)
    p.add_argument('--tpm',action='store_true');p.add_argument('--secure-boot',action='store_true');p.add_argument('--port-base',type=int,default=24689)
    p.add_argument('--completion-mode',choices=['StartupTask','SetupComplete'],default='StartupTask')
    p.add_argument('--vnc-display',type=int,default=106);p.add_argument('--deadline-sec',type=int,default=3600)
    a=p.parse_args()
    if not 60<=a.deadline_sec<=7200:p.error('deadline must be 60..7200 seconds')
    if not a.guest_agent_msi.name in ('qemu-ga-x86_64.msi','qemu-ga-aarch64.msi'):p.error('Use the official QGA MSI filename')
    for path in (a.windows_iso,a.guest_agent_msi,a.firmware_code,a.firmware_vars):
        if not path.is_file():p.error('Required lab media is missing')
    if a.virtio_iso and not a.virtio_iso.is_file():p.error('VirtIO ISO is missing')
    if a.virtio_directory and not a.virtio_directory.is_dir():p.error('VirtIO directory is missing')
    run(a)
