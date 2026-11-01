#!/usr/bin/env python3
"""Qualify complete offline state using the public CLI on a disposable VM."""
from __future__ import annotations
import argparse
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.hypervisor.driver import ApplianceHypervisor
from enclave_gateway.hypervisor.state import private_dir,atomic_json,inventory


def run(args):
    raw=json.loads(args.configuration.read_text(encoding='utf-8-sig'))
    if raw.get('scope')!='disposable-vm-state':raise ValueError('Explicit disposable VM scope required')
    cfg=EnclaveConfig.from_dict(raw['config'])
    if cfg.appliance.hypervisor=='direct' or not cfg.appliance.network_restrict:raise ValueError('A restricted disposable VM is required')
    folder=args.output.resolve()
    if folder.exists() and any(folder.iterdir()):raise FileExistsError('Use a new qualification directory')
    private_dir(folder);config=folder/'source-config.json';atomic_json(config,raw['config'])
    report={'status':'running','scope':raw['scope'],'checks':[],'guest_os':args.guest_os}
    token=secrets.token_hex(8);name='state_'+token;known=[config]
    guest_dir=('C:\\EGWQualification-'+token) if args.guest_os=='windows' else '/var/lib/egw-qualification-'+token
    marker=guest_dir+('\\marker' if args.guest_os=='windows' else '/marker')
    def cli(path,*arguments):
        # Explicit source bootstrap also works with Windows embedded Python,
        # whose isolated ._pth configuration can ignore PYTHONPATH.
        bootstrap="import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('enclave_gateway.cli',run_name='__main__')"
        command=[sys.executable,'-c',bootstrap,str(ROOT/'src'),'-c',str(path),'--state-dir',str(folder/'controller'),*arguments]
        result=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=900)
        with (folder/'cli.log').open('ab') as log:log.write((' '.join(arguments)+'\n').encode()+result.stdout+result.stderr)
        if result.returncode:raise RuntimeError('Public VM CLI failed; inspect the private cli.log')
        return result.stdout.decode()
    def up(path):
        cli(path,'up');current=EnclaveConfig.from_dict(json.loads(path.read_text()));agent=QgaClient(current.appliance.qga_socket)
        deadline=time.monotonic()+args.ready_timeout
        while time.monotonic()<deadline:
            try:
                with agent._connect_synced(5) as(s,r):agent._request(s,r,'guest-ping')
                if args.guest_os=='windows':
                    result=agent.exec_powershell("$s=Get-ItemProperty 'HKLM:\\SYSTEM\\Setup'; if($s.OOBEInProgress -or $s.SystemSetupInProgress -or $s.SetupType){throw 'Setup pending'}; Write-Output 'ready'",timeout_sec=30)
                else:result=agent.exec_guest('/bin/echo',['ready'],timeout_sec=15)
                if result.exit_code==0 and result.stdout.strip()=='ready':return agent
            except (OSError,ValueError,RuntimeError):pass
            time.sleep(1)
        raise TimeoutError('Disposable guest readiness deadline expired')
    def tpm(agent):
        if args.guest_os=='windows' and cfg.appliance.tpm_state_dir:
            result=agent.exec_powershell('Get-Tpm | Select TpmPresent,TpmReady,ManufacturerIdTxt | ConvertTo-Json -Compress',timeout_sec=60)
            value=json.loads(result.stdout);assert result.exit_code==0 and value['TpmPresent'] and value['TpmReady']
            return value
        return 'not_requested'
    try:
        agent=up(config)
        if args.guest_os=='windows':
            result=agent.exec_powershell("if(Test-Path '"+guest_dir+"'){throw 'Fixture path exists'}; [void][IO.Directory]::CreateDirectory('"+guest_dir+"')",timeout_sec=30)
        else:result=agent.exec_guest('/bin/mkdir',['-m','700','--',guest_dir],timeout_sec=15)
        assert result.exit_code==0
        agent.write_bytes(b'A',marker);report['initial_tpm']=tpm(agent);cli(config,'down')
        cli(config,'snapshot','--name',name);report['checks'].append('public-cli-complete-offline-capture')
        agent=up(config);assert agent.read_bytes(marker)==b'A';agent.write_bytes(b'B',marker);cli(config,'down')
        cli(config,'reset','--snapshot',name)
        store=ApplianceHypervisor(cfg.appliance).state_store();bundle,manifest=store.verify(name)
        assert {k:inventory(p) for k,p in store.targets.items()}==manifest['files']
        report['restored_resources']=sorted(store.targets);report['checks'].append('all-restored-resource-hashes-match-before-boot')
        agent=up(config);assert agent.read_bytes(marker)==b'A';assert agent.sync_guest_clock();report['restored_tpm']=tpm(agent)
        cli(config,'down');report['checks'].append('restored-windows-or-linux-boots-and-keeps-canary-A')
        if args.with_profile:
            profile_name='state_profile_'+token
            value=json.loads(cli(config,'profile','create',profile_name,'--create-disk','--output-dir',str(folder/'profile')))
            profile=Path(value['profile_config']);known.append(profile)
            agent=up(config);agent.write_bytes(b'C',marker);cli(config,'down')
            agent=up(profile);assert agent.read_bytes(marker)==b'A';assert agent.sync_guest_clock();report['profile_tpm']=tpm(agent)
            cli(profile,'down');report['checks'].append('independent-pinned-complete-profile-survives-source-mutation')
        report.update(status='passed',final_state='all-known-guests-stopped',ram_state='not_captured',hardware_attestation='not_qualified')
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        errors=[]
        for path in reversed(known):
            try:
                current=EnclaveConfig.from_dict(json.loads(path.read_text()));h=ApplianceHypervisor(current.appliance)
                if h.is_running()[0]:h.stop()
            except Exception as error:errors.append(type(error).__name__)
        if errors:report.update(status='failed',cleanup_errors=errors)
        atomic_json(folder/'result.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--configuration',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--guest-os',required=True,choices=['windows','linux']);p.add_argument('--with-profile',action='store_true')
    p.add_argument('--ready-timeout',type=int,default=300);a=p.parse_args()
    if not 30<=a.ready_timeout<=900:p.error('ready timeout must be 30..900 seconds')
    result=run(a);print(json.dumps(result,indent=2));sys.exit(0 if result['status']=='passed' else 1)
