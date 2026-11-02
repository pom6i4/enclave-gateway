"""Offline configuration and explicit deployment of immutable worker bundles."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import secrets
from enclave_gateway.operations.context import mark_dispatched
from enclave_gateway.security.quoting import ps_quote


def starter_configuration(mode='standard'):
    if mode not in ('standard','enterprise'):raise ValueError('Select standard or enterprise')
    security={'mode':mode}
    if mode=='enterprise':
        security.update(trusted_signers=[],worker_sha256='',runtime_sha256='',worker_account='',
                        bootstrap_sha256='',agent_package_dir='')
    return {'profile':'default','security':security,
            'appliance':{'hypervisor':'auto'},'provider':{'type':'custom','installer_path':'','dst_key_path':''},
            'bastion':{'enabled':True,'host':'10.0.1.10'},
            'forwards':{'app_https':'18443:app01:443'},
            'targets':{'app01':{'host':'10.0.20.11','user':'deploy','via':'bastion','ssh_key_path':'~/.ssh/id_ed25519'}}}


def configuration_summary(config):
    security=config.security
    routes={}
    for name in config.targets:
        seen=set();node=name
        while node not in ('bastion','appliance',''):
            if node in seen or node not in config.targets:raise ValueError('Invalid or circular target route: '+name)
            seen.add(node);node=config.targets[node].via.lstrip('@')
        routes[name]='appliance' if node=='appliance' else 'bastion'
        if routes[name]=='bastion' and not config.bastion.enabled:raise ValueError('Target route needs bastion.enabled: true: '+name)
    next_steps=[]
    if config.bastion.enabled:
        next_steps=['egw agents stage (or egw heal) to deliver the worker'] if security.mode!='custom' else ['Custom defaults retained: choose a named mode for agent deployment, or keep your existing manual deployment.']
        next_steps.append('Start the printed command in the Bastion RDP session')
    return {'valid':True,'security_mode':security.mode,'targets':list(config.targets),'ssh_execution_hops':routes,
            'execution_model':'owned-process-job' if security.require_process_isolation else 'in-process-runspace',
            'signed_agents':security.require_signed_agents,'signed_helpers':security.require_signed_helpers,
            'worker_attestation':security.enforce_worker_attestation,'owned_ssh_commands':security.owned_ssh_commands,
            'next_steps':next_steps+[
                          'Provision verified known_hosts and SSH keys on the executing hop',
                          'egw doctor --probe-targets'],
            'trust_boundary':'Standard trusts the local operator and RDP session; it does not isolate hostile commands.'
                if security.mode=='standard' else 'See docs/SECURITY.md for deployment requirements.'}


def agent_bundle(config):
    if not config.bastion.enabled:raise ValueError('Agent deployment requires bastion.enabled: true')
    security=config.security
    if security.mode=='custom':raise ValueError('Agent deployment requires explicit security.mode: standard or enterprise; custom configurations are unchanged.')
    signed=security.require_signed_agents or security.mode=='enterprise'
    if signed and not (security.agent_package_dir and security.worker_sha256 and security.bootstrap_sha256 and security.trusted_signers):
        raise ValueError('Signed agent deployment needs security.agent_package_dir, worker_sha256, bootstrap_sha256 and trusted_signers. See docs/SECURITY.md.')
    folder=Path(security.agent_package_dir).expanduser() if security.agent_package_dir else Path(__file__).parent/'agents'
    files={name:(folder/name).read_bytes() for name in ('bastion_worker.ps1','bastion_bootstrap.ps1')}
    hashes={name:hashlib.sha256(data).hexdigest() for name,data in files.items()}
    if signed and (hashes['bastion_worker.ps1']!=security.worker_sha256.lower() or hashes['bastion_bootstrap.ps1']!=security.bootstrap_sha256.lower()):
        raise ValueError('Approved agent package hashes do not match security pins; no files were deployed.')
    identity=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
    relative='agents\\'+identity
    remote=config.bastion.bastion_spool_dir.rstrip('\\/')+'\\'+relative+'\\bastion_bootstrap.ps1'
    command='& '+ps_quote(remote)+' -Mode '+security.mode.title()+' -SourceSpool '+ps_quote(config.bastion.bastion_spool_dir)
    command+=' -WorkerPath '+ps_quote(remote.rsplit('\\',1)[0]+'\\bastion_worker.ps1')
    command+=' -ProcessIsolation:$'+str(security.require_process_isolation).lower()
    command+=' -RequireSignedAgents:$'+str(security.require_signed_agents).lower()
    if security.require_process_isolation:command+=' -RuntimeHelper '+ps_quote(security.runtime_helper_path)
    if security.trusted_signers:command+=' -TrustedSignerThumbprintsCsv '+ps_quote(','.join(security.trusted_signers))
    return files,hashes,identity,command


def stage_agents(control,config):
    if not config.bastion.enabled:raise ValueError('Agent deployment requires bastion.enabled: true')
    files,hashes,identity,command=agent_bundle(config)
    spool=config.bastion.appliance_spool_dir.rstrip('\\/')
    root=spool+'\\agents';target=root+'\\'+identity;temporary=root+'\\.incoming-'+secrets.token_hex(16)
    def execute(script):
        mark_dispatched();result=control.exec_powershell(script,timeout_sec=60)
        if result.exit_code:raise RuntimeError('Agent staging failed; existing bundles were preserved. '+result.stderr[-1000:])
        return result
    guard=r'''$ErrorActionPreference='Stop'
function Assert-LocalDirectory([string]$path){
 if(-not [IO.Path]::IsPathRooted($path) -or $path.StartsWith('\\')){throw 'Use a local absolute Appliance spool path'}
 $p=New-Object IO.DirectoryInfo($path)
 while($p){if($p.Exists -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse-point agent directory rejected'};$p=$p.Parent}
}
'''
    execute(guard+"Assert-LocalDirectory "+ps_quote(root)+";[void][IO.Directory]::CreateDirectory("+ps_quote(root)+")\n"+
            '$lock='+ps_quote(root+'\\.bundle-lease')+r'''
if(-not (Test-Path -LiteralPath $lock)){
 try{$f=[IO.File]::Open($lock,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read);$f.Dispose()}
 catch{if(-not (Test-Path -LiteralPath $lock)){throw}}
}
if((Get-Item -LiteralPath $lock -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked bundle lease rejected'}
'''+ '[void][IO.Directory]::CreateDirectory('+ps_quote(temporary)+')')
    try:
        for name,data in files.items():control.write_bytes(data,temporary+'\\'+name)
        expected=json.dumps(hashes,separators=(',',':'))
        checks=guard+'$stage='+ps_quote(temporary)+';$target='+ps_quote(target)+';$expected='+ps_quote(expected)+r'''|ConvertFrom-Json
Assert-LocalDirectory $stage;Assert-LocalDirectory $target
function Assert-Bundle([string]$folder){
 foreach($entry in $expected.PSObject.Properties){
  $p=Join-Path $folder $entry.Name;$f=Get-Item -LiteralPath $p
  if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked agent rejected'}
  if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value){throw 'Agent content mismatch'}
'''
        if config.security.require_signed_agents:
            trusted=','.join(ps_quote(t.replace(' ','').upper()) for t in config.security.trusted_signers)
            checks+="$s=Get-AuthenticodeSignature -LiteralPath $p;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -notin @("+trusted+")){throw 'Untrusted agent publisher'}\n"
        checks+='}}\n$lease=[IO.File]::Open('+ps_quote(root+'\\.bundle-lease')+',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\ntry {\nAssert-Bundle $stage\n'
        if b'# EGW_BUNDLE_LEASE_V1' in files['bastion_worker.ps1']:
            receipt=json.dumps({'protocol':1,'bundle_sha256':identity,'files':hashes},sort_keys=True)
            checks+='[IO.File]::WriteAllText((Join-Path $stage \'bundle.json\'),'+ps_quote(receipt)+',(New-Object Text.UTF8Encoding($false)))\n'
        checks+='if(Test-Path -LiteralPath $target){Assert-Bundle $target}else{[IO.Directory]::Move($stage,$target)}\n}finally{$lease.Dispose()}\n'
        execute(checks)
    finally:
        # Only the unique incoming directory belongs to this invocation.
        execute(guard+'Assert-LocalDirectory '+ps_quote(temporary)+';if(Test-Path -LiteralPath '+ps_quote(temporary)+'){Remove-Item -LiteralPath '+ps_quote(temporary)+' -Recurse -Force}')
    return {'status':'staged','bundle_sha256':identity,'appliance_directory':target,
            'files':hashes,'start_command':command,'worker_started':False,
            'next_step':'Run start_command inside the Bastion RDP session. Then run egw doctor --probe-targets.'}
