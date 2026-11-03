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
    from enclave_gateway.config import ApplianceSpec
    app=ApplianceSpec()
    return {'profile':'default','security':security,
            'appliance':{name:getattr(app,name) for name in ('name','hypervisor','runtime_dir','disk_path','efi_vars_path','qga_socket_path','qmp_socket_path','pid_file_path')},
            'provider':{'type':'custom','installer_path':'','dst_key_path':'','probe_host':'','probe_port':0},
            'bastion':{'enabled':True,'host':'10.0.1.10'},
            'forwards':{'app_https':'18443:app01:443'},
            'targets':{'app01':{'host':'10.0.20.11','user':'deploy','via':'bastion','ssh_key_path':'~/.ssh/id_ed25519'}}}


def starter_yaml(mode='standard'):
    notes={'appliance':'Existing VM: name is the QMP identity, control paths can use any verified filenames.',
           'runtime_dir':'Keep UNIX control socket paths short and private.',
           'qga_socket_path':'Optional existing QGA socket; empty uses runtime_dir/name-qga.sock.',
           'qmp_socket_path':'Optional existing QMP socket; empty uses runtime_dir/name-qmp.sock.',
           'pid_file_path':'Optional existing PID file; empty uses runtime_dir/name-qemu.pid.',
           'provider':'Use an existing approved VPN connection; no automatic key import.',
           'probe_host':'Empty follows bastion.host; set an explicit address for a different network probe.',
           'probe_port':'Zero follows bastion.port.',
           'ssh_key_path':'Private key on the executing SSH hop, not on Host.'}
    def emit(mapping,level=0):
        lines=[];pad='  '*level
        for key,value in mapping.items():
            if key in notes:lines.append(pad+'# '+notes[key])
            if isinstance(value,dict):
                lines.append(pad+key+':');lines.extend(emit(value,level+1))
            else:lines.append(pad+key+': '+json.dumps(value,ensure_ascii=False))
        return lines
    return '# Edit topology, then run egw config check and egw doctor --preflight.\n'+'\n'.join(emit(starter_configuration(mode)))+'\n'


def key_only_authentication(config,node):
    return config.security.mode=='standard' and bool(node.ssh_key_path) and not config.security.askpass_helper_path


def authentication_warnings(config):
    result=[]
    for name,node in config.targets.items():
        if node.password_env and not config.security.askpass_helper_path:
            key=key_only_authentication(config,node)
            result.append({'code':'ssh_password_helper_missing','target':name,'severity':'warning' if key else 'error',
                           'authentication':'key-only' if key else 'password-helper-required',
                           'message':('Backup password_env is ignored; SSH uses the configured key with BatchMode=yes. ' if key else 'Password authentication is not configured for execution. ')+
                           'Configure security.askpass_helper_path with an approved native helper for SSH password authentication or ssh-copy-id password bootstrap. sudo_password_env is independent.'})
    return result


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
    return {'configuration_file':str(config.source_path) if config.source_path else None,
            'warnings':authentication_warnings(config),
            'ssh_authentication':{name:('key-only' if key_only_authentication(config,node) else 'password-helper' if node.password_env else 'key-or-agent') for name,node in config.targets.items()},
            'provider_type':config.provider.type,'provider_lifecycle_configured':bool(config.provider.lifecycle_manifest),
            'spool_protocol':config.bastion.spool_protocol,'valid':True,'security_mode':security.mode,'targets':list(config.targets),'ssh_execution_hops':routes,
            'execution_model':'owned-process-job' if security.require_process_isolation else 'in-process-runspace',
            'signed_agents':security.require_signed_agents,'signed_helpers':security.require_signed_helpers,
            'worker_attestation':security.enforce_worker_attestation,'owned_ssh_commands':security.owned_ssh_commands,
            'next_steps':next_steps+[
                          'Provision verified known_hosts and SSH keys on the executing hop',
                          'egw doctor --probe-targets'],
            'trust_boundary':'Standard trusts the local operator and RDP session; it does not isolate hostile commands.'
                if security.mode=='standard' else 'See docs/SECURITY.md for deployment requirements.'}


def agent_bundle(config, *, execution_policy='',migrate_legacy_state=False,persist_autostart=False):
    if not config.bastion.enabled:raise ValueError('Agent deployment requires bastion.enabled: true')
    security=config.security
    if execution_policy and (execution_policy!='RemoteSigned' or security.mode!='standard' or security.require_signed_agents):raise ValueError('Process RemoteSigned is an explicit Standard-only option; signed modes retain endpoint policy')
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
    command="& (Join-Path $egwLocal 'bastion_bootstrap.ps1') -Mode "+security.mode.title()+' -SourceSpool '+ps_quote(config.bastion.bastion_spool_dir)
    command+=" -WorkerPath (Join-Path $egwLocal 'bastion_worker.ps1')"
    command+=' -SpoolProtocol '+config.bastion.spool_protocol.title()
    command+=' -ProcessIsolation:$'+str(security.require_process_isolation).lower()
    command+=' -RequireSignedAgents:$'+str(security.require_signed_agents).lower()
    if security.require_process_isolation:command+=' -RuntimeHelper '+ps_quote(security.runtime_helper_path)
    if security.trusted_signers:command+=' -TrustedSignerThumbprintsCsv '+ps_quote(','.join(security.trusted_signers))
    if migrate_legacy_state:command+=' -MigrateLegacyState'
    if persist_autostart:command+=' -RegisterAutostart'
    command=_local_bootstrap_prefix(remote.rsplit('\\',1)[0],identity,hashes,execution_policy)+command
    return files,hashes,identity,command


def stage_agents(control,config,*,execution_policy='',migrate_legacy_state=False,persist_autostart=False):
    if not config.bastion.enabled:raise ValueError('Agent deployment requires bastion.enabled: true')
    files,hashes,identity,command=agent_bundle(config,execution_policy=execution_policy,migrate_legacy_state=migrate_legacy_state,persist_autostart=persist_autostart)
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


def _local_bootstrap_prefix(source,identity,hashes,execution_policy):
    policy=""
    if execution_policy:
        policy="if((Get-ExecutionPolicy) -eq 'AllSigned'){throw 'AllSigned requires an approved signed package'};Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force;"
    script=r"""$ErrorActionPreference='Stop';POLICY
if((Get-ExecutionPolicy) -in @('Restricted','Undefined')){throw 'Script execution is disabled. Review Get-ExecutionPolicy -List; approve signed agents or explicitly request agents command --execution-policy RemoteSigned in Standard mode'}
$egwRoot=Join-Path $env:LOCALAPPDATA 'EnclaveGateway\agents';$egwLocal=Join-Path $egwRoot 'IDENTITY';$egwSource=SOURCE
$p=New-Object IO.DirectoryInfo($egwRoot);while($p){if($p.Exists -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked local agent path rejected'};$p=$p.Parent}
[void][IO.Directory]::CreateDirectory($egwRoot)
$lock=Join-Path $egwRoot '.bundle-lease'
if(-not [IO.File]::Exists($lock)){try{$f=[IO.File]::Open($lock,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$f.Dispose()}catch{if(-not [IO.File]::Exists($lock)){throw}}}
$egwIncoming=Join-Path $egwRoot ('.incoming-'+[Guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($egwIncoming)
$egwHashes=HASHES|ConvertFrom-Json
$egwSourceLease=$null
try{
 $egwLeasePath=Join-Path ((New-Object IO.DirectoryInfo($egwSource)).Parent.FullName) '.bundle-lease'
 if([IO.File]::GetAttributes($egwLeasePath) -band [IO.FileAttributes]::ReparsePoint){throw 'Linked source lease rejected'}
 $egwSourceLease=[IO.File]::Open($egwLeasePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 foreach($entry in $egwHashes.PSObject.Properties){[IO.File]::Copy((Join-Path $egwSource $entry.Name),(Join-Path $egwIncoming $entry.Name),$false)}
 foreach($folder in @($egwIncoming,$egwLocal)){
  if(-not [IO.Directory]::Exists($folder)){continue}
  if([IO.File]::GetAttributes($folder) -band [IO.FileAttributes]::ReparsePoint){throw 'Linked local generation rejected'}
  foreach($entry in $egwHashes.PSObject.Properties){
   $path=Join-Path $folder $entry.Name
   if([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint){throw 'Linked local script rejected'}
   if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value){throw 'Local agent content mismatch'}
  }
 }
 if(-not [IO.Directory]::Exists($egwLocal)){[IO.Directory]::Move($egwIncoming,$egwLocal)}
}finally{try{if([IO.Directory]::Exists($egwIncoming)){[IO.Directory]::Delete($egwIncoming,$true)}}finally{if($egwSourceLease){$egwSourceLease.Dispose()}}}
"""
    return script.replace('POLICY',policy).replace('IDENTITY',identity).replace('SOURCE',ps_quote(source)).replace('HASHES',ps_quote(json.dumps(hashes,sort_keys=True)))+'\n'
