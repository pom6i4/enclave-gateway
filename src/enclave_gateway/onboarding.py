"""Offline configuration and explicit deployment of immutable worker bundles."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PureWindowsPath
import secrets
from enclave_gateway.operations.context import mark_dispatched
from enclave_gateway.security.quoting import ps_quote


def unregister_autostart_command():
    """Print a local recovery action that needs neither worker nor RDP spool.

    Remove only a recognized registration. Preserve running processes and all
    files, including journals and quarantine evidence, for administrator review.
    """
    return r'''$ErrorActionPreference='Stop'
$starter=Join-Path $env:LOCALAPPDATA 'EnclaveGateway\start_worker.ps1'
$key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run',$true)
try {
 if($key){
  $value=$key.GetValue('EnclaveGatewayWorker',$null)
  if($null -ne $value){
   $quoted='"'+$starter+'"'
   if($value -isnot [string] -or -not $value.Contains($quoted) -or $value -notmatch '(?i)\s-File\s' -or $value -notmatch '\s-UseAutostartConfiguration(?:\s|$)'){throw 'Unrecognized worker startup value; preserve it for administrator review'}
   $key.DeleteValue('EnclaveGatewayWorker',$false)
   if($null -ne $key.GetValue('EnclaveGatewayWorker',$null)){throw 'Autostart removal readback failed'}
  }
 }
 Write-Output 'AUTOSTART_UNREGISTERED; running processes and durable state were preserved'
} finally {if($key){$key.Dispose()}}'''


def starter_configuration(mode='standard',route='rdp_vfs'):
    if mode not in ('standard','enterprise'):raise ValueError('Select standard or enterprise')
    if route not in ('ssh','rdp_vfs'):raise ValueError('Select ssh or rdp_vfs')
    security={'mode':mode}
    if mode=='enterprise':
        security.update(trusted_signers=[],worker_sha256='',runtime_sha256='',worker_account='',
                        bootstrap_sha256='',agent_package_dir='')
    from enclave_gateway.config import ApplianceSpec
    app=ApplianceSpec()
    result={'profile':'default','security':security,
            'appliance':{name:getattr(app,name) for name in ('name','hypervisor','runtime_dir','disk_path','efi_vars_path','qga_socket_path','qmp_socket_path','pid_file_path','attach_only','mtu')},
            'provider':{'type':'custom','installer_path':'','dst_key_path':'','probe_host':'','probe_port':0},
            'bastion':{'enabled':True,'host':'10.0.1.10'},
            'forwards':{'app_https':'18443:app01:443'},
            'targets':{'app01':{'host':'10.0.20.11','user':'deploy','via':'bastion','ssh_key_path':'~/.ssh/id_ed25519'}}}
    if route=='ssh':
        result['bastion']={'enabled':False}
        result['provider'].update(probe_host='10.0.20.11',probe_port=22)
        result['forwards']={}
        result['targets']['app01'].update(via='appliance',ssh_known_hosts_path='~/.ssh/known_hosts')
    return result


def starter_yaml(mode='standard',route='rdp_vfs'):
    notes={'appliance':'Existing VM: name is the QMP identity, control paths can use any verified filenames.',
           'runtime_dir':'Keep UNIX control socket paths short and private.',
           'qga_socket_path':'Optional existing QGA socket; empty uses runtime_dir/name-qga.sock.',
           'qmp_socket_path':'Optional existing QMP socket; empty uses runtime_dir/name-qmp.sock.',
           'pid_file_path':'Optional existing PID file; empty uses runtime_dir/name-qemu.pid.',
           'attach_only':'Null infers attachment from overrides; false allows managed paths directly in runtime_dir.',
           'mtu':'IPv4 MTU applied by heal on the managed VPN and Ethernet adapters.',
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
    return '# Edit topology, then run egw config check and egw doctor --preflight.\n'+'\n'.join(emit(starter_configuration(mode,route)))+'\n'


def key_only_authentication(config,node):
    return config.bastion.execution_profile=='structured_only' or (config.security.mode=='standard' and bool(node.ssh_key_path) and not config.security.askpass_helper_path)


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
    from enclave_gateway.routing import route_summary
    resolved=route_summary(config)
    routes={name:value['execution_hop'] for name,value in resolved.items()}
    next_steps=[]
    if config.bastion.enabled:
        next_steps=['egw agents stage (or egw heal) to deliver the worker'] if security.mode!='custom' else ['Custom defaults retained: choose a named mode for agent deployment, or keep your existing manual deployment.']
        if config.bastion.structured_backend=='operator':
            next_steps.append('Run bastion_copy_command from the staging receipt in the Bastion RDP session')
        next_steps.append('Start the printed command in the Bastion RDP session')
    return {'configuration_file':str(config.source_path) if config.source_path else None,
            'appliance_mtu':config.appliance.mtu,
            'warnings':authentication_warnings(config),
            'ssh_authentication':{name:('key-only' if key_only_authentication(config,node) else 'password-helper' if node.password_env else 'key-or-agent') for name,node in config.targets.items()},
            'provider_type':config.provider.type,'provider_lifecycle_configured':bool(config.provider.lifecycle_manifest),
            'routes':resolved,'automatic_route_fallback':False,'bastion_worker_required':config.bastion.enabled,
            'spool_protocol':config.bastion.spool_protocol if config.bastion.enabled else None,'valid':True,'security_mode':security.mode,'targets':list(config.targets),'ssh_execution_hops':routes,
            'execution_profile':config.bastion.execution_profile if config.bastion.enabled else None,
            'execution_model':'agentless-ssh' if not config.bastion.enabled else ('operator-openssh' if config.bastion.structured_backend=='operator' else 'foreground-openssh') if config.bastion.execution_profile=='structured_only' else 'owned-process-job' if security.require_process_isolation else 'in-process-runspace',
            'signed_agents':security.require_signed_agents,'signed_helpers':security.require_signed_helpers,
            'worker_attestation':security.enforce_worker_attestation,'owned_ssh_commands':security.owned_ssh_commands,
            'next_steps':next_steps+[
                          'Provision verified known_hosts and SSH keys on the executing hop',
                          'egw doctor --probe-targets'],
            'trust_boundary':('Standard trusts the controller operator and configured SSH accounts; no Bastion worker is used.' if not config.bastion.enabled else 'Standard trusts the local operator and RDP session; it does not isolate hostile commands.')
                if security.mode=='standard' else 'See docs/SECURITY.md for deployment requirements.'}


def agent_bundle(config, *, execution_policy='',migrate_legacy_state=False,persist_autostart=False):
    if not config.bastion.enabled:raise ValueError('Agent deployment requires bastion.enabled: true')
    security=config.security
    if config.bastion.execution_profile=='structured_only':
        operator=config.bastion.structured_backend=='operator'
        if migrate_legacy_state or persist_autostart:
            raise ValueError('structured_only rejects startup registration and legacy journal adoption')
        if execution_policy and (execution_policy!='RemoteSigned' or not operator or security.require_signed_agents):
            raise ValueError('Process RemoteSigned requires an unsigned Standard operator adapter')
        bundled=Path(__file__).parent/'agents'
        folder=Path(security.agent_package_dir).expanduser() if security.agent_package_dir else bundled
        files={'bastion_structured.ps1':(folder/'bastion_structured.ps1').read_bytes()}
        if hashlib.sha256(files['bastion_structured.ps1']).hexdigest()!=security.worker_sha256.lower():
            raise ValueError('Structured adapter does not match the pinned worker SHA-256')
        if operator:
            files['operator_target.py']=(bundled/'operator_target.py').read_bytes()
        hashes={name:hashlib.sha256(data).hexdigest() for name,data in files.items()}
        identity=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
        script=config.bastion.bastion_spool_dir.rstrip('\\/')+'\\agents\\'+identity+'\\bastion_structured.ps1'
        if operator:
            script=str(PureWindowsPath(config.bastion.worker_policy_path).parent/'bastion_structured.ps1')
        command='& '+('$egwScript' if operator else ps_quote(script))+' -SpoolDir '+ps_quote(config.bastion.bastion_spool_dir)
        command+=' -PolicyPath '+ps_quote(config.bastion.worker_policy_path)+' -PolicySha256 '+ps_quote(config.bastion.worker_policy_sha256)
        command+=f' -LeaseSeconds {config.bastion.lease_seconds}'
        if security.require_signed_agents:
            command+=' -TrustedSignerThumbprints @('+','.join(ps_quote(v) for v in security.trusted_signers)+')'
        else:
            command+=' -RequireSignedAgents:$false'
        if operator:
            if config.bastion.operator_exec_max_sec > 15:
                command+=f' -OperatorExecMaxSec {config.bastion.operator_exec_max_sec}'
            prefix="$ErrorActionPreference='Stop';"
            if execution_policy:
                prefix+="if((Get-ExecutionPolicy) -eq 'AllSigned'){throw 'AllSigned requires an approved signed package'};Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force;"
            prefix+=_operator_path_guard()+';$egwScript='+ps_quote(script)+';Assert-EgwLocalPath $egwScript;'
            prefix+="$egwLease=[IO.File]::Open($egwScript,'Open','Read','Read');try{"
            prefix+="if((Get-FileHash -LiteralPath $egwScript -Algorithm SHA256).Hash.ToLowerInvariant() -cne "+ps_quote(hashes['bastion_structured.ps1'])+"){throw 'Local adapter hash mismatch; run bastion_copy_command'};"
            command=prefix+command+' -OperatorOpenSsh}finally{$egwLease.Dispose()}'
        return files,hashes,identity,command
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


def stage_agents(control,config,*,execution_policy='',migrate_legacy_state=False,persist_autostart=False,policy_source=None):
    if not config.bastion.enabled:raise ValueError('Agent deployment requires bastion.enabled: true')
    files,hashes,identity,command=agent_bundle(config,execution_policy=execution_policy,migrate_legacy_state=migrate_legacy_state,persist_autostart=persist_autostart)
    if policy_source is not None:
        if config.bastion.structured_backend != 'operator':
            raise ValueError('--policy-source requires the operator OpenSSH backend')
        with Path(policy_source).expanduser().open('rb') as source:
            policy = source.read(65537)
        digest = hashlib.sha256(policy).hexdigest()
        if not 0 < len(policy) <= 65536 or digest != config.bastion.worker_policy_sha256:
            raise ValueError('Policy source exceeds 64 KiB or does not match the approved policy SHA-256')
        files['worker-policy.json'] = policy
        hashes['worker-policy.json'] = digest
        identity = hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
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
            checks+="if($entry.Name.EndsWith('.ps1')){$s=Get-AuthenticodeSignature -LiteralPath $p;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -notin @("+trusted+")){throw 'Untrusted agent publisher'}}\n"
        checks+='}}\n$lease=[IO.File]::Open('+ps_quote(root+'\\.bundle-lease')+',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\ntry {\nAssert-Bundle $stage\n'
        if b'# EGW_BUNDLE_LEASE_V1' in files.get('bastion_worker.ps1',b''):
            receipt=json.dumps({'protocol':1,'bundle_sha256':identity,'files':hashes},sort_keys=True)
            checks+='[IO.File]::WriteAllText((Join-Path $stage \'bundle.json\'),'+ps_quote(receipt)+',(New-Object Text.UTF8Encoding($false)))\n'
        checks+='if(Test-Path -LiteralPath $target){Assert-Bundle $target}else{[IO.Directory]::Move($stage,$target)}\n}finally{$lease.Dispose()}\n'
        execute(checks)
    finally:
        # Only the unique incoming directory belongs to this invocation.
        execute(guard+'Assert-LocalDirectory '+ps_quote(temporary)+';if(Test-Path -LiteralPath '+ps_quote(temporary)+'){Remove-Item -LiteralPath '+ps_quote(temporary)+' -Recurse -Force}')
    receipt={'status':'staged','bundle_sha256':identity,'appliance_directory':target,
            'files':hashes,'start_command':command,'worker_started':False,
            'next_step':'Run start_command inside the Bastion RDP session. Then run egw doctor --probe-targets.'}
    if config.bastion.structured_backend=='operator':
        receipt.update(
            bastion_copy_command=_operator_copy_command(config.bastion, identity, hashes, install_policy=policy_source is not None),
            target_authorized_keys_prefix='command="/usr/bin/python3 /path/to/operator_target.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty',
            next_step='Provision the approved worker policy and target helper. Run bastion_copy_command and then start_command inside the Bastion RDP session.',
        )
    return receipt


def _operator_path_guard():
    return (r"function Assert-EgwLocalPath([string]$path){if($path -notmatch '^[a-zA-Z]:[\\/]'){throw 'Use an absolute local operator path'};"
            r"$p=if([IO.Directory]::Exists($path)){[IO.DirectoryInfo]::new($path)}else{[IO.FileInfo]::new($path)};"
            r"while($p){if($p.Exists -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked operator path rejected'};"
            r"$p=if($p -is [IO.FileInfo]){$p.Directory}else{$p.Parent}}}")


def _operator_copy_command(bastion,identity,hashes,*,install_policy=False):
    source=bastion.bastion_spool_dir.rstrip('\\/')+'\\agents\\'+identity+'\\bastion_structured.ps1'
    install = ''
    if install_policy:
        install = (
            "if(-not [IO.File]::Exists($egwPolicy)){"
            "$egwParent=[IO.Path]::GetDirectoryName($egwPolicy);"
            "Assert-EgwLocalPath $egwParent;[void][IO.Directory]::CreateDirectory($egwParent);"
            "$egwSid=[Security.Principal.WindowsIdentity]::GetCurrent().User;"
            "$egwAllowed=@($egwSid.Value,'S-1-5-18','S-1-5-32-544');"
            "$egwParentAcl=Get-Acl -LiteralPath $egwParent;"
            "if($egwParentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin $egwAllowed){throw 'Use a private policy directory'};"
            "foreach($rule in $egwParentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){"
            "if($rule.AccessControlType -eq 'Allow' -and ([int]$rule.FileSystemRights -band 852310) -ne 0 -and "
            "$rule.IdentityReference.Value -cnotin $egwAllowed){throw 'Use a private policy directory'}};"
            "$egwTemp=$egwPolicy+'.'+[Guid]::NewGuid().ToString('N')+'.tmp';try{"
            "[IO.File]::Copy("+ps_quote(str(PureWindowsPath(source).with_name('worker-policy.json')))+",$egwTemp,$false);"
            "if((Get-FileHash -LiteralPath $egwTemp -Algorithm SHA256).Hash.ToLowerInvariant() -cne "+
            ps_quote(bastion.worker_policy_sha256)+"){throw 'Approved worker policy hash mismatch'};"
            "$egwPolicyData=[IO.File]::ReadAllText($egwTemp)|ConvertFrom-Json;"
            "if($egwPolicyData.revision -ne 1 -or $egwPolicyData.owner_sid -cne $egwSid.Value){throw 'Invalid policy or worker SID'};"
            "$egwAcl=[Security.AccessControl.FileSecurity]::new();$egwAcl.SetOwner($egwSid);"
            "$egwAcl.SetAccessRuleProtection($true,$false);"
            "foreach($id in $egwAllowed){"
            "$egwAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
            "[Security.Principal.SecurityIdentifier]::new($id),'FullControl','Allow'))};"
            "if($PSVersionTable.PSEdition -eq 'Desktop'){[IO.File]::SetAccessControl($egwTemp,$egwAcl)}"
            "else{[IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($egwTemp),$egwAcl)};"
            "Assert-EgwLocalPath $egwPolicy;[IO.File]::Move($egwTemp,$egwPolicy)"
            "}finally{[IO.File]::Delete($egwTemp)}};"
        )
    return (
        "$ErrorActionPreference='Stop';"+_operator_path_guard()+";$egwPolicy="+ps_quote(bastion.worker_policy_path)+
        ";Assert-EgwLocalPath $egwPolicy;"+install+"$egwPolicyLease=[IO.File]::Open($egwPolicy,'Open','Read','Read');try{"
        "if((Get-FileHash -LiteralPath $egwPolicy -Algorithm SHA256).Hash.ToLowerInvariant() -cne "+
        ps_quote(bastion.worker_policy_sha256)+"){throw 'Approved worker policy hash mismatch'};"
        "$egwSettings=[IO.File]::ReadAllText($egwPolicy)|ConvertFrom-Json;"
        "if($egwSettings.revision -ne 1 -or $egwSettings.owner_sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'Invalid policy or worker SID'};"
        "$egwState=$egwSettings.operator_state_dir;Assert-EgwLocalPath $egwState;"
        "[void][IO.Directory]::CreateDirectory($egwState);"
        "$egwRoot=[IO.Path]::GetDirectoryName($egwPolicy);"
        "function Copy-EgwPinned([string]$name,[string]$digest,[string]$label){"
        "$egwDestination=Join-Path $egwRoot $name;"
        "Assert-EgwLocalPath $egwDestination;$egwTemp=$egwDestination+'.'+[Guid]::NewGuid().ToString('N')+'.tmp';try{"
        "[IO.File]::Copy((Join-Path "+ps_quote(str(PureWindowsPath(source).parent))+" $name),$egwTemp,$false);"
        "if((Get-FileHash -LiteralPath $egwTemp -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest){throw ('Staged '+$label+' hash mismatch')};"
        "if([IO.File]::Exists($egwDestination)){[IO.File]::Replace($egwTemp,$egwDestination,[NullString]::Value)}"
        "else{[IO.File]::Move($egwTemp,$egwDestination)}"
        "}finally{[IO.File]::Delete($egwTemp)}};"
        "Copy-EgwPinned 'bastion_structured.ps1' "+ps_quote(hashes['bastion_structured.ps1'])+" 'adapter';"
        "Copy-EgwPinned 'operator_target.py' "+ps_quote(hashes['operator_target.py'])+" 'target helper'"
        "}finally{$egwPolicyLease.Dispose()}"
    )


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
