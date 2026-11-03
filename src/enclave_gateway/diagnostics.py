"""Actionable setup diagnostics without accepting unknown SSH identities."""
from __future__ import annotations
import os
from pathlib import Path
import shutil


def diagnostic_code(detail, exit_code=None):
    """Stable guidance categories; SSH 255 cannot prove transport versus remote exit."""
    value=str(detail).lower()
    if exit_code is not None and exit_code not in (0,255):return 'remote_command_failed'
    if any(s in value for s in ('host key verification failed','remote host identification has changed','no ed25519 host key','no rsa host key')):return 'ssh_host_key'
    if 'permission denied' in value or 'publickey' in value:return 'ssh_authentication'
    if any(s in value for s in ('constrained','fulllanguage','applocker','wdac','pssecurityexception','running scripts is disabled','execution policy')):return 'endpoint_policy'
    if any(s in value for s in ('authenticode','untrusted runtime','managed runtime','credential helper')):return 'runtime_trust'
    if any(s in value for s in ('worker','spool','session_pending','vfs')):return 'worker_channel'
    if exit_code==255:return 'ssh_connection_or_remote_exit'
    return 'setup_check_failed'


def support_preview(config):
    """Collect an allow-listed, offline snapshot; never copy free-form diagnostics."""
    import hashlib
    import json
    import platform
    from enclave_gateway import __version__
    result=preflight(config)
    allowed={'qemu','appliance_disk','appliance_firmware','uefi_code','powershell','agent_package','qga_endpoint','qmp_endpoint','pid_file'}
    payload={'schema':'egw.support.v1','version':__version__,
             'platform':{'os':platform.system(),'architecture':platform.machine(),'python':platform.python_version()},
             'security':{name:getattr(config.security,name) for name in ('mode','require_signed_helpers','require_signed_agents','require_process_isolation','enforce_worker_attestation','owned_ssh_commands')},
             'topology':{'bastion_enabled':config.bastion.enabled,'target_count':len(config.targets)},
             'checks':[{'check':row['check'],'ok':bool(row['ok']),
                        'code':'ok' if row['ok'] else row['check']+'_unavailable'}
                       for row in result['checks'] if row['check'] in allowed],
             'scope':'host-only; no remote probes, configuration values, paths, addresses, commands, logs or credentials'}
    data=(json.dumps(payload,sort_keys=True,indent=2)+'\n').encode()
    return {'sha256':hashlib.sha256(data).hexdigest(),'payload':payload},data


def save_support(config,output,expected_sha256):
    import re
    preview,data=support_preview(config)
    if not re.fullmatch('[a-f0-9]{64}',expected_sha256) or preview['sha256']!=expected_sha256:
        raise ValueError('Diagnostic preview changed or digest is invalid; review diagnostics preview again before saving.')
    requested=Path(output).absolute()
    path=requested.parent.resolve(strict=True)/requested.name
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return {'saved':str(output),'sha256':preview['sha256'],'sent':False}


def remediation(detail):
    value=str(detail).lower()
    if any(s in value for s in ('host key verification failed','remote host identification has changed','no ed25519 host key','no rsa host key')):
        return 'Verify the TargetNode host-key fingerprint with its administrator, then provision known_hosts on the SSH hop (Bastion or Appliance). Do not disable StrictHostKeyChecking or delete a changed key blindly. See docs/GUIDE.md#ssh-trust.'
    if 'permission denied' in value or 'publickey' in value:
        return 'Check the target user, authorized_keys and the private key on the executing SSH hop. Host keys and login keys are separate. Password bootstrap via egw ssh-copy-id requires an approved native askpass helper. See docs/GUIDE.md#ssh-trust.'
    if any(s in value for s in ('managed runtime','native runtime','credential helper','untrusted runtime','untrusted process','authenticode')):
        return 'Standard mode supports key-based SSH and an in-process worker without helpers. Explicit isolation/signing requirements need an approved native package and trusted publishers; they never fall back. See docs/SECURITY.md.'
    if any(s in value for s in ('constrained','fulllanguage','applocker','wdac','pssecurityexception','running scripts is disabled','execution policy')):
        return 'Review Get-ExecutionPolicy -List and endpoint policy with the administrator. Approve signed agents, or explicitly request agents command --execution-policy RemoteSigned in Standard mode when permitted. AllSigned, Group Policy, WDAC and AppLocker are not weakened. See docs/SECURITY.md.'
    if any(s in value for s in ('worker','spool','session_pending','vfs')):
        return 'Run egw agents stage (or egw heal), enable approved RDP drive redirection, then run the printed bootstrap command inside the Bastion RDP session. See docs/GUIDE.md#first-connection.'
    return 'Run egw config check and egw doctor --preflight; see docs/GUIDE.md#troubleshooting.'


def preflight(config):
    from enclave_gateway.onboarding import configuration_summary,agent_bundle
    checks=[]
    def add(name,ok,detail,fix):checks.append({'check':name,'ok':bool(ok),'code':'ok' if ok else name+'_unavailable','detail':detail,'remediation':fix})
    external=any((config.appliance.qga_socket_path,config.appliance.qmp_socket_path,config.appliance.pid_file_path))
    if config.appliance.hypervisor!='direct' and external:
        for name,path in (('qga_endpoint',config.appliance.qga_socket),('qmp_endpoint',config.appliance.qmp_socket),('pid_file',config.appliance.pid_file)):
            add(name,path.exists(),'Configured attachment endpoint exists' if path.exists() else 'Configured attachment endpoint is missing',
                'Use the verified owner launcher and set all matching control paths; preflight does not query VM identity.')
    elif config.appliance.hypervisor!='direct':
        from enclave_gateway.hypervisor.driver import detect_host_arch,resolve_qemu_binary,resolve_efi_code_path
        arch=detect_host_arch(config.appliance.arch)
        binary=resolve_qemu_binary(arch);present=shutil.which(binary) or Path(binary).is_file()
        add('qemu',present,'QEMU executable available' if present else 'QEMU is missing from Host PATH','Install QEMU for the intended guest architecture; docs/GUIDE.md#installation.')
        add('appliance_disk',config.appliance.resolved_disk_path.is_file(),'Configured Appliance disk','Point appliance.disk_path at an existing VM disk or follow egw init in docs/GUIDE.md.')
        add('appliance_firmware',config.appliance.resolved_efi_vars_path.is_file(),'Configured writable UEFI variables','Supply the matching NVRAM file for the existing VM; do not reuse unrelated firmware state.')
        try:
            firmware=resolve_efi_code_path(arch,config.appliance.efi_code_path)
            add('uefi_code',Path(firmware).is_file(),'UEFI firmware code available','Install matching QEMU/UEFI firmware.')
        except FileNotFoundError:add('uefi_code',False,'UEFI firmware code missing','Install matching QEMU/UEFI firmware or set appliance.efi_code_path.')
    elif os.name=='nt':
        add('powershell',shutil.which('powershell.exe'),'Windows PowerShell available','Enable the Windows PowerShell component.')
    if config.bastion.enabled and config.security.mode!='custom':
        try:agent_bundle(config);add('agent_package',True,'Agent bundle ready to stage','egw agents stage')
        except (OSError,ValueError) as error:add('agent_package',False,str(error),'Provide the approved signed package and pins for Enterprise; bundled sources are used in Standard.')
    result=configuration_summary(config)
    for warning in result['warnings']:
        add('ssh_authentication:'+warning['target'],warning['severity']!='error',warning['message'],
            'Use an SSH key in Standard, or configure the approved askpass helper on the executing hop.')
        checks[-1]['severity']=warning['severity']
    result.update(healthy=all(c['ok'] for c in checks),checks=checks,scope='host-only-read-only',
                  remote_checks='not_run: QGA, RDP, endpoint policy, SSH trust and login must be checked on the actual hop')
    return result
