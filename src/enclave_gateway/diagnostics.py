"""Actionable setup diagnostics without accepting unknown SSH identities."""
from __future__ import annotations
import os
from pathlib import Path
import shutil


def remediation(detail):
    value=str(detail).lower()
    if any(s in value for s in ('host key verification failed','remote host identification has changed','no ed25519 host key','no rsa host key')):
        return 'Verify the TargetNode host-key fingerprint with its administrator, then provision known_hosts on the SSH hop (Bastion or Appliance). Do not disable StrictHostKeyChecking or delete a changed key blindly. See docs/GUIDE.md#ssh-trust.'
    if 'permission denied' in value or 'publickey' in value:
        return 'Check the target user, authorized_keys and the private key on the executing SSH hop. Host keys and login keys are separate. Password bootstrap via egw ssh-copy-id requires an approved native askpass helper. See docs/GUIDE.md#ssh-trust.'
    if any(s in value for s in ('managed runtime','native runtime','credential helper','untrusted runtime','untrusted process','authenticode')):
        return 'Standard mode supports key-based SSH and an in-process worker without helpers. Explicit isolation/signing requirements need an approved native package and trusted publishers; they never fall back. See docs/SECURITY.md.'
    if any(s in value for s in ('constrained','fulllanguage','applocker','wdac')):
        return 'Ask the endpoint administrator to approve the worker under the existing application-control policy. No mode bypasses WDAC, AppLocker or ConstrainedLanguage. See docs/SECURITY.md.'
    if any(s in value for s in ('worker','spool','session_pending','vfs')):
        return 'Run egw agents stage (or egw heal), enable approved RDP drive redirection, then run the printed bootstrap command inside the Bastion RDP session. See docs/GUIDE.md#first-connection.'
    return 'Run egw config check and egw doctor --preflight; see docs/GUIDE.md#troubleshooting.'


def preflight(config):
    from enclave_gateway.onboarding import configuration_summary,agent_bundle
    checks=[]
    def add(name,ok,detail,fix):checks.append({'check':name,'ok':bool(ok),'detail':detail,'remediation':fix})
    if config.appliance.hypervisor!='direct':
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
    result.update(healthy=all(c['ok'] for c in checks),checks=checks,scope='host-only-read-only',
                  remote_checks='not_run: QGA, RDP, endpoint policy, SSH trust and login must be checked on the actual hop')
    return result
