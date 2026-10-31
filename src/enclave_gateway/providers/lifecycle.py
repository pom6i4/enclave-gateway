"""Explicit, hash-pinned lifecycle recipes; proprietary CLIs are never guessed."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from enclave_gateway.security.quoting import ps_quote

ACTIONS=frozenset(('install','connect','disconnect','import_key'))
INPUTS=frozenset(('installer','key_file','profile_file','tunnel_name'))


def plan(spec,action):
    if action not in ACTIONS: raise ValueError('Unsupported provider action')
    if not spec.lifecycle_manifest or not re.fullmatch('[a-fA-F0-9]{64}',spec.lifecycle_manifest_sha256):
        raise ValueError('Configure an approved lifecycle manifest and SHA-256 first')
    if not Path(spec.lifecycle_manifest).is_absolute(): raise ValueError('Lifecycle manifest must use an absolute trusted path')
    if not isinstance(spec.lifecycle_inputs,dict) or any(not isinstance(value,str) or '\0' in value for value in spec.lifecycle_inputs.values()): raise ValueError('Lifecycle inputs must be literal strings')
    raw=Path(spec.lifecycle_manifest).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=spec.lifecycle_manifest_sha256.lower(): raise ValueError('Lifecycle manifest changed after approval')
    manifest=json.loads(raw)
    if set(manifest)!={'revision','provider','versions','architectures','actions','source'} or manifest['revision']!=1 or manifest['provider']!=spec.type:
        raise ValueError('Lifecycle manifest schema/provider mismatch')
    if not manifest['versions'] or not manifest['architectures'] or not isinstance(manifest['source'],str) or not manifest['source']:
        raise ValueError('Lifecycle recipes require version/architecture/documentation provenance')
    steps=manifest['actions'].get(action)
    if not isinstance(steps,list) or not 1<=len(steps)<=16: raise ValueError('Action has no approved procedure')
    if set(spec.lifecycle_inputs)-INPUTS: raise ValueError('Unknown lifecycle input')
    resolved=[]
    for step in steps:
        required={'executable','sha256','publisher','version','architecture','arguments','success_codes'}
        if not isinstance(step,dict) or not required<=set(step) or set(step)-required-{'stdin_env','timeout_sec'}:
            raise ValueError('Invalid lifecycle step')
        if not re.fullmatch('[a-fA-F0-9]{64}',step['sha256']) or not step['publisher']:
            raise ValueError('Every lifecycle executable requires an approved hash/publisher')
        if step['version'] not in manifest['versions'] or step['architecture'] not in manifest['architectures']:
            raise ValueError('Step is outside qualified version/architecture contract')
        if not isinstance(step['arguments'],list) or any(not isinstance(arg,str) or '\0' in arg for arg in step['arguments']): raise ValueError('Arguments must be literal strings')
        if not isinstance(step['success_codes'],list) or not step['success_codes'] or any(type(code) is not int for code in step['success_codes']): raise ValueError('Invalid success codes')
        arguments=[]
        for arg in step['arguments']:
            if '{' in arg or '}' in arg:
                name=arg[1:-1]
                if arg!='{'+name+'}' or name not in INPUTS or name not in spec.lifecycle_inputs: raise ValueError('Only whole approved input placeholders are supported')
                arg=spec.lifecycle_inputs[name]
            arguments.append(arg)
        if step['executable'].replace('\\','/').rsplit('/',1)[-1].lower()=='msiexec.exe':
            if '/norestart' not in [arg.lower() for arg in arguments] or '/forcerestart' in [arg.lower() for arg in arguments]:
                raise ValueError('MSI lifecycle recipes must suppress reboot')
        if 'stdin_env' in step and not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',step['stdin_env']): raise ValueError('Invalid vault reference')
        if 'timeout_sec' in step and (type(step['timeout_sec']) not in (int,float) or not 0<step['timeout_sec']<=86400):
            raise ValueError('Invalid lifecycle step deadline')
        resolved.append({**step,'arguments':arguments})
    artifacts=[]
    selected=('installer',) if action=='install' else ('key_file',) if action=='import_key' else ()
    for name in selected:
        if name not in spec.lifecycle_local_artifacts: continue
        if name not in spec.lifecycle_inputs: raise ValueError('Artifact requires a remote input path')
        local=Path(spec.lifecycle_local_artifacts[name]).expanduser()
        digest=hashlib.sha256()
        with local.open('rb') as stream:
            from enclave_gateway.operations.context import checkpoint
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                checkpoint('provider.plan_artifact'); digest.update(chunk)
        publisher=spec.lifecycle_artifact_publishers.get(name,'')
        if name=='installer' and not publisher: raise ValueError('Installer artifact requires an approved publisher')
        artifacts.append({'input':name,'local_path':str(local.resolve()),'remote_path':spec.lifecycle_inputs[name],
                          'sha256':digest.hexdigest(),'publisher':publisher})
    document={'artifacts':artifacts,'provider':spec.type,'revision':manifest['revision'],'action':action,'manifest_sha256':spec.lifecycle_manifest_sha256.lower(),
              'steps':resolved,'source':manifest['source'],'automatic_reboot':False}
    document['approval_digest']=hashlib.sha256(json.dumps(document,sort_keys=True).encode()).hexdigest()
    return document


def powershell(step,security,secret=''):
    import base64
    # Artifact and signature checks occur on the execution host immediately before
    # launch. The recipe never resolves a command supplied by an MCP caller.
    arguments=','.join(ps_quote(arg) for arg in step['arguments'])
    signers=','.join(ps_quote(value) for value in security.trusted_signers)
    encoded=base64.b64encode(secret.encode()).decode()
    return f"""
$ErrorActionPreference='Stop'
$exe=[Environment]::ExpandEnvironmentVariables({ps_quote(step['executable'])})
$runtime=[Environment]::ExpandEnvironmentVariables({ps_quote(security.runtime_helper_path)})
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne {ps_quote(step['sha256'])}) {{throw 'Provider artifact hash mismatch'}}
$s=Get-AuthenticodeSignature -LiteralPath $exe
if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -ne {ps_quote(step['publisher'])}) {{throw 'Provider publisher mismatch'}}
if ((Get-Item -LiteralPath $exe).VersionInfo.FileVersion -ne {ps_quote(step['version'])}) {{throw 'Provider version mismatch'}}
$s=Get-AuthenticodeSignature -LiteralPath $runtime
if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -notin @({signers})) {{throw 'Untrusted process runtime'}}
$fs=[IO.File]::OpenRead($exe)
try {{
    $reader=New-Object IO.BinaryReader($fs)
    if ($reader.ReadUInt16() -ne 0x5a4d) {{throw 'Lifecycle controller is not PE'}}
    $fs.Position=0x3c; $offset=$reader.ReadInt32()
    if ($offset -lt 1 -or $offset -gt $fs.Length-6) {{throw 'Invalid PE'}}
    $fs.Position=$offset
    if ($reader.ReadUInt32() -ne 0x4550) {{throw 'Invalid PE'}}
    $machine=$reader.ReadUInt16()
    $arch=switch ($machine) {{ 0x8664 {{'x86_64'}} 0xaa64 {{'arm64'}} 0x014c {{'x86'}} default {{'unknown'}} }}
    if ($arch -ne {ps_quote(step['architecture'])}) {{throw 'Provider architecture mismatch'}}
}} finally {{$fs.Dispose()}}
$command=@($exe)+@({arguments})
$inputObject=@{{command=$command; timeout_ms={max(1,int(step.get('timeout_sec',120)*1000))}; stdin_b64='{encoded}'}}
# Capture output inside this approved wrapper; lifecycle results expose status only.
$null=($inputObject | ConvertTo-Json -Compress | & $runtime run 2>&1)
$code=$LASTEXITCODE
@{{exit_code=$code; reboot_required=($code -eq 3010)}} | ConvertTo-Json -Compress
"""
