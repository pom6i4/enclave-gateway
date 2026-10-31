"""Wrap SSH execution in a supervisor; cancellation uses a separate SSH request."""
from __future__ import annotations
import base64
import json
import secrets
import shlex
from pathlib import Path
from enclave_gateway.operations.context import current,owned_cleanup,OperationError,budget


def script(payload):
    code=(Path(__file__).parents[1]/'agents/owned_command.py').read_bytes()
    source=base64.b64encode(code).decode()
    encoded=base64.b64encode(json.dumps(payload).encode()).decode()
    program='import base64;exec(compile(base64.b64decode('+repr(source)+"),'<owned-command>','exec'))"
    return 'printf %s '+shlex.quote(encoded)+' | base64 -d | python3 -c '+shlex.quote(program)


def run(executor,node,command,options):
    context=current(); token=secrets.token_hex(32)
    wrap=(lambda payload:windows_script(payload,executor)) if node.os in ('windows','win','powershell') else script
    def cancel():
        with owned_cleanup():
            executor._exec_plain(node,wrap({'action':'cancel','token':token}),**{**options,'timeout_sec':2})
    timeout=budget(options.get('timeout_sec',120))
    payload={'action':'exec','token':token,'script':command,'timeout_sec':timeout}
    try:
        if context:
            with context.cancellation_hook('ssh_'+token,cancel):
                result=executor._exec_plain(node,wrap(payload),**options)
        else: result=executor._exec_plain(node,wrap(payload),**options)
        data=json.loads(result.stdout)
        if result.exit_code or 'error' in data: raise OperationError('owned_command_failed','ssh',indeterminate=True)
        result.exit_code=data['exit_code']
        result.stdout=base64.b64decode(data['stdout_b64'],validate=True).decode('utf-8','replace').replace('\r\n','\n').strip()
        result.stderr=base64.b64decode(data['stderr_b64'],validate=True).decode('utf-8','replace').replace('\r\n','\n').strip()
        return result
    except BaseException:
        try: cancel()
        except Exception: pass
        raise


def windows_script(payload,executor):
    from enclave_gateway.security.quoting import ps_quote
    signers=','.join(ps_quote(item) for item in executor.helper_options['trusted_signers'])
    check=f"$s=Get-AuthenticodeSignature -LiteralPath $helper; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -notin @({signers})) {{throw 'Untrusted runtime'}}" if executor.helper_options['require_signed'] else ''
    token=payload['token']
    header=f"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); $helper=[Environment]::ExpandEnvironmentVariables({ps_quote(executor.runtime_helper_path)}); {check}; "
    if payload['action']=='cancel':
        return header+f"'{{\"cancel_token\":\"{token}\"}}' | & $helper cancel; if ($LASTEXITCODE) {{throw 'Cancellation request failed'}}"
    encoded=base64.b64encode(('[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);\n'+payload['script']).encode('utf-8')).decode()
    return header+f"""
$bootstrap='[Console]::InputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'
$command=@((Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile','-NonInteractive','-Command',$bootstrap)
$psi=New-Object Diagnostics.ProcessStartInfo
$psi.FileName=$helper; $psi.Arguments='run'; $psi.UseShellExecute=$false
$psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
$psi.StandardOutputEncoding=New-Object Text.UTF8Encoding($false); $psi.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
$proc=New-Object Diagnostics.Process; $proc.StartInfo=$psi
try {{
    [void]$proc.Start(); $output=$proc.StandardOutput.ReadToEndAsync(); $errorOutput=$proc.StandardError.ReadToEndAsync()
    $request=@{{command=$command;timeout_ms={max(1,int(payload['timeout_sec']*1000))};cancel_token='{token}';stdin_b64='{encoded}'}} | ConvertTo-Json -Compress
    $proc.StandardInput.WriteLine($request); $proc.StandardInput.Close()
    if (-not $proc.WaitForExit({max(1,int(payload['timeout_sec']*1000))+2000})) {{$proc.Kill(); throw 'Owned command deadline expired'}}
    @{{exit_code=$proc.ExitCode;stdout_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($output.GetAwaiter().GetResult()));
       stderr_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($errorOutput.GetAwaiter().GetResult()));owned_tree_stopped=$true}} | ConvertTo-Json -Compress
}} finally {{try {{if (-not $proc.HasExited) {{$proc.Kill()}}}} catch {{}}; $proc.Dispose()}}
"""
