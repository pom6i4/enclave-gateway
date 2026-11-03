"""Multi-hop OpenSSH execution and verified binary file transfer."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
import re
import secrets
import shlex
import subprocess
from pathlib import Path
from typing import Callable

from enclave_gateway.operations.context import budget, mark_dispatched, timed, owned_cleanup
from enclave_gateway.config import TargetNodeSpec
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.security.quoting import ps_quote, validate_endpoint


def _build_b64_decode_expr(b64_str: str) -> str:
    return (f"(echo '{b64_str}' | base64 -d 2>/dev/null || "
            f"echo '{b64_str}' | base64 -D 2>/dev/null || "
            f"echo '{b64_str}' | openssl enc -base64 -d -A 2>/dev/null)")


def build_remote_bash_invocation(script: str, *, as_root: bool = False,
                               sudo_password: str = "", target_os: str = "linux") -> str:
    if target_os.lower() in ("windows", "win", "powershell"):
        if as_root:
            raise ValueError("sudo is unsupported for Windows targets")
        payload = "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n$ErrorActionPreference='Stop'\n$global:LASTEXITCODE=0\n" + script + "\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
        return "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    payload = "unset HISTFILE; export HISTFILE=/dev/null;\n" + script.replace("\r\n", "\n")
    encoded = base64.b64encode(payload.encode()).decode("ascii")
    command = f"{_build_b64_decode_expr(encoded)} | tr -d '\\r' | (command -v bash >/dev/null 2>&1 && exec bash || exec sh)"
    if not as_root:
        return command
    invocation = "sh -c " + shlex.quote(command)
    if sudo_password:
        password = base64.b64encode(sudo_password.rstrip("\r\n").encode()).decode("ascii")
        return (f"if sudo -n true 2>/dev/null; then sudo -n {invocation}; "
                f"else printf '%s\\n' \"$( {_build_b64_decode_expr(password)} )\" | sudo -S -p '' {invocation}; fi")
    return "sudo -S -p '' " + invocation


def _node_uri(node: TargetNodeSpec) -> str:
    validate_endpoint(node.host, node.port)
    if not re.fullmatch(r"[A-Za-z0-9_.\\@-]+", node.user) or node.user.startswith("-"):
        raise ValueError("Invalid SSH user")
    host = f"[{node.host}]" if ":" in node.host else node.host
    return f"{node.user}@{host}"


def _ssh_args(node, *, scp=False, has_ssh_password=False, connect_timeout_sec=15, jump_node=None, windows=True):
    _node_uri(node)
    args = ["-o", f"BatchMode={'no' if has_ssh_password else 'yes'}", "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={int(connect_timeout_sec)}", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3", "-P" if scp else "-p", str(node.port)]
    if node.ssh_known_hosts_path:
        from enclave_gateway.security.quoting import ssh_config_quote
        args.extend(['-o','UserKnownHostsFile='+ssh_config_quote(node.ssh_known_hosts_path)])
    jumps = jump_node if isinstance(jump_node, list) else ([jump_node] if jump_node else [])
    if jumps:
        if any(j.password_env for j in jumps):
            raise ValueError("Per-hop password authentication requires independently configured OpenSSH host entries")
        spec = ",".join(f"{_node_uri(j)}:{j.port}" for j in jumps)
        if any(j.ssh_key_path or j.ssh_known_hosts_path for j in jumps):
            def channel(host, port, index):
                jump = jumps[index]
                command = ["ssh.exe" if windows else "ssh"] + _ssh_args(jump,windows=windows)
                if index:
                    command += ["-o", "ProxyCommand=" + channel(jump.host, jump.port, index - 1)]
                command += ["-W", f"[{host}]:{port}", _node_uri(jump)]
                return subprocess.list2cmdline(command) if windows else shlex.join(command)
            args.extend(["-o", "ProxyCommand=" + channel(node.host, node.port, len(jumps) - 1)])
        else:
            args.extend(["-o", "ProxyJump=" + spec])
    if node.ssh_key_path:
        args.extend(["-i", node.ssh_key_path])
    return args


def _build_ssh_common_opts(node, *, port_flag="-p", has_ssh_password=False, connect_timeout_sec=15, jump_node=None):
    return " ".join(ps_quote(arg) for arg in _ssh_args(node, scp=port_flag == "-P", has_ssh_password=has_ssh_password,
                                                        connect_timeout_sec=connect_timeout_sec, jump_node=jump_node))


def _wrap_with_askpass_ps(inner_ps: str, ssh_password: str, token_id: str, *, stage_dir=r"%LOCALAPPDATA%\EnclaveGateway\stage",
                          helper_path=r"%LOCALAPPDATA%\EnclaveGateway\bin\egw-askpass.exe", trusted_signers=(), require_signed=True) -> str:
    if not ssh_password:
        return inner_ps.strip()
    encoded = base64.b64encode(ssh_password.encode()).decode("ascii")
    signers = ",".join(ps_quote(value.replace(" ", "").upper()) for value in trusted_signers)
    signature_check = f"""
    $signature=Get-AuthenticodeSignature -LiteralPath $askHelper
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -notin @({signers})) {{
        throw 'Credential helper requires a valid signature from an explicitly trusted publisher'
    }}
""" if require_signed else ""
    return f"""
$askMutex = New-Object Threading.Mutex($false, "EnclaveAskpass_$PID")
$askAcquired = $false
$oldAsk = @{{}}
try {{
    $askHelper=[Environment]::ExpandEnvironmentVariables({ps_quote(helper_path)})
    if (-not (Test-Path -LiteralPath $askHelper -PathType Leaf)) {{ throw 'Install the native credential helper before password authentication' }}
{signature_check}
    $askAcquired = $askMutex.WaitOne(30000)
    if (-not $askAcquired) {{ throw 'Timed out waiting for credential environment lock' }}
    foreach ($key in @('SSH_ASKPASS','SSH_ASKPASS_REQUIRE','DISPLAY','EGW_ASKPASS_B64')) {{
        $oldAsk[$key]=[Environment]::GetEnvironmentVariable($key,'Process')
    }}
    $env:EGW_ASKPASS_B64='{encoded}'
    $env:SSH_ASKPASS=$askHelper
    $env:SSH_ASKPASS_REQUIRE = 'force'
    $env:DISPLAY='localhost:0.0'
{inner_ps}
}} finally {{
    if ($askAcquired) {{
        foreach ($key in $oldAsk.Keys) {{ [Environment]::SetEnvironmentVariable($key,$oldAsk[$key],'Process') }}
        $askMutex.ReleaseMutex()
    }}
    $askMutex.Dispose()
}}
""".strip()


def build_powershell_ssh_hop_script(node, bash_script, *, as_root=False, ssh_password="", sudo_password="",
                                   connect_timeout_sec=15, stage_dir=r"%LOCALAPPDATA%\EnclaveGateway\stage", jump_node=None,
                                   helper_path=r"%LOCALAPPDATA%\EnclaveGateway\bin\egw-askpass.exe", trusted_signers=(), require_signed=True,
                                   capture_streams=False, result_envelope=False):
    if node.os in ('windows','win','powershell'):
        if as_root: raise ValueError('sudo is unsupported for Windows targets')
        bootstrap='$ErrorActionPreference="Stop"; $global:LASTEXITCODE=0; [Console]::InputEncoding=New-Object Text.UTF8Encoding($false); [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd())); if ($LASTEXITCODE) {exit $LASTEXITCODE}'
        remote='powershell.exe -NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(bootstrap.encode('utf-16le')).decode()
        payload=bash_script
    else:
        shell="if command -v bash >/dev/null 2>&1; then exec bash -s; else exec sh -s; fi"
        remote=('sudo -S -p '+shlex.quote('')+' sh -c '+shlex.quote(shell)) if as_root else shell
        if as_root and any(char in sudo_password for char in ('\r','\n','\0')): raise ValueError('sudo password must be a single line')
        payload=(sudo_password+'\n' if as_root else '')+'unset HISTFILE\n'+bash_script.replace('\r','')+'\n'
    arguments=['-T']+_ssh_args(node,has_ssh_password=bool(ssh_password),connect_timeout_sec=connect_timeout_sec,jump_node=jump_node)+[_node_uri(node),remote]
    encoded=base64.b64encode(payload.encode()).decode()
    # A resident worker captures PowerShell objects; standalone callers retain
    # the original byte-for-byte console behavior.
    output_statement='Write-Output ($outText.TrimEnd([char[]]"`r`n"))' if capture_streams else '[Console]::Out.Write($outText)'
    error_statement='Write-Error -Message $errText -ErrorAction Continue' if capture_streams else '[Console]::Error.Write($errText)'
    publish=f'''if ($outText) {{{output_statement}}}
    if ($proc.ExitCode -ne 0) {{throw "SSH failed with exit code $($proc.ExitCode): $errText"}}
    if ($errText) {{{error_statement}}}'''
    if result_envelope:
        publish='''@{schema='egw.ssh-result.v1';exit_code=$proc.ExitCode;
        stdout_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($outText));
        stderr_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($errText))} | ConvertTo-Json -Compress'''
    script=f"""
$psi=[Diagnostics.ProcessStartInfo]::new()
$psi.FileName='ssh.exe'
$psi.Arguments={ps_quote(subprocess.list2cmdline(arguments))}
$psi.UseShellExecute=$false
$psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
$psi.StandardOutputEncoding=[Text.UTF8Encoding]::new($false); $psi.StandardErrorEncoding=$psi.StandardOutputEncoding
$proc=[Diagnostics.Process]::new(); $proc.StartInfo=$psi
try {{
    [void]$proc.Start()
    $output=$proc.StandardOutput.ReadToEndAsync(); $errorOutput=$proc.StandardError.ReadToEndAsync()
    $bytes=[Convert]::FromBase64String('{encoded}')
    $proc.StandardInput.BaseStream.Write($bytes,0,$bytes.Length)
    $proc.StandardInput.Close()
    $proc.WaitForExit()
    $outText=$output.GetAwaiter().GetResult(); $errText=$errorOutput.GetAwaiter().GetResult()
    {publish}
}} finally {{try {{if (-not $proc.HasExited) {{$proc.Kill()}}}} catch {{}}; $proc.Dispose()}}
"""
    return _wrap_with_askpass_ps(script, ssh_password, secrets.token_hex(12), stage_dir=stage_dir, helper_path=helper_path, trusted_signers=trusted_signers, require_signed=require_signed)


def _hash_sh(path: str) -> str:
    path = shlex.quote(path)
    return f"""if command -v sha256sum >/dev/null 2>&1; then
    sha=$(sha256sum < {path} | awk '{{print tolower($1)}}')
elif command -v shasum >/dev/null 2>&1; then
    sha=$(shasum -a 256 < {path} | awk '{{print tolower($1)}}')
elif command -v sha256 >/dev/null 2>&1; then
    sha=$(sha256 -q < {path} | tr 'A-F' 'a-f')
else
    sha=$(openssl dgst -sha256 < {path} | awk '{{print tolower($NF)}}')
fi"""


def _stream_ps(node, stage, remote_path, *, pulling, password, jump_node, timeout_sec, remove_source=False):
    windows = node.os in ("windows", "win", "powershell")
    if windows:
        operation = (f"$s=[IO.File]::OpenRead([Environment]::ExpandEnvironmentVariables({ps_quote(remote_path)})); try {{$s.CopyTo([Console]::OpenStandardOutput())}} finally {{$s.Dispose()}}" if pulling
                     else f"$s=[IO.File]::Create([Environment]::ExpandEnvironmentVariables({ps_quote(remote_path)})); try {{[Console]::OpenStandardInput().CopyTo($s)}} finally {{$s.Dispose()}}")
        remote = build_remote_bash_invocation(operation, target_os="windows")
    else:
        remote = f"cat {'-- ' + shlex.quote(remote_path) if pulling else '> ' + shlex.quote(remote_path)}"
        if pulling and remove_source:
            remote='trap '+shlex.quote('rm -f -- '+shlex.quote(remote_path))+' 0; '+remote
    args = ["-T"] + _ssh_args(node, has_ssh_password=bool(password), jump_node=jump_node) + [_node_uri(node), remote]
    arguments = ps_quote(subprocess.list2cmdline(args))
    redirect = "$psi.RedirectStandardOutput = $true" if pulling else "$psi.RedirectStandardInput = $true"
    copy_call = "$proc.StandardOutput.BaseStream.CopyToAsync($file)" if pulling else "$file.CopyToAsync($proc.StandardInput.BaseStream)"
    copy = f"$copy = {copy_call}; if (-not $copy.Wait({int(timeout_sec * 1000)})) {{ $proc.Kill(); throw 'SSH binary stream timed out' }}; [void]$copy.GetAwaiter().GetResult();" + ("" if pulling else "$proc.StandardInput.Close()")
    mode = "Create" if pulling else "OpenRead"
    return f"""
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = 'ssh.exe'
$psi.Arguments = {arguments}
$psi.UseShellExecute = $false
{redirect}
$proc = New-Object Diagnostics.Process
$proc.StartInfo = $psi
$file = $null
try {{
    [void]$proc.Start()
    $file = [IO.File]::{mode}($stage)
    {copy}
    if (-not $proc.WaitForExit({int(timeout_sec * 1000)})) {{ $proc.Kill(); throw 'SSH stream timed out' }}
    if ($proc.ExitCode -ne 0) {{ throw 'SSH stream transfer failed' }}
}} finally {{
    if ($file) {{ $file.Dispose() }}
    try {{ if (-not $proc.HasExited) {{ $proc.Kill() }} }} catch {{}}
    $proc.Dispose()
}}
"""


class SshHopExecutor:
    def __init__(self, exec_hop_fn: Callable[[str, float], ExecResult], push_hop_fn: Callable[[Path, str, float], str],
                 pull_hop_fn: Callable[[str, Path, float], str], *, stage_dir=r"%LOCALAPPDATA%\EnclaveGateway\stage",
                 helper_path=r"%LOCALAPPDATA%\EnclaveGateway\bin\egw-askpass.exe", trusted_signers=(), require_signed=True, owned_commands=False, runtime_helper_path=r"%LOCALAPPDATA%\EnclaveGateway\bin\egw-runtime.exe", cleanup_hop_fn=None, security_mode='custom'):
        self.runtime_helper_path=runtime_helper_path
        self.security_mode=security_mode
        self.owned_commands=owned_commands
        self._exec_hop = exec_hop_fn
        self._push_hop = push_hop_fn
        self._pull_hop = pull_hop_fn
        self._cleanup_hop=cleanup_hop_fn
        self.stage_dir = stage_dir.rstrip("\\/")
        self.helper_options = dict(helper_path=helper_path, trusted_signers=tuple(trusted_signers), require_signed=require_signed)

    def _authentication(self,node,password,jump_node):
        def key_only(value):return self.security_mode=='standard' and value.ssh_key_path and not self.helper_options['helper_path']
        if key_only(node):password=''
        if jump_node:
            if isinstance(jump_node,(list,tuple)):jump_node=[replace(j,password_env='') if key_only(j) else j for j in jump_node]
            elif key_only(jump_node):jump_node=replace(jump_node,password_env='')
        return password,jump_node

    def exec_node(self, node, bash_script, *, as_root=False, ssh_password="", sudo_password="", timeout_sec=120.0, jump_node=None):
        ssh_password,jump_node=self._authentication(node,ssh_password,jump_node)
        if self.owned_commands:
            from enclave_gateway.transports.owned_ssh import run
            return run(self,node,bash_script,dict(as_root=as_root,ssh_password=ssh_password,sudo_password=sudo_password,timeout_sec=timeout_sec,jump_node=jump_node))
        return self._exec_plain(node,bash_script,as_root=as_root,ssh_password=ssh_password,sudo_password=sudo_password,timeout_sec=timeout_sec,jump_node=jump_node)

    def _exec_plain(self, node, bash_script, *, as_root=False, ssh_password="", sudo_password="", timeout_sec=120.0, jump_node=None):
        script = build_powershell_ssh_hop_script(node, bash_script, as_root=as_root, ssh_password=ssh_password,
                                                sudo_password=sudo_password, stage_dir=self.stage_dir, jump_node=jump_node, result_envelope=True, **self.helper_options)
        mark_dispatched()
        with timed("ssh.exec"):
            result=self._exec_hop(script, budget(timeout_sec, "ssh.exec"))
        if result.exit_code:return result
        try:
            data=json.loads(result.stdout)
            if set(data)!={'schema','exit_code','stdout_b64','stderr_b64'} or data['schema']!='egw.ssh-result.v1' or type(data['exit_code']) is not int or not 0<=data['exit_code']<=255:
                raise ValueError('Invalid SSH result envelope')
            stdout=base64.b64decode(data['stdout_b64'],validate=True).decode('utf-8')
            stderr=base64.b64decode(data['stderr_b64'],validate=True).decode('utf-8')
        except (ValueError,TypeError,KeyError,UnicodeError) as error:
            from enclave_gateway.operations.context import OperationError,current
            context=current()
            raise OperationError('ssh_result_invalid','ssh.exec',tx_id=context.tx_id if context else '',
                                 node=context.node if context else '',indeterminate=True,
                                 message='SSH result could not be decoded; reconcile the transaction before retrying.') from error
        return replace(result,exit_code=data['exit_code'],stdout=stdout,stderr=stderr)

    def push_file_to_node(self, node, local_path, remote_path, *, as_root=False, ssh_password="", sudo_password="", timeout_sec=900.0, jump_node=None):
        ssh_password,jump_node=self._authentication(node,ssh_password,jump_node)
        token = secrets.token_hex(12)
        stage = f"{self.stage_dir}\\egw_stage_{token}"
        windows = node.os in ("windows", "win", "powershell")
        if windows and as_root:
            raise ValueError("sudo is unsupported for Windows targets")
        temporary = f".egw_stage_{token}" if windows else f"/tmp/.egw_stage_{token}"
        expected = self._push_hop(local_path, stage, budget(timeout_sec, "ssh.upload"))
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Invalid staging checksum")
        options = _build_ssh_common_opts(node, port_flag="-P", has_ssh_password=bool(ssh_password), jump_node=jump_node)
        fallback = _stream_ps(node, stage, temporary, pulling=False, password=ssh_password, jump_node=jump_node, timeout_sec=timeout_sec)
        script = f"""
$ErrorActionPreference = 'Stop'
$stage = [Environment]::ExpandEnvironmentVariables({ps_quote(stage)})
try {{
    & scp.exe {options} $stage {ps_quote(_node_uri(node) + ':' + temporary)}
    if ($LASTEXITCODE -ne 0) {{
{fallback}
        $global:LASTEXITCODE = 0
    }}
}} finally {{ [IO.File]::Delete($stage) }}
"""
        try:
            result = self._exec_hop(_wrap_with_askpass_ps(script, ssh_password, token, stage_dir=self.stage_dir, **self.helper_options), budget(timeout_sec, "ssh.transfer"))
            if result.exit_code:
                raise RuntimeError(f"Target transfer failed: {result.stderr or result.stdout}")
            if windows:
                verify = f"""
$tmp={ps_quote(temporary)}
try {{
$dst=[Environment]::ExpandEnvironmentVariables({ps_quote(remote_path)})
$sha=(Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLower()
if ($sha -ne '{expected}') {{ throw 'Target checksum mismatch' }}
$parent=Split-Path -Parent $dst
if ($parent) {{ [void][IO.Directory]::CreateDirectory($parent) }}
Move-Item -LiteralPath $tmp -Destination $dst -Force -ErrorAction Stop
Write-Output "VERIFIED:$sha"
}} finally {{[IO.File]::Delete($tmp)}}
"""
            else:
                tmp, dst = shlex.quote(temporary), shlex.quote(remote_path)
                verify = f"""set -e
trap {shlex.quote("rm -f -- "+shlex.quote(temporary))} 0
{_hash_sh(temporary)}
if [ "$sha" != '{expected}' ]; then
    rm -f {tmp}
    echo "MISMATCH:$sha" >&2
    exit 1
fi
mkdir -p -- "$(dirname -- {dst})"
mv -f -- {tmp} {dst}
echo "VERIFIED:$sha"
"""
            result = self.exec_node(node, verify, as_root=as_root, ssh_password=ssh_password, sudo_password=sudo_password, timeout_sec=timeout_sec, jump_node=jump_node)
            if result.exit_code or f"VERIFIED:{expected}" not in result.stdout:
                raise RuntimeError(f"Target verification failed: {result.stderr or result.stdout}")
            return expected
        except BaseException:
            self._cleanup_hop_stage(stage)
            raise

    def pull_file_from_node(self, node, remote_path, local_path, *, as_root=False, ssh_password="", sudo_password="", timeout_sec=600.0, jump_node=None):
        ssh_password,jump_node=self._authentication(node,ssh_password,jump_node)
        token = secrets.token_hex(12)
        stage = f"{self.stage_dir}\\egw_pull_{token}"
        windows = node.os in ("windows", "win", "powershell")
        if windows and as_root:
            raise ValueError("sudo is unsupported for Windows targets")
        source = remote_path
        if as_root:
            source = f"/tmp/.egw_pull_{token}"
            prep = f"set -e; umask 077; set -C; cat -- {shlex.quote(remote_path)} > {shlex.quote(source)}; chown -- {shlex.quote(node.user)} {shlex.quote(source)}"
            result = self.exec_node(node, prep, as_root=True, ssh_password=ssh_password, sudo_password=sudo_password, jump_node=jump_node)
            if result.exit_code:
                raise RuntimeError("Failed to stage root-owned file")
        try:
            if windows:
                hash_script = f"Write-Output ('SHA256:' + (Get-FileHash -LiteralPath ([Environment]::ExpandEnvironmentVariables({ps_quote(source)})) -Algorithm SHA256).Hash.ToLower())"
            else:
                hash_script = "set -e\n" + _hash_sh(source) + '\necho "SHA256:$sha"'
            result = self.exec_node(node, hash_script, ssh_password=ssh_password, timeout_sec=timeout_sec, jump_node=jump_node)
            match = re.search(r"SHA256:([0-9a-f]{64})", result.stdout)
            if result.exit_code or not match:
                raise RuntimeError("Failed to hash target file")
            expected = match.group(1)
            # Binary streams preserve NUL bytes and avoid text transcoding in PS5.
            stream = _stream_ps(node, stage, source, pulling=True, password=ssh_password, jump_node=jump_node, timeout_sec=timeout_sec,remove_source=as_root)
            script = f"$stage=[Environment]::ExpandEnvironmentVariables({ps_quote(stage)})\n[void][IO.Directory]::CreateDirectory((Split-Path -Parent $stage))\n" + stream
            result = self._exec_hop(_wrap_with_askpass_ps(script, ssh_password, token, stage_dir=self.stage_dir, **self.helper_options), budget(timeout_sec, "ssh.transfer"))
            if result.exit_code:
                raise RuntimeError(f"Target file retrieval failed: {result.stderr or result.stdout}")
            from tempfile import NamedTemporaryFile
            from enclave_gateway.transports.rdp_vfs import compute_file_sha256
            local_path.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile(dir=local_path.parent, delete=False) as fp:
                temporary = Path(fp.name)
            try:
                self._pull_hop(stage, temporary, budget(timeout_sec, "ssh.download"))
                if compute_file_sha256(temporary) != expected:
                    raise RuntimeError("Target file checksum mismatch")
                temporary.replace(local_path)
            finally:
                temporary.unlink(missing_ok=True)
            return expected
        finally:
            self._cleanup_hop_stage(stage)

    def _cleanup_hop_stage(self, stage):
        # A cleanup callback uses the controller directly. Never enqueue a new
        # short-lived VFS transaction after the original operation has expired.
        if self._cleanup_hop is None:return
        try:
            with owned_cleanup(10):
                self._cleanup_hop(stage)
        except Exception:
            pass

    def bootstrap_ssh_key(self, node, *, ssh_password="", timeout_sec=60.0, jump_node=None):
        if ssh_password and not self.helper_options['helper_path']:
            raise ValueError('Password bootstrap requires security.askpass_helper_path; configure the approved native credential helper before ssh-copy-id')
        if node.os in ("windows", "win", "powershell"):
            raise ValueError("Windows authorized_keys provisioning requires an administrator-approved ACL policy")
        result = self._exec_hop("""
$ErrorActionPreference='Stop'
$dir=Join-Path $env:USERPROFILE '.ssh'
[void][IO.Directory]::CreateDirectory($dir)
$key=Join-Path $dir 'id_ed25519'
if (-not (Test-Path -LiteralPath "$key.pub")) {
    & ssh-keygen.exe -t ed25519 -N '\"\"' -f $key
    if ($LASTEXITCODE) { throw 'SSH key generation failed' }
}
(Get-Content -LiteralPath "$key.pub" -Raw).Trim()
""", 30.0)
        if result.exit_code or not result.stdout.strip():
            return ExecResult(1, "", "Failed to obtain hop SSH public key", result.duration_ms)
        key = result.stdout.strip().splitlines()[-1]
        encoded = base64.b64encode(key.encode()).decode("ascii")
        script = f"set -e; umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; PUB=$( {_build_b64_decode_expr(encoded)} ); grep -qxF \"$PUB\" ~/.ssh/authorized_keys || printf '%s\\n' \"$PUB\" >> ~/.ssh/authorized_keys"
        return self.exec_node(node, script, ssh_password=ssh_password, timeout_sec=timeout_sec, jump_node=jump_node)
