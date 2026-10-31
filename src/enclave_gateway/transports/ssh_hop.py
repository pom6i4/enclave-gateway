"""Multi-hop OpenSSH execution, SSH_ASKPASS password auth, key bootstrap, and verified file transfer."""

from __future__ import annotations

import base64
import secrets
from pathlib import Path
from typing import Callable

from enclave_gateway.config import TargetNodeSpec
from enclave_gateway.control.qga_client import ExecResult


def _build_b64_decode_expr(b64_str: str) -> str:
    """Build a portable POSIX Base64 decode pipeline (GNU/BusyBox -d, BSD/macOS -D, OpenSSL fallback)."""
    return (
        f"(echo '{b64_str}' | base64 -d 2>/dev/null || "
        f"echo '{b64_str}' | base64 -D 2>/dev/null || "
        f"echo '{b64_str}' | openssl enc -base64 -d -A 2>/dev/null)"
    )


def build_remote_bash_invocation(
    script: str, *, as_root: bool = False, sudo_password: str = ""
) -> str:
    """Encode a POSIX/bash script in Base64, disable shell history, strip CR, and execute portably."""
    clean_script = "unset HISTFILE; export HISTFILE=/dev/null;\n" + script.replace("\r\n", "\n")
    b64_script = base64.b64encode(clean_script.encode("utf-8")).decode("ascii")
    polyglot_pipe = (
        f"{_build_b64_decode_expr(b64_script)} | tr -d '\\r' | "
        "(command -v bash >/dev/null 2>&1 && exec bash || exec sh)"
    )
    if as_root:
        if sudo_password:
            clean_pw = sudo_password.rstrip("\r\n")
            pw_b64 = base64.b64encode(clean_pw.encode("utf-8")).decode("ascii")
            pw_expr = _build_b64_decode_expr(pw_b64)
            return (
                f"if sudo -n true 2>/dev/null; then sudo -n sh -c \"{polyglot_pipe}\"; "
                f"else printf '%s\\n' \"$({pw_expr})\" | sudo -S -p '' sh -c \"{polyglot_pipe}\"; fi"
            )
        return f"sudo -S -p '' sh -c \"{polyglot_pipe}\""
    return polyglot_pipe


def _build_ssh_common_opts(
    node: TargetNodeSpec,
    *,
    port_flag: str = "-p",
    has_ssh_password: bool = False,
    connect_timeout_sec: int = 15,
    jump_node: TargetNodeSpec | None = None,
) -> str:
    batch_val = "no" if has_ssh_password else "yes"
    opts = [
        f"-o BatchMode={batch_val}",
        "-o StrictHostKeyChecking=no",
        "-o UserKnownHostsFile=NUL",
        f"-o ConnectTimeout={connect_timeout_sec}",
        "-o ServerAliveInterval=15",
        "-o ServerAliveCountMax=3",
        f"{port_flag} {node.port}",
    ]
    if jump_node is not None:
        jump_spec = f"{jump_node.user}@{jump_node.host}:{jump_node.port}"
        if port_flag == "-P":
            opts.append(f"-o ProxyJump={jump_spec}")
        else:
            opts.append(f"-J {jump_spec}")
    if node.ssh_key_path:
        opts.append(f"-i {node.ssh_key_path}")
    return " ".join(opts)


def _wrap_with_askpass_ps(
    inner_ps: str,
    ssh_password: str,
    token_id: str,
    *,
    stage_dir: str = r"%LOCALAPPDATA%\EnclaveGateway\stage",
) -> str:
    """Wrap a PowerShell SSH/SCP block with an ephemeral SSH_ASKPASS helper if ssh_password is set."""
    if not ssh_password:
        return inner_ps.strip()

    clean_ssh_pw = ssh_password.rstrip("\r\n")
    # Escape special batch characters for cmd.exe echo
    escaped_bat = (
        clean_ssh_pw.replace("^", "^^")
        .replace("&", "^&")
        .replace("|", "^|")
        .replace("<", "^<")
        .replace(">", "^>")
        .replace("%", "%%")
    )
    bat_content = f"@echo off\r\necho {escaped_bat}\r\n"
    bat_b64 = base64.b64encode(bat_content.encode("utf-8")).decode("ascii")

    return f"""
$askDir = [Environment]::ExpandEnvironmentVariables('{stage_dir}')
if (-not (Test-Path $askDir)) {{ New-Item -ItemType Directory -Force -Path $askDir | Out-Null }}
$askCmd = Join-Path $askDir 'ask_{token_id}.cmd'
try {{
    $askBytes = [Convert]::FromBase64String('{bat_b64}')
    if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {{
        [IO.File]::WriteAllBytes($askCmd, $askBytes)
    }} else {{
        Set-Content -Path $askCmd -Value $askBytes -Encoding Byte -Force
    }}
    $env:SSH_ASKPASS = $askCmd
    $env:SSH_ASKPASS_REQUIRE = 'force'
    $env:DISPLAY = 'localhost:0.0'
{inner_ps}
}} finally {{
    if (Test-Path $askCmd) {{
        $zeroBytes = New-Object byte[] 64
        if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {{
            [IO.File]::WriteAllBytes($askCmd, $zeroBytes)
        }} else {{
            Set-Content -Path $askCmd -Value $zeroBytes -Encoding Byte -Force -ErrorAction SilentlyContinue
        }}
        Remove-Item $askCmd -Force -ErrorAction SilentlyContinue
    }}
    Remove-Item Env:\\SSH_ASKPASS -ErrorAction SilentlyContinue
    Remove-Item Env:\\SSH_ASKPASS_REQUIRE -ErrorAction SilentlyContinue
}}
""".strip()


def build_powershell_ssh_hop_script(
    node: TargetNodeSpec,
    bash_script: str,
    *,
    as_root: bool = False,
    ssh_password: str = "",
    sudo_password: str = "",
    connect_timeout_sec: int = 15,
    stage_dir: str = r"%LOCALAPPDATA%\EnclaveGateway\stage",
    jump_node: TargetNodeSpec | None = None,
) -> str:
    """Build a PowerShell script that invokes ssh.exe on the hop host safely without cmd.exe or temp sudo files."""
    remote_cmd = build_remote_bash_invocation(
        bash_script, as_root=as_root, sudo_password=sudo_password
    )
    opts_str = _build_ssh_common_opts(
        node,
        port_flag="-p",
        has_ssh_password=bool(ssh_password),
        connect_timeout_sec=connect_timeout_sec,
        jump_node=jump_node,
    )
    target_uri = f"{node.user}@{node.host}"
    token_id = secrets.token_hex(6)

    core_ps = f"""
ssh.exe -n -T {opts_str} {target_uri} '{remote_cmd}'
exit $LASTEXITCODE
"""
    return _wrap_with_askpass_ps(
        core_ps, ssh_password, token_id, stage_dir=stage_dir
    )


class SshHopExecutor:
    """Executes commands and transfers files to TargetNodes via Bastion or Appliance."""

    def __init__(
        self,
        exec_hop_fn: Callable[[str, float], ExecResult],
        push_hop_fn: Callable[[Path, str, float], str],
        pull_hop_fn: Callable[[str, Path, float], str],
        *,
        stage_dir: str = r"%LOCALAPPDATA%\EnclaveGateway\stage",
    ) -> None:
        self._exec_hop = exec_hop_fn
        self._push_hop = push_hop_fn
        self._pull_hop = pull_hop_fn
        self.stage_dir = stage_dir.rstrip("\\/")

    def exec_node(
        self,
        node: TargetNodeSpec,
        bash_script: str,
        *,
        as_root: bool = False,
        ssh_password: str = "",
        sudo_password: str = "",
        timeout_sec: float = 120.0,
        jump_node: TargetNodeSpec | None = None,
    ) -> ExecResult:
        hop_ps = build_powershell_ssh_hop_script(
            node,
            bash_script,
            as_root=as_root,
            ssh_password=ssh_password,
            sudo_password=sudo_password,
            stage_dir=self.stage_dir,
            jump_node=jump_node,
        )
        return self._exec_hop(hop_ps, timeout_sec)

    def push_file_to_node(
        self,
        node: TargetNodeSpec,
        local_path: Path,
        remote_path: str,
        *,
        as_root: bool = False,
        ssh_password: str = "",
        sudo_password: str = "",
        timeout_sec: float = 900.0,
        jump_node: TargetNodeSpec | None = None,
    ) -> str:
        """Two-hop verified file delivery: Host -> VFS/Hop staging -> SCP (or zero-cmd SSH stream) -> TargetNode."""
        stage_id = secrets.token_hex(6)
        hop_stage = f"{self.stage_dir}\\egw_stage_{stage_id}_{local_path.name}"
        expected_sha = self._push_hop(local_path, hop_stage, timeout_sec)

        scp_opts = _build_ssh_common_opts(
            node, port_flag="-P", has_ssh_password=bool(ssh_password), jump_node=jump_node
        )
        ssh_opts = _build_ssh_common_opts(
            node, port_flag="-p", has_ssh_password=bool(ssh_password), jump_node=jump_node
        )
        remote_tmp = (
            f"/tmp/.egw_stage_{stage_id}"
            if as_root
            else f"{remote_path}.tmp_{stage_id}"
        )

        scp_core_ps = f"""
$stage = [Environment]::ExpandEnvironmentVariables('{hop_stage}')
try {{
    scp.exe {scp_opts} $stage '{node.user}@{node.host}:{remote_tmp}'
    if ($LASTEXITCODE -ne 0) {{
        if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {{
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'ssh.exe'
            $psi.Arguments = "-T {ssh_opts} {node.user}@{node.host} `"cat > '{remote_tmp}'`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardInput = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $fs = [IO.File]::OpenRead($stage)
            try {{
                $fs.CopyTo($proc.StandardInput.BaseStream)
            }} finally {{
                $fs.Close()
                $proc.StandardInput.Close()
            }}
            $proc.WaitForExit()
            $global:LASTEXITCODE = $proc.ExitCode
        }} else {{
            Get-Content -Path $stage -Encoding Byte -Raw | ssh.exe -T {ssh_opts} {node.user}@{node.host} "cat > '{remote_tmp}'"
        }}
        if ($LASTEXITCODE -ne 0) {{ Write-Error 'SCP and SSH stream transfer to target node failed'; exit 1 }}
    }}
}} finally {{
    Remove-Item $stage -Force -ErrorAction SilentlyContinue
}}
"""
        scp_ps = _wrap_with_askpass_ps(
            scp_core_ps, ssh_password, stage_id, stage_dir=self.stage_dir
        )
        scp_res = self._exec_hop(scp_ps, timeout_sec)
        if scp_res.exit_code != 0:
            raise RuntimeError(
                f"TargetNode SCP stage failed for {node.name}:{remote_path}: {scp_res.stderr or scp_res.stdout}"
            )

        verify_and_move_sh = f"""
set -e
if command -v sha256sum >/dev/null 2>&1; then
    sha=$(sha256sum '{remote_tmp}' | awk '{{print tolower($1)}}')
elif command -v shasum >/dev/null 2>&1; then
    sha=$(shasum -a 256 '{remote_tmp}' | awk '{{print tolower($1)}}')
elif command -v sha256 >/dev/null 2>&1; then
    sha=$(sha256 -q '{remote_tmp}' | tr 'A-F' 'a-f')
else
    sha=$(openssl dgst -sha256 '{remote_tmp}' | awk '{{print tolower($NF)}}')
fi
if [ "$sha" != '{expected_sha}' ]; then
    rm -f '{remote_tmp}'
    echo "MISMATCH:$sha" >&2
    exit 1
fi
mkdir -p "$(dirname '{remote_path}')"
mv -f '{remote_tmp}' '{remote_path}'
echo "VERIFIED:$sha"
""".strip()

        verify_res = self.exec_node(
            node,
            verify_and_move_sh,
            as_root=as_root,
            ssh_password=ssh_password,
            sudo_password=sudo_password,
            timeout_sec=120.0,
            jump_node=jump_node,
        )
        if verify_res.exit_code != 0 or f"VERIFIED:{expected_sha}" not in verify_res.stdout:
            raise RuntimeError(
                f"TargetNode verification/move failed for {node.name}:{remote_path}: {verify_res.stderr or verify_res.stdout}"
            )
        return expected_sha

    def pull_file_from_node(
        self,
        node: TargetNodeSpec,
        remote_path: str,
        local_path: Path,
        *,
        as_root: bool = False,
        ssh_password: str = "",
        sudo_password: str = "",
        timeout_sec: float = 600.0,
        jump_node: TargetNodeSpec | None = None,
    ) -> str:
        """Two-hop verified file retrieval: TargetNode -> SCP (or SSH stream fallback) -> VFS/Hop staging -> Host."""
        stage_id = secrets.token_hex(6)
        hop_stage = f"{self.stage_dir}\\egw_pull_{stage_id}_{local_path.name}"
        remote_src = f"/tmp/.egw_pull_{stage_id}" if as_root else remote_path

        if as_root:
            prep_sh = f"""
set -e
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    avail_kb=$(df -Pk /dev/shm 2>/dev/null | awk 'NR==2 {{print $4}}')
    fsize_kb=$(du -k '{remote_path}' 2>/dev/null | awk '{{print $1}}')
    if [ -n "$avail_kb" ] && [ -n "$fsize_kb" ] && [ "$fsize_kb" -lt 16384 ] && [ "$avail_kb" -gt 65536 ]; then
        cp -f '{remote_path}' '/dev/shm/.egw_pull_{stage_id}'
        chown '{node.user}' '/dev/shm/.egw_pull_{stage_id}'
        chmod 600 '/dev/shm/.egw_pull_{stage_id}'
        ln -sf '/dev/shm/.egw_pull_{stage_id}' '{remote_src}'
        exit 0
    fi
fi
cp -f '{remote_path}' '{remote_src}'
chown '{node.user}' '{remote_src}'
chmod 600 '{remote_src}'
""".strip()
            prep_res = self.exec_node(
                node,
                prep_sh,
                as_root=True,
                ssh_password=ssh_password,
                sudo_password=sudo_password,
                timeout_sec=60.0,
                jump_node=jump_node,
            )
            if prep_res.exit_code != 0:
                raise RuntimeError(
                    f"Failed to stage root-owned file {node.name}:{remote_path}: {prep_res.stderr or prep_res.stdout}"
                )

        scp_opts = _build_ssh_common_opts(
            node, port_flag="-P", has_ssh_password=bool(ssh_password), jump_node=jump_node
        )
        ssh_opts = _build_ssh_common_opts(
            node, port_flag="-p", has_ssh_password=bool(ssh_password), jump_node=jump_node
        )
        scp_core_ps = f"""
$stage = [Environment]::ExpandEnvironmentVariables('{hop_stage}')
$stageParent = Split-Path -Parent $stage
if ($stageParent -and -not (Test-Path $stageParent)) {{ New-Item -ItemType Directory -Force -Path $stageParent | Out-Null }}
scp.exe {scp_opts} '{node.user}@{node.host}:{remote_src}' $stage
if ($LASTEXITCODE -ne 0) {{
    $b64 = ssh.exe -n -T {ssh_opts} {node.user}@{node.host} "base64 '{remote_src}' | tr -d '\\r\\n'"
    if ($LASTEXITCODE -ne 0) {{ Write-Error 'SCP and SSH stream pull from target node failed'; exit 1 }}
    $pullBytes = [Convert]::FromBase64String(($b64 | Out-String).Trim())
    if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {{
        [IO.File]::WriteAllBytes($stage, $pullBytes)
    }} else {{
        Set-Content -Path $stage -Value $pullBytes -Encoding Byte -Force
    }}
}}
"""
        scp_ps = _wrap_with_askpass_ps(
            scp_core_ps, ssh_password, stage_id, stage_dir=self.stage_dir
        )
        try:
            res = self._exec_hop(scp_ps, timeout_sec)
            if res.exit_code != 0:
                raise RuntimeError(
                    f"Failed to pull {node.name}:{remote_path} to hop host: {res.stderr or res.stdout}"
                )
            return self._pull_hop(hop_stage, local_path, timeout_sec)
        finally:
            self._exec_hop(
                f"Remove-Item ([Environment]::ExpandEnvironmentVariables('{hop_stage}')) -Force -ErrorAction SilentlyContinue",
                30.0,
            )
            if as_root:
                self.exec_node(
                    node,
                    f"rm -f '{remote_src}' '/dev/shm/.egw_pull_{stage_id}'",
                    as_root=True,
                    ssh_password=ssh_password,
                    sudo_password=sudo_password,
                    timeout_sec=30.0,
                    jump_node=jump_node,
                )

    def bootstrap_ssh_key(
        self,
        node: TargetNodeSpec,
        *,
        ssh_password: str = "",
        timeout_sec: float = 60.0,
        jump_node: TargetNodeSpec | None = None,
    ) -> ExecResult:
        """Ensure an ed25519 keypair exists on the hop host and install its public key onto TargetNode."""
        gen_ps = """
$sshDir = Join-Path $env:USERPROFILE '.ssh'
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Force -Path $sshDir | Out-Null }
$keyPath = Join-Path $sshDir 'id_ed25519'
$pubPath = "$keyPath.pub"
if (-not (Test-Path $pubPath)) {
    ssh-keygen.exe -t ed25519 -N '""' -f $keyPath | Out-Null
}
(Get-Content $pubPath -Raw -Encoding UTF8).Trim()
"""
        pub_res = self._exec_hop(gen_ps, 30.0)
        if pub_res.exit_code != 0 or not pub_res.stdout.strip():
            return ExecResult(
                exit_code=1,
                stdout="",
                stderr=f"Failed to read or generate hop SSH public key: {pub_res.stderr}",
                duration_ms=pub_res.duration_ms,
            )
        pub_key = pub_res.stdout.strip().splitlines()[-1].strip()
        pub_b64 = base64.b64encode(pub_key.encode("utf-8")).decode("ascii")
        install_sh = f"""
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
PUB=$(echo '{pub_b64}' | base64 -d)
grep -qxF "$PUB" ~/.ssh/authorized_keys || echo "$PUB" >> ~/.ssh/authorized_keys
echo "SSH_KEY_INSTALLED"
""".strip()
        return self.exec_node(
            node,
            install_sh,
            as_root=False,
            ssh_password=ssh_password,
            timeout_sec=timeout_sec,
            jump_node=jump_node,
        )
