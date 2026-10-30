"""Multi-hop OpenSSH execution and verified file transfer to upstream TargetNodes."""

from __future__ import annotations

import base64
import secrets
from pathlib import Path
from typing import Callable

from enclave_gateway.config import TargetNodeSpec
from enclave_gateway.control.qga_client import ExecResult


def build_remote_bash_invocation(
    script: str, *, as_root: bool = False
) -> str:
    """Encode a bash script in Base64 and strip CR characters before execution."""
    clean_script = script.replace("\r\n", "\n")
    b64_script = base64.b64encode(clean_script.encode("utf-8")).decode("ascii")
    if as_root:
        # First line of stdin is consumed by sudo -S, remaining script comes from base64
        return (
            f"sudo -S -p '' bash -c \"echo '{b64_script}' | base64 -d | tr -d '\\r' | bash\""
        )
    return f"echo '{b64_script}' | base64 -d | tr -d '\\r' | bash"


def build_powershell_ssh_hop_script(
    node: TargetNodeSpec,
    bash_script: str,
    *,
    as_root: bool = False,
    sudo_password: str = "",
    connect_timeout_sec: int = 15,
) -> str:
    """Build a PowerShell script that invokes ssh.exe on the hop host safely."""
    remote_cmd = build_remote_bash_invocation(bash_script, as_root=as_root)
    ssh_opts = [
        "-o BatchMode=yes",
        "-o StrictHostKeyChecking=no",
        f"-o ConnectTimeout={connect_timeout_sec}",
        f"-p {node.port}",
    ]
    if node.ssh_key_path:
        ssh_opts.append(f"-i {node.ssh_key_path}")
    opts_str = " ".join(ssh_opts)
    target_uri = f"{node.user}@{node.host}"

    if as_root and sudo_password:
        clean_pw = sudo_password.rstrip("\r\n")
        pw_b64 = base64.b64encode((clean_pw + "\n").encode("utf-8")).decode("ascii")
        token_id = secrets.token_hex(6)
        return f"""
$secDir = Join-Path $env:TEMP 'enclave_gw_sec'
if (-not (Test-Path $secDir)) {{ New-Item -ItemType Directory -Force -Path $secDir | Out-Null }}
$secFile = Join-Path $secDir 's_{token_id}.bin'
try {{
    [IO.File]::WriteAllBytes($secFile, [Convert]::FromBase64String('{pw_b64}'))
    cmd.exe /c "type `"$secFile`" | ssh.exe -T {opts_str} {target_uri} `{remote_cmd}`"
    exit $LASTEXITCODE
}} finally {{
    Remove-Item $secFile -Force -ErrorAction SilentlyContinue
}}
""".strip()

    return f"""
ssh.exe -n -T {opts_str} {target_uri} '{remote_cmd}'
exit $LASTEXITCODE
""".strip()


class SshHopExecutor:
    """Executes commands and transfers files to TargetNodes via Bastion or Appliance."""

    def __init__(
        self,
        exec_hop_fn: Callable[[str, float], ExecResult],
        push_hop_fn: Callable[[Path, str, float], str],
        pull_hop_fn: Callable[[str, Path, float], str],
    ) -> None:
        self._exec_hop = exec_hop_fn
        self._push_hop = push_hop_fn
        self._pull_hop = pull_hop_fn

    def exec_node(
        self,
        node: TargetNodeSpec,
        bash_script: str,
        *,
        as_root: bool = False,
        sudo_password: str = "",
        timeout_sec: float = 120.0,
    ) -> ExecResult:
        hop_ps = build_powershell_ssh_hop_script(
            node,
            bash_script,
            as_root=as_root,
            sudo_password=sudo_password,
        )
        return self._exec_hop(hop_ps, timeout_sec)

    def push_file_to_node(
        self,
        node: TargetNodeSpec,
        local_path: Path,
        remote_path: str,
        *,
        timeout_sec: float = 900.0,
    ) -> str:
        """Two-hop verified file delivery: Host -> Hop staging -> SCP -> TargetNode."""
        stage_id = secrets.token_hex(6)
        hop_stage = f"C:\\Windows\\Temp\\egw_stage_{stage_id}_{local_path.name}"
        expected_sha = self._push_hop(local_path, hop_stage, timeout_sec)

        scp_ps = f"""
$stage = '{hop_stage}'
try {{
    scp.exe -B -o StrictHostKeyChecking=no -P {node.port} $stage '{node.user}@{node.host}:{remote_path}.tmp_{stage_id}'
    if ($LASTEXITCODE -ne 0) {{ Write-Error 'SCP transfer to target node failed'; exit 1 }}
    $verifyCmd = "sha=\\$(sha256sum '{remote_path}.tmp_{stage_id}' | awk '{{print tolower(\\$1)}}'); if [ \\"\\$sha\\" != '{expected_sha}' ]; then rm -f '{remote_path}.tmp_{stage_id}'; echo 'MISMATCH' >&2; exit 1; fi; mv -f '{remote_path}.tmp_{stage_id}' '{remote_path}'; echo 'VERIFIED:'\\$sha"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($verifyCmd))
    ssh.exe -n -o BatchMode=yes -o StrictHostKeyChecking=no -p {node.port} '{node.user}@{node.host}' "echo $b64 | base64 -d | bash"
    exit $LASTEXITCODE
}} finally {{
    Remove-Item $stage -Force -ErrorAction SilentlyContinue
}}
"""
        res = self._exec_hop(scp_ps, timeout_sec)
        if res.exit_code != 0 or f"VERIFIED:{expected_sha}" not in res.stdout:
            raise RuntimeError(
                f"TargetNode transfer failed for {node.name}:{remote_path}: {res.stderr or res.stdout}"
            )
        return expected_sha

    def pull_file_from_node(
        self,
        node: TargetNodeSpec,
        remote_path: str,
        local_path: Path,
        *,
        timeout_sec: float = 600.0,
    ) -> str:
        """Two-hop verified file retrieval: TargetNode -> SCP -> Hop staging -> Host."""
        stage_id = secrets.token_hex(6)
        hop_stage = f"C:\\Windows\\Temp\\egw_pull_{stage_id}_{local_path.name}"
        scp_ps = f"""
scp.exe -B -o StrictHostKeyChecking=no -P {node.port} '{node.user}@{node.host}:{remote_path}' '{hop_stage}'
if ($LASTEXITCODE -ne 0) {{ Write-Error 'SCP pull from target node failed'; exit 1 }}
"""
        res = self._exec_hop(scp_ps, timeout_sec)
        if res.exit_code != 0:
            raise RuntimeError(
                f"Failed to pull {node.name}:{remote_path} to hop host: {res.stderr}"
            )
        try:
            return self._pull_hop(hop_stage, local_path, timeout_sec)
        finally:
            self._exec_hop(
                f"Remove-Item '{hop_stage}' -Force -ErrorAction SilentlyContinue", 30.0
            )
