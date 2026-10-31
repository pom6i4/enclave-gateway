"""High-level Enclave Gateway orchestration engine and multi-hop router."""

from __future__ import annotations

import base64
import fnmatch
import json
import re
import secrets
import shlex
import tarfile
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

DEFAULT_SYNC_EXCLUDES = (
    ".git",
    "__pycache__",
    ".DS_Store",
    ".venv",
    "node_modules",
    "*.pyc",
)
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.config import EnclaveConfig, TargetNodeSpec
from enclave_gateway.control.qga_client import (
    ControlChannel,
    DirectHostControlChannel,
    ExecResult,
    QgaClient,
)
from enclave_gateway.hypervisor.driver import ApplianceHypervisor
from enclave_gateway.security.secrets import SecretVault, verify_command_safety
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, generate_tx_id
from enclave_gateway.transports.ssh_hop import SshHopExecutor


class EnclaveEngine:
    """Routes commands, file transfers, database queries, and HTTP requests across the enclave."""

    def __init__(
        self,
        config: EnclaveConfig | None = None,
        vault: SecretVault | None = None,
        recorder: FlightRecorder | None = None,
        control_override: ControlChannel | None = None,
    ) -> None:
        self.config = config or EnclaveConfig.load()
        self.vault = vault or SecretVault()
        self.recorder = recorder or FlightRecorder()
        self.hypervisor = ApplianceHypervisor(self.config.appliance)

        if control_override is not None:
            self.control: ControlChannel = control_override
        elif self.config.appliance.hypervisor == "direct":
            self.control = DirectHostControlChannel()
        else:
            self.control = QgaClient(
                self.config.appliance.qga_socket,
                self.config.appliance.qga_lock_file,
            )

        self.rdp_vfs = RdpVfsTransport(self.control, self.config.bastion)
        self.bastion_ssh = SshHopExecutor(
            exec_hop_fn=self.rdp_vfs.exec_bastion,
            push_hop_fn=self._push_bastion_vfs_stage,
            pull_hop_fn=self._pull_bastion_vfs_stage,
            stage_dir=self.config.bastion.bastion_spool_dir,
        )
        self.appliance_ssh = SshHopExecutor(
            exec_hop_fn=self.control.exec_powershell,
            push_hop_fn=self._push_to_appliance_with_sha,
            pull_hop_fn=self._pull_from_appliance_with_sha,
        )

    def _push_bastion_vfs_stage(
        self, local_path: Path, hop_stage: str, timeout: float
    ) -> str:
        vfs_root = self.config.bastion.bastion_spool_dir.rstrip("\\/")
        if hop_stage.startswith(vfs_root):
            filename = hop_stage.replace("/", "\\").rsplit("\\", 1)[-1]
            app_spool_file = (
                f"{self.config.bastion.appliance_spool_dir.rstrip('\\/')}\\{filename}"
            )
            return self._push_to_appliance_with_sha(local_path, app_spool_file, timeout)
        return self.rdp_vfs.push_file(
            local_path, hop_stage, use_delta=True, timeout_sec=timeout
        )

    def _pull_bastion_vfs_stage(
        self, hop_stage: str, local_path: Path, timeout: float
    ) -> str:
        vfs_root = self.config.bastion.bastion_spool_dir.rstrip("\\/")
        if hop_stage.startswith(vfs_root):
            filename = hop_stage.replace("/", "\\").rsplit("\\", 1)[-1]
            app_spool_file = (
                f"{self.config.bastion.appliance_spool_dir.rstrip('\\/')}\\{filename}"
            )
            return self._pull_from_appliance_with_sha(
                app_spool_file, local_path, timeout
            )
        return self.rdp_vfs.pull_file(hop_stage, local_path, timeout_sec=timeout)

    def _push_to_appliance_with_sha(
        self, local_path: Path, guest_path: str, _timeout: float
    ) -> str:
        from enclave_gateway.transports.rdp_vfs import compute_file_sha256

        sha = compute_file_sha256(local_path)
        self.control.write_file(local_path, guest_path)
        return sha

    def _pull_from_appliance_with_sha(
        self, guest_path: str, local_path: Path, _timeout: float
    ) -> str:
        from enclave_gateway.transports.rdp_vfs import compute_file_sha256

        self.control.read_file(guest_path, local_path)
        return compute_file_sha256(local_path)

    def _scrub_result(self, res: ExecResult) -> ExecResult:
        return ExecResult(
            exit_code=res.exit_code,
            stdout=self.vault.scrubber.scrub(res.stdout),
            stderr=self.vault.scrubber.scrub(res.stderr),
            duration_ms=res.duration_ms,
        )

    def status(self) -> dict[str, Any]:
        """Collect health telemetry across Appliance, VPN provider, and Bastion."""
        vm_running, pid = self.hypervisor.is_running()
        report: dict[str, Any] = {
            "profile": self.config.profile,
            "appliance": {
                "name": self.config.appliance.name,
                "running": vm_running,
                "pid": pid,
                "hypervisor": self.config.appliance.hypervisor,
            },
            "provider": {
                "type": self.config.provider.type,
                "probe_host": self.config.provider.probe_host,
                "probe_port": self.config.provider.probe_port,
                "tunnel_up": False,
                "details": "",
            },
            "bastion": {
                "enabled": self.config.bastion.enabled,
                "host": self.config.bastion.host,
                "worker_healthy": False,
                "worker_state": None,
            },
            "targets": list(self.config.targets.keys()),
        }

        if not vm_running and self.config.appliance.hypervisor != "direct":
            return report

        probe_ps = f"""
$info = ""
$ptype = '{self.config.provider.type}'.ToLower()
if ($ptype -eq 'vipnet' -and (Test-Path '{self.config.provider.binary_path}')) {{
    $info = (& '{self.config.provider.binary_path}' info | Out-String).Trim()
}} elseif ($ptype -eq 'wireguard') {{
    if (Get-Command wg.exe -ErrorAction SilentlyContinue) {{
        $info = (& wg.exe show | Out-String).Trim()
    }} else {{
        $info = (Get-Service 'WireGuardTunnel*' -ErrorAction SilentlyContinue | Select-Object Name, Status | Out-String).Trim()
    }}
}} elseif ($ptype -eq 'anyconnect' -and (Test-Path '{self.config.provider.binary_path}')) {{
    $info = (& '{self.config.provider.binary_path}' state | Out-String).Trim()
}} elseif ($ptype -in @('openvpn', 'kontinent', 'custom')) {{
    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceDescription -like '*{self.config.provider.adapter_name}*' -or $_.Name -like '*{self.config.provider.adapter_name}*' }}
    if ($adapter) {{
        $info = ($adapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed | Out-String).Trim()
    }}
}}
$tcp = Test-NetConnection -ComputerName '{self.config.provider.probe_host}' -Port {self.config.provider.probe_port} -WarningAction SilentlyContinue
$spool = '{self.config.bastion.appliance_spool_dir}'
$stateJson = ""
$statePath = Join-Path $spool 'worker_state.json'
if (Test-Path $statePath) {{
    $age = ((Get-Date) - (Get-Item $statePath).LastWriteTime).TotalSeconds
    if ($age -lt 10) {{
        $stateJson = (Get-Content $statePath -Raw -Encoding UTF8).Trim()
    }}
}}
$out = @{{
    tunnel_up = [bool]$tcp.TcpTestSucceeded
    source_ip = [string]$tcp.SourceAddress
    vpn_info  = $info
    worker    = $stateJson
}}
ConvertTo-Json $out -Compress
"""
        try:
            res = self.control.exec_powershell(probe_ps, timeout_sec=20.0)
            if res.exit_code == 0 and res.stdout:
                data = json.loads(res.stdout.splitlines()[-1])
                report["provider"]["tunnel_up"] = bool(data.get("tunnel_up"))
                report["provider"]["source_ip"] = data.get("source_ip", "")
                report["provider"]["details"] = self.vault.scrubber.scrub(
                    str(data.get("vpn_info", ""))
                )
                worker_raw = data.get("worker")
                if worker_raw:
                    try:
                        report["bastion"]["worker_state"] = json.loads(worker_raw)
                        report["bastion"]["worker_healthy"] = True
                    except json.JSONDecodeError:
                        pass
        except Exception as exc:
            report["provider"]["details"] = f"Status probe error: {exc}"

        return report

    def heal(self, *, update_credentials: bool = False, actor: str = "cli") -> ExecResult:
        """Self-heal clock drift, MTU, RDP UDP policy, interactive credentials, and Bastion RDP session."""
        tx_id = generate_tx_id()
        sync_fn = getattr(self.control, "sync_guest_clock", None)
        if callable(sync_fn):
            sync_fn()

        agents_dir = Path(__file__).resolve().parent / "agents"
        init_script = (agents_dir / "appliance_init.ps1").read_text(encoding="utf-8")
        sup_script = (agents_dir / "session_supervisor.ps1").read_text(encoding="utf-8")

        domain = self.vault.get(self.config.bastion.domain_env)
        user = self.vault.get(self.config.bastion.user_env)
        password = self.vault.get(self.config.bastion.password_env)
        domain_user = f"{domain}\\{user}" if domain and user else user

        cred_args = ""
        if update_credentials and domain_user and password:
            pw_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
            cred_args = f"-RdpDomainUser '{domain_user}' -RdpPasswordB64 '{pw_b64}'"

        host_epoch = int(time.time())
        routes_csv = ",".join(self.config.provider.routes)
        dns_csv = ",".join(self.config.provider.dns_servers)

        combined_ps = f"""
& {{
{init_script}
}} -Mtu {self.config.appliance.mtu} -AdapterName '{self.config.provider.adapter_name}' -BastionHost '{self.config.bastion.host}' -BastionPort {self.config.bastion.port} -HostEpochUtc {host_epoch} -RoutesCsv '{routes_csv}' -DnsServersCsv '{dns_csv}'

& {{
{sup_script}
}} -BastionHost '{self.config.bastion.host}' -BastionPort {self.config.bastion.port} -SpoolDir '{self.config.bastion.appliance_spool_dir}' -ScheduledTaskName '{self.config.bastion.scheduled_task_name}' {cred_args} -ForceReconnect
"""
        res = self._scrub_result(self.control.exec_powershell(combined_ps, timeout_sec=60.0))
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation="heal",
            node="@appliance",
            summary="Heal appliance clock, MTU, UDP policy, and Bastion session",
            exit_code=res.exit_code,
            duration_ms=res.duration_ms,
        )
        return res

    def _inject_env_into_script(
        self,
        script: str,
        *,
        is_powershell: bool,
        env: dict[str, str] | None = None,
        secret_env: dict[str, str] | None = None,
    ) -> str:
        merged: dict[str, str] = {}
        for k, v in (env or {}).items():
            if not _ENV_KEY_RE.match(k):
                raise ValueError(f"Invalid environment variable name: {k}")
            merged[k] = str(v)

        for env_key, vault_key in (secret_env or {}).items():
            if not _ENV_KEY_RE.match(env_key):
                raise ValueError(f"Invalid environment variable name: {env_key}")
            val = self.vault.get(vault_key)
            if not val:
                raise KeyError(
                    f"Secret '{vault_key}' for environment variable '{env_key}' is not set in SecretVault"
                )
            self.vault.scrubber.register(val)
            merged[env_key] = val

        if not merged:
            return script

        prefix_lines: list[str] = []
        for k, val_str in merged.items():
            val_b64 = base64.b64encode(val_str.encode("utf-8")).decode("ascii")
            if is_powershell:
                prefix_lines.append(
                    f"$env:{k} = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{val_b64}'))"
                )
            else:
                prefix_lines.append(f"export {k}=\"$(echo '{val_b64}' | base64 -d)\"")
        return "\n".join(prefix_lines) + "\n" + script

    def _is_powershell_node(self, node: str) -> bool:
        if node in ("@appliance", "appliance", "@bastion", "bastion"):
            return True
        if node in self.config.targets:
            return self.config.targets[node].os.lower() in (
                "windows",
                "win",
                "powershell",
            )
        return False

    def exec_node(
        self,
        node: str,
        script: str,
        *,
        as_root: bool = False,
        confirm_destructive: bool = False,
        env: dict[str, str] | None = None,
        secret_env: dict[str, str] | None = None,
        timeout_sec: float = 120.0,
        actor: str = "cli",
    ) -> ExecResult:
        """Execute a script on @appliance, @bastion, or a named TargetNode."""
        verify_command_safety(script, confirm_destructive=confirm_destructive)
        tx_id = generate_tx_id()
        is_ps = self._is_powershell_node(node)
        full_script = self._inject_env_into_script(
            script, is_powershell=is_ps, env=env, secret_env=secret_env
        )

        if node in ("@appliance", "appliance"):
            raw_res = self.control.exec_powershell(full_script, timeout_sec=timeout_sec)
        elif node in ("@bastion", "bastion"):
            raw_res = self.rdp_vfs.exec_bastion(full_script, timeout_sec=timeout_sec)
        else:
            target = self._resolve_target(node)
            ssh_pw = (
                self.vault.get(target.password_env) if target.password_env else ""
            )
            sudo_pw = (
                self.vault.get(target.sudo_password_env)
                if as_root and target.sudo_password_env
                else ""
            )
            hop, jump_node = self._resolve_hop_and_jump(target)
            raw_res = hop.exec_node(
                target,
                full_script,
                as_root=as_root,
                ssh_password=ssh_pw,
                sudo_password=sudo_pw,
                timeout_sec=timeout_sec,
                jump_node=jump_node,
            )

        clean_res = self._scrub_result(raw_res)
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation="exec_root" if as_root else "exec",
            node=node,
            summary=self.vault.scrubber.scrub(script.strip().splitlines()[0] if script.strip() else ""),
            exit_code=clean_res.exit_code,
            duration_ms=clean_res.duration_ms,
        )
        return clean_res

    def transfer_file(
        self,
        direction: str,
        local_path: str | Path,
        node: str,
        remote_path: str,
        *,
        as_root: bool = False,
        use_delta: bool = True,
        timeout_sec: float = 900.0,
        actor: str = "cli",
    ) -> dict[str, Any]:
        """Push or pull a file between Host and @appliance, @bastion, or a TargetNode."""
        tx_id = generate_tx_id()
        started = time.monotonic()
        lpath = Path(local_path).expanduser().resolve()

        if direction == "push":
            if not lpath.is_file():
                raise FileNotFoundError(f"Local file not found: {lpath}")
            if node in ("@appliance", "appliance"):
                sha = self._push_to_appliance_with_sha(lpath, remote_path, timeout_sec)
            elif node in ("@bastion", "bastion"):
                sha = self.rdp_vfs.push_file(
                    lpath, remote_path, use_delta=use_delta, timeout_sec=timeout_sec
                )
            else:
                target = self._resolve_target(node)
                ssh_pw = (
                    self.vault.get(target.password_env) if target.password_env else ""
                )
                sudo_pw = (
                    self.vault.get(target.sudo_password_env)
                    if as_root and target.sudo_password_env
                    else ""
                )
                hop, jump_node = self._resolve_hop_and_jump(target)
                sha = hop.push_file_to_node(
                    target,
                    lpath,
                    remote_path,
                    as_root=as_root,
                    ssh_password=ssh_pw,
                    sudo_password=sudo_pw,
                    timeout_sec=timeout_sec,
                    jump_node=jump_node,
                )
        elif direction == "pull":
            if node in ("@appliance", "appliance"):
                sha = self._pull_from_appliance_with_sha(remote_path, lpath, timeout_sec)
            elif node in ("@bastion", "bastion"):
                sha = self.rdp_vfs.pull_file(remote_path, lpath, timeout_sec=timeout_sec)
            else:
                target = self._resolve_target(node)
                ssh_pw = (
                    self.vault.get(target.password_env) if target.password_env else ""
                )
                sudo_pw = (
                    self.vault.get(target.sudo_password_env)
                    if as_root and target.sudo_password_env
                    else ""
                )
                hop, jump_node = self._resolve_hop_and_jump(target)
                sha = hop.pull_file_from_node(
                    target,
                    remote_path,
                    lpath,
                    as_root=as_root,
                    ssh_password=ssh_pw,
                    sudo_password=sudo_pw,
                    timeout_sec=timeout_sec,
                    jump_node=jump_node,
                )
        else:
            raise ValueError(f"Unsupported transfer direction '{direction}' (use 'push' or 'pull')")

        duration_ms = int((time.monotonic() - started) * 1000)
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation=f"transfer_{direction}{'_root' if as_root else ''}",
            node=node,
            summary=f"{lpath.name} <-> {node}:{remote_path}",
            exit_code=0,
            duration_ms=duration_ms,
            sha256=sha,
        )
        return {
            "tx_id": tx_id,
            "direction": direction,
            "node": node,
            "as_root": as_root,
            "local_path": str(lpath),
            "remote_path": remote_path,
            "sha256": sha,
            "duration_ms": duration_ms,
        }

    def sync_directory(
        self,
        direction: str,
        local_dir: str | Path,
        node: str,
        remote_dir: str,
        *,
        as_root: bool = False,
        exclude: list[str] | None = None,
        timeout_sec: float = 900.0,
        actor: str = "cli",
    ) -> dict[str, Any]:
        """Batch-synchronize a directory between Host and @appliance, @bastion, or a TargetNode via streaming tar.gz."""
        tx_id = generate_tx_id()
        started = time.monotonic()
        ldir = Path(local_dir).expanduser().resolve()
        patterns = list(DEFAULT_SYNC_EXCLUDES) + list(exclude or [])
        sync_id = secrets.token_hex(6)
        is_windows_node = node in ("@appliance", "appliance", "@bastion", "bastion")

        def _is_excluded(rel_posix: str, name: str) -> bool:
            for pat in patterns:
                if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_posix, pat):
                    return True
                for part in rel_posix.split("/"):
                    if fnmatch.fnmatch(part, pat):
                        return True
            return False

        with TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / f"egw_sync_{sync_id}.tar.gz"
            files_synced = 0

            if direction == "push":
                if not ldir.is_dir():
                    raise NotADirectoryError(f"Local directory not found: {ldir}")

                with tarfile.open(archive_path, "w:gz") as tf:
                    for item in sorted(ldir.rglob("*")):
                        rel = item.relative_to(ldir).as_posix()
                        if _is_excluded(rel, item.name):
                            continue
                        tf.add(item, arcname=rel, recursive=False)
                        if item.is_file():
                            files_synced += 1

                archive_bytes = archive_path.stat().st_size
                if node in ("@bastion", "bastion"):
                    remote_stage = f"{self.config.bastion.bastion_spool_dir.rstrip(chr(92) + '/')}\\egw_sync_{sync_id}.tar.gz"
                elif is_windows_node:
                    remote_stage = f"%LOCALAPPDATA%\\EnclaveGateway\\stage\\egw_sync_{sync_id}.tar.gz"
                else:
                    remote_stage = f"/tmp/.egw_sync_{sync_id}.tar.gz"
                tx_meta = self.transfer_file(
                    "push",
                    archive_path,
                    node,
                    remote_stage,
                    as_root=False,
                    use_delta=True,
                    timeout_sec=timeout_sec,
                    actor=actor,
                )
                sha = tx_meta["sha256"]

                if is_windows_node:
                    extract_ps = f"""
$stage = [Environment]::ExpandEnvironmentVariables('{remote_stage}')
$dst = [Environment]::ExpandEnvironmentVariables('{remote_dir}')
try {{
    if (-not (Test-Path $dst)) {{ New-Item -ItemType Directory -Force -Path $dst | Out-Null }}
    tar.exe -xzf $stage -C $dst
    if ($LASTEXITCODE -ne 0) {{ Write-Error 'tar.exe extraction failed'; exit 1 }}
    Write-Output 'SYNC_EXTRACT_OK'
}} finally {{
    Remove-Item $stage -Force -ErrorAction SilentlyContinue
}}
"""
                    ext_res = self.exec_node(
                        node, extract_ps, timeout_sec=timeout_sec, actor=actor
                    )
                else:
                    extract_sh = f"""
set -e
trap "rm -f '{remote_stage}'" EXIT
mkdir -p '{remote_dir}'
tar -xzf '{remote_stage}' -C '{remote_dir}'
echo "SYNC_EXTRACT_OK"
""".strip()
                    ext_res = self.exec_node(
                        node,
                        extract_sh,
                        as_root=as_root,
                        timeout_sec=timeout_sec,
                        actor=actor,
                    )

                if ext_res.exit_code != 0 or "SYNC_EXTRACT_OK" not in ext_res.stdout:
                    raise RuntimeError(
                        f"Directory sync extraction failed on {node}:{remote_dir}: {ext_res.stderr or ext_res.stdout}"
                    )

            elif direction == "pull":
                if node in ("@bastion", "bastion"):
                    remote_stage = f"{self.config.bastion.bastion_spool_dir.rstrip(chr(92) + '/')}\\egw_sync_pull_{sync_id}.tar.gz"
                elif is_windows_node:
                    remote_stage = f"%LOCALAPPDATA%\\EnclaveGateway\\stage\\egw_sync_pull_{sync_id}.tar.gz"
                else:
                    remote_stage = f"/tmp/.egw_sync_pull_{sync_id}.tar.gz"
                if is_windows_node:
                    pack_ps = f"""
$src = [Environment]::ExpandEnvironmentVariables('{remote_dir}')
$stage = [Environment]::ExpandEnvironmentVariables('{remote_stage}')
$parent = Split-Path -Parent $stage
if ($parent -and -not (Test-Path $parent)) {{ New-Item -ItemType Directory -Force -Path $parent | Out-Null }}
tar.exe -czf $stage -C $src .
if ($LASTEXITCODE -ne 0) {{ Write-Error 'tar.exe archive creation failed'; exit 1 }}
Write-Output 'SYNC_PACK_OK'
"""
                    pack_res = self.exec_node(
                        node, pack_ps, timeout_sec=timeout_sec, actor=actor
                    )
                else:
                    excl_flags = " ".join(
                        f"--exclude={shlex.quote(p)}" for p in patterns
                    )
                    target_user = self._resolve_target(node).user
                    chown_line = (
                        f"chown '{target_user}' '{remote_stage}' && chmod 600 '{remote_stage}'"
                        if as_root
                        else f"chmod 600 '{remote_stage}'"
                    )
                    pack_sh = f"""
set -e
tar -czf '{remote_stage}' {excl_flags} -C '{remote_dir}' .
{chown_line}
echo "SYNC_PACK_OK"
""".strip()
                    pack_res = self.exec_node(
                        node,
                        pack_sh,
                        as_root=as_root,
                        timeout_sec=timeout_sec,
                        actor=actor,
                    )

                if pack_res.exit_code != 0 or "SYNC_PACK_OK" not in pack_res.stdout:
                    raise RuntimeError(
                        f"Directory sync archive creation failed on {node}:{remote_dir}: {pack_res.stderr or pack_res.stdout}"
                    )

                try:
                    tx_meta = self.transfer_file(
                        "pull",
                        archive_path,
                        node,
                        remote_stage,
                        as_root=False,
                        timeout_sec=timeout_sec,
                        actor=actor,
                    )
                    sha = tx_meta["sha256"]
                    archive_bytes = archive_path.stat().st_size
                finally:
                    cleanup_cmd = (
                        f"Remove-Item ([Environment]::ExpandEnvironmentVariables('{remote_stage}')) -Force -ErrorAction SilentlyContinue"
                        if is_windows_node
                        else f"rm -f '{remote_stage}'"
                    )
                    self.exec_node(
                        node,
                        cleanup_cmd,
                        as_root=as_root and not is_windows_node,
                        timeout_sec=30.0,
                        actor=actor,
                    )

                ldir.mkdir(parents=True, exist_ok=True)
                with tarfile.open(archive_path, "r:gz") as tf:
                    for member in tf.getmembers():
                        member_dest = (ldir / member.name).resolve()
                        if not str(member_dest).startswith(str(ldir)):
                            raise ValueError(
                                f"Refusing to extract unsafe tar member path: {member.name}"
                            )
                        tf.extract(member, path=ldir)
                        if member.isfile():
                            files_synced += 1
            else:
                raise ValueError(
                    f"Unsupported sync direction '{direction}' (use 'push' or 'pull')"
                )

        duration_ms = int((time.monotonic() - started) * 1000)
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation=f"sync_{direction}{'_root' if as_root else ''}",
            node=node,
            summary=f"{ldir.name} <-> {node}:{remote_dir} ({files_synced} files)",
            exit_code=0,
            duration_ms=duration_ms,
            sha256=sha,
        )
        return {
            "tx_id": tx_id,
            "direction": direction,
            "node": node,
            "as_root": as_root,
            "local_dir": str(ldir),
            "remote_dir": remote_dir,
            "files_synced": files_synced,
            "archive_bytes": archive_bytes,
            "sha256": sha,
            "duration_ms": duration_ms,
        }

    def bootstrap_ssh_key(self, node: str, *, actor: str = "cli") -> ExecResult:
        """Generate hop host SSH keypair if missing and install public key onto TargetNode."""
        tx_id = generate_tx_id()
        target = self._resolve_target(node)
        ssh_pw = self.vault.get(target.password_env) if target.password_env else ""
        hop, jump_node = self._resolve_hop_and_jump(target)
        raw_res = hop.bootstrap_ssh_key(
            target, ssh_password=ssh_pw, jump_node=jump_node
        )
        clean_res = self._scrub_result(raw_res)
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation="ssh_copy_id",
            node=node,
            summary=f"Install hop SSH public key onto {target.user}@{target.host}:{target.port}",
            exit_code=clean_res.exit_code,
            duration_ms=clean_res.duration_ms,
        )
        return clean_res

    def doctor(
        self,
        *,
        fix: bool = False,
        probe_targets: bool = False,
        actor: str = "cli",
    ) -> dict[str, Any]:
        """Run end-to-end L1-L7 diagnostic checklist across Host, Appliance, VPN, Bastion, and Targets."""
        st = self.status()
        checks: list[dict[str, Any]] = []
        needs_heal = False

        vm_ok = bool(st["appliance"]["running"]) or st["appliance"]["hypervisor"] == "direct"
        checks.append(
            {
                "check": "appliance_vm",
                "ok": vm_ok,
                "detail": f"Hypervisor={st['appliance']['hypervisor']}, PID={st['appliance']['pid']}",
            }
        )

        # Check clock skew and UDP policy on Appliance if reachable
        clock_skew_sec = 0
        udp_disabled = True
        if vm_ok:
            diag_ps = """
$epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$udpPol = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Client' -Name 'fClientDisableUDP' -ErrorAction SilentlyContinue).fClientDisableUDP
Write-Output ("DIAG_CLOCK:" + $epoch + ":UDP:" + [int]$udpPol)
"""
            diag_res = self.control.exec_powershell(diag_ps, timeout_sec=15.0)
            if diag_res.exit_code == 0 and "DIAG_CLOCK:" in diag_res.stdout:
                marker = [
                    ln.strip()
                    for ln in diag_res.stdout.splitlines()
                    if ln.strip().startswith("DIAG_CLOCK:")
                ][0]
                parts = marker.split(":")
                guest_epoch = int(parts[1])
                clock_skew_sec = abs(int(time.time()) - guest_epoch)
                udp_disabled = int(parts[3]) == 1

        clock_ok = clock_skew_sec < 120
        if not clock_ok:
            needs_heal = True
        checks.append(
            {
                "check": "appliance_clock_sync",
                "ok": clock_ok,
                "detail": f"Clock skew={clock_skew_sec}s (Kerberos/NLA limit is 300s)",
            }
        )

        checks.append(
            {
                "check": "rdp_udp_blackhole_guard",
                "ok": udp_disabled,
                "detail": f"fClientDisableUDP={'1 (TCP-only)' if udp_disabled else '0 (vulnerable to UDP drops)'}",
            }
        )
        if not udp_disabled:
            needs_heal = True

        tun_ok = bool(st["provider"]["tunnel_up"])
        checks.append(
            {
                "check": "vpn_tunnel_probe",
                "ok": tun_ok,
                "detail": f"Target={st['provider']['probe_host']}:{st['provider']['probe_port']}",
            }
        )

        wrk_ok = bool(st["bastion"]["worker_healthy"])
        vfs_rtt_ms: int | None = None
        if wrk_ok:
            ping_res = self.rdp_vfs.exec_bastion(
                "Write-Output 'VFS_PONG'", timeout_sec=10.0
            )
            if ping_res.exit_code == 0 and "VFS_PONG" in ping_res.stdout:
                vfs_rtt_ms = ping_res.duration_ms
            else:
                wrk_ok = False

        if not wrk_ok:
            needs_heal = True
        checks.append(
            {
                "check": "bastion_rdp_vfs_ipc",
                "ok": wrk_ok,
                "detail": f"Worker healthy={wrk_ok}, RTT={vfs_rtt_ms if vfs_rtt_ms is not None else '-'}ms",
            }
        )

        if probe_targets and wrk_ok:
            for t_name in self.config.targets:
                t_res = self.exec_node(t_name, "echo TARGET_SSH_OK", timeout_sec=20.0, actor=actor)
                checks.append(
                    {
                        "check": f"target_ssh:{t_name}",
                        "ok": t_res.exit_code == 0 and "TARGET_SSH_OK" in t_res.stdout,
                        "detail": t_res.stdout or t_res.stderr,
                    }
                )

        healed = False
        if fix and needs_heal and vm_ok:
            self.heal(actor=actor)
            healed = True

        all_ok = all(bool(c["ok"]) for c in checks)
        return {
            "healthy": all_ok,
            "auto_healed": healed,
            "checks": checks,
        }

    def clean_session(self, *, actor: str = "cli") -> dict[str, Any]:
        """Purge transient spool chunks, staging files, and idle multiplexed sockets across tiers."""
        tx_id = generate_tx_id()
        started = time.monotonic()

        bastion_clean_ps = """
if ($Global:EnclaveMuxSockets) {
    foreach ($k in @($Global:EnclaveMuxSockets.Keys)) {
        try { $Global:EnclaveMuxSockets[$k].Client.Close() } catch {}
    }
    $Global:EnclaveMuxSockets.Clear()
}
$stageDir = Join-Path $env:LOCALAPPDATA 'EnclaveGateway\\stage'
if (Test-Path $stageDir) {
    Get-ChildItem -Path $stageDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}
Write-Output 'BASTION_CLEAN_OK'
"""
        bastion_res = self.rdp_vfs.exec_bastion(bastion_clean_ps, timeout_sec=20.0)

        spool = self.config.bastion.appliance_spool_dir
        appliance_clean_ps = f"""
$spool = '{spool}'
if (Test-Path $spool) {{
    Get-ChildItem -Path $spool -Include '*.tmp', 'req_*.json', 'res_*.json', 'chunk_*.bin', 'pull_*.bin', 'egw_stage_*', 'egw_pull_*' -File -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}}
Write-Output 'APPLIANCE_CLEAN_OK'
"""
        app_res = self.control.exec_powershell(appliance_clean_ps, timeout_sec=15.0)

        duration_ms = int((time.monotonic() - started) * 1000)
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation="clean",
            node="@all",
            summary="Purge transient spool and staging files across Appliance and Bastion",
            exit_code=0 if (bastion_res.exit_code == 0 and app_res.exit_code == 0) else 1,
            duration_ms=duration_ms,
        )
        return {
            "tx_id": tx_id,
            "appliance_cleaned": app_res.exit_code == 0,
            "bastion_cleaned": bastion_res.exit_code == 0,
            "duration_ms": duration_ms,
        }

    def generate_ssh_config(
        self,
        *,
        config_path: str | None = None,
        prefix: str = "enclave-",
    ) -> str:
        """Generate an OpenSSH ~/.ssh/config block using `egw stdio-proxy %h %p`."""
        cfg_flag = f" -c {shlex.quote(config_path)}" if config_path else ""
        lines = [
            f"# Enclave Gateway OpenSSH ProxyCommand Configuration (profile: {self.config.profile})"
        ]
        for name, spec in sorted(self.config.targets.items()):
            host_alias = f"{prefix}{name}" if prefix else name
            lines.extend(
                [
                    f"Host {host_alias}",
                    f"    HostName {spec.host}",
                    f"    Port {spec.port}",
                    f"    User {spec.user}",
                ]
            )
            if spec.via in self.config.targets and spec.via != name:
                jump_alias = f"{prefix}{spec.via}" if prefix else spec.via
                lines.append(f"    ProxyJump {jump_alias}")
            else:
                lines.append(f"    ProxyCommand egw{cfg_flag} stdio-proxy %h %p")
            lines.extend(
                [
                    "    StrictHostKeyChecking no",
                    "    UserKnownHostsFile /dev/null",
                ]
            )
            if spec.ssh_key_path:
                lines.append(f"    IdentityFile {spec.ssh_key_path}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def build_ssh_command(
        self,
        node: str,
        extra_args: list[str] | None = None,
        *,
        config_path: str | None = None,
    ) -> list[str]:
        """Build a host OpenSSH client command line that tunnels directly via `egw stdio-proxy`."""
        target = self._resolve_target(node)
        cfg_flag = f" -c {shlex.quote(config_path)}" if config_path else ""
        cmd = [
            "ssh",
            "-o",
            f"ProxyCommand=egw{cfg_flag} stdio-proxy %h %p",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            str(target.port),
        ]
        _, jump_chain = self._resolve_hop_and_jump(target)
        if jump_chain:
            jump_list = (
                jump_chain if isinstance(jump_chain, list) else [jump_chain]
            )
            cmd.extend(
                ["-J", ",".join(f"{j.user}@{j.host}:{j.port}" for j in jump_list)]
            )
        if target.ssh_key_path:
            cmd.extend(["-i", target.ssh_key_path])
        cmd.append(f"{target.user}@{target.host}")
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def watch(
        self,
        *,
        interval_sec: float = 15.0,
        max_iterations: int | None = None,
        probe_targets: bool = False,
    ) -> list[dict[str, Any]]:
        """Autonomous self-healing watchdog loop that monitors health and heals drift."""
        history: list[dict[str, Any]] = []
        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            diag = self.doctor(
                fix=True, probe_targets=probe_targets, actor="watchdog"
            )
            history.append(diag)
            iteration += 1
            if max_iterations is not None and iteration >= max_iterations:
                break
            time.sleep(max(0.1, interval_sec))
        return history

    def query_database(
        self,
        node: str,
        container: str,
        engine: str,
        query: str,
        *,
        database: str = "",
        db_user: str = "root",
        db_password_env: str = "",
        as_root: bool = True,
        confirm_destructive: bool = False,
        actor: str = "cli",
    ) -> ExecResult:
        """Execute a SQL query on a TargetNode (directly or in Docker/Podman/nerdctl) without CLI password exposure."""
        verify_command_safety(query, confirm_destructive=confirm_destructive)
        sql_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
        sec_env = {"EGW_DB_PWD": db_password_env} if db_password_env else None
        ctr_resolver = 'CTR_BIN=$(command -v docker 2>/dev/null || command -v podman 2>/dev/null || command -v nerdctl 2>/dev/null || echo docker); '

        eng = engine.lower()
        if eng in ("mysql", "mariadb"):
            db_part = shlex.quote(database) if database else ""
            if container:
                env_flag = '-e MYSQL_PWD="$EGW_DB_PWD"' if db_password_env else ""
                fallback_pw = "" if db_password_env else '-p"$MYSQL_ROOT_PASSWORD"'
                script = (
                    f"{ctr_resolver}echo '{sql_b64}' | base64 -d | "
                    f'"$CTR_BIN" exec -i {env_flag} {shlex.quote(container)} sh -c '
                    f"'mysql -u{shlex.quote(db_user)} {fallback_pw} {db_part}'"
                )
            else:
                env_prefix = 'MYSQL_PWD="$EGW_DB_PWD" ' if db_password_env else ""
                script = (
                    f"echo '{sql_b64}' | base64 -d | "
                    f"{env_prefix}mysql -u{shlex.quote(db_user)} {db_part}"
                )
        elif eng in ("postgres", "postgresql", "psql"):
            db_part = f"-d {shlex.quote(database)}" if database else ""
            if container:
                env_flag = '-e PGPASSWORD="$EGW_DB_PWD"' if db_password_env else ""
                script = (
                    f"{ctr_resolver}echo '{sql_b64}' | base64 -d | "
                    f'"$CTR_BIN" exec -i {env_flag} {shlex.quote(container)} psql -U {shlex.quote(db_user)} {db_part}'
                )
            else:
                env_prefix = 'PGPASSWORD="$EGW_DB_PWD" ' if db_password_env else ""
                script = (
                    f"echo '{sql_b64}' | base64 -d | "
                    f"{env_prefix}psql -U {shlex.quote(db_user)} {db_part}"
                )
        else:
            raise ValueError(f"Unsupported database engine: {engine}")

        return self.exec_node(
            node,
            script,
            as_root=as_root,
            confirm_destructive=confirm_destructive,
            secret_env=sec_env,
            actor=actor,
        )

    def http_request(
        self,
        node: str,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str = "",
        insecure_tls: bool = False,
        actor: str = "cli",
    ) -> ExecResult:
        """Execute an HTTP request from inside a node with adaptive curl / python3 / wget / Invoke-WebRequest fallback."""
        if self._is_powershell_node(node):
            hdr_entries = ", ".join(
                f"'{k}'='{v}'" for k, v in (headers or {}).items()
            )
            body_arg = ""
            if body:
                b64_b = base64.b64encode(body.encode("utf-8")).decode("ascii")
                body_arg = f"-Body ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64_b}')))"
            ps_http = f"""
$resp = Invoke-WebRequest -Uri '{url}' -Method '{method.upper()}' -Headers @{{{hdr_entries}}} {body_arg} -UseBasicParsing
Write-Output $resp.Content
Write-Output "---HTTP_STATUS:$($resp.StatusCode)---"
""".strip()
            return self.exec_node(node, ps_http, as_root=False, actor=actor)

        hdr_flags: list[str] = []
        for k, v in (headers or {}).items():
            hdr_flags.append(f"-H {shlex.quote(f'{k}: {v}')}")
        k_flag = "-k" if insecure_tls else ""
        body_part = ""
        if body:
            b64_body = base64.b64encode(body.encode("utf-8")).decode("ascii")
            body_part = f"--data-binary \"$(echo '{b64_body}' | base64 -d)\""

        curl_cmd = (
            f"if command -v curl >/dev/null 2>&1; then "
            f"curl -sS {k_flag} -X {shlex.quote(method.upper())} "
            f"{' '.join(hdr_flags)} {body_part} "
            f"-w '\\n---HTTP_STATUS:%{{http_code}}---\\n' {shlex.quote(url)}; "
            f"elif command -v wget >/dev/null 2>&1; then "
            f"wget -qO- {'--no-check-certificate' if insecure_tls else ''} {shlex.quote(url)} && printf '\\n---HTTP_STATUS:200---\\n'; "
            f"else "
            f"python3 -c \"import urllib.request,ssl; ctx=ssl._create_unverified_context() if {bool(insecure_tls)} else None; r=urllib.request.urlopen({url!r},context=ctx); print(r.read().decode('utf-8','replace')); print('---HTTP_STATUS:'+str(r.status)+'---')\"; "
            f"fi"
        )
        return self.exec_node(node, curl_cmd, as_root=False, actor=actor)

    def _resolve_target(self, name: str) -> TargetNodeSpec:
        if name not in self.config.targets:
            available = ", ".join(sorted(self.config.targets.keys())) or "none"
            raise KeyError(
                f"Unknown TargetNode '{name}'. Configured targets: {available}"
            )
        return self.config.targets[name]

    def _resolve_hop_and_jump(
        self, target: TargetNodeSpec
    ) -> tuple[SshHopExecutor, list[TargetNodeSpec] | None]:
        chain: list[TargetNodeSpec] = []
        visited: set[str] = {target.name}
        curr = target
        while True:
            via = curr.via.lstrip("@")
            if via == "appliance":
                return self.appliance_ssh, ( list(reversed(chain)) if chain else None )
            if via in ("bastion", ""):
                return self.bastion_ssh, ( list(reversed(chain)) if chain else None )
            if via in visited:
                raise ValueError(
                    f"Circular TargetNode 'via' routing cycle detected involving '{via}'"
                )
            if via not in self.config.targets:
                return self.bastion_ssh, ( list(reversed(chain)) if chain else None )
            visited.add(via)
            jump_spec = self.config.targets[via]
            chain.append(jump_spec)
            curr = jump_spec
