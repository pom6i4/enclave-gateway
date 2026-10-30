"""High-level Enclave Gateway orchestration engine and multi-hop router."""

from __future__ import annotations

import base64
import json
import shlex
import time
from pathlib import Path
from typing import Any

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
            push_hop_fn=lambda src, dst, timeout: self.rdp_vfs.push_file(
                src, dst, use_delta=True, timeout_sec=timeout
            ),
            pull_hop_fn=self.rdp_vfs.pull_file,
        )
        self.appliance_ssh = SshHopExecutor(
            exec_hop_fn=self.control.exec_powershell,
            push_hop_fn=self._push_to_appliance_with_sha,
            pull_hop_fn=self._pull_from_appliance_with_sha,
        )

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
if ('{self.config.provider.type}' -eq 'vipnet' -and (Test-Path '{self.config.provider.binary_path}')) {{
    $info = (& '{self.config.provider.binary_path}' info | Out-String).Trim()
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
        """Self-heal MTU, RDP UDP policy, interactive credentials, and Bastion RDP session."""
        tx_id = generate_tx_id()
        agents_dir = Path(__file__).resolve().parent / "agents"
        init_script = (agents_dir / "appliance_init.ps1").read_text(encoding="utf-8")
        sup_script = (agents_dir / "session_supervisor.ps1").read_text(encoding="utf-8")

        domain = self.vault.get(self.config.bastion.domain_env)
        user = self.vault.get(self.config.bastion.user_env)
        password = self.vault.get(self.config.bastion.password_env)
        domain_user = f"{domain}\\{user}" if domain and user else user

        cred_args = ""
        if update_credentials and domain_user and password:
            cred_args = f"-RdpDomainUser '{domain_user}' -RdpPassword '{password}'"

        combined_ps = f"""
& {{
{init_script}
}} -Mtu {self.config.appliance.mtu} -AdapterName '{self.config.provider.adapter_name}' -BastionHost '{self.config.bastion.host}' -BastionPort {self.config.bastion.port}

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
            summary="Heal appliance MTU, UDP policy, and Bastion session",
            exit_code=res.exit_code,
            duration_ms=res.duration_ms,
        )
        return res

    def exec_node(
        self,
        node: str,
        script: str,
        *,
        as_root: bool = False,
        confirm_destructive: bool = False,
        timeout_sec: float = 120.0,
        actor: str = "cli",
    ) -> ExecResult:
        """Execute a script on @appliance, @bastion, or a named TargetNode."""
        verify_command_safety(script, confirm_destructive=confirm_destructive)
        tx_id = generate_tx_id()

        if node in ("@appliance", "appliance"):
            raw_res = self.control.exec_powershell(script, timeout_sec=timeout_sec)
        elif node in ("@bastion", "bastion"):
            raw_res = self.rdp_vfs.exec_bastion(script, timeout_sec=timeout_sec)
        else:
            target = self._resolve_target(node)
            sudo_pw = (
                self.vault.get(target.sudo_password_env)
                if as_root and target.sudo_password_env
                else ""
            )
            hop = (
                self.bastion_ssh if target.via == "bastion" else self.appliance_ssh
            )
            raw_res = hop.exec_node(
                target,
                script,
                as_root=as_root,
                sudo_password=sudo_pw,
                timeout_sec=timeout_sec,
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
                hop = (
                    self.bastion_ssh if target.via == "bastion" else self.appliance_ssh
                )
                sha = hop.push_file_to_node(
                    target, lpath, remote_path, timeout_sec=timeout_sec
                )
        elif direction == "pull":
            if node in ("@appliance", "appliance"):
                sha = self._pull_from_appliance_with_sha(remote_path, lpath, timeout_sec)
            elif node in ("@bastion", "bastion"):
                sha = self.rdp_vfs.pull_file(remote_path, lpath, timeout_sec=timeout_sec)
            else:
                target = self._resolve_target(node)
                hop = (
                    self.bastion_ssh if target.via == "bastion" else self.appliance_ssh
                )
                sha = hop.pull_file_from_node(
                    target, remote_path, lpath, timeout_sec=timeout_sec
                )
        else:
            raise ValueError(f"Unsupported transfer direction '{direction}' (use 'push' or 'pull')")

        duration_ms = int((time.monotonic() - started) * 1000)
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation=f"transfer_{direction}",
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
            "local_path": str(lpath),
            "remote_path": remote_path,
            "sha256": sha,
            "duration_ms": duration_ms,
        }

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
        """Execute a SQL query inside a container on a TargetNode without quote-escaping hazards."""
        verify_command_safety(query, confirm_destructive=confirm_destructive)
        sql_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
        db_pw = self.vault.get(db_password_env) if db_password_env else ""

        if engine.lower() in ("mysql", "mariadb"):
            pw_part = f"-p{shlex.quote(db_pw)}" if db_pw else '-p"$MYSQL_ROOT_PASSWORD"'
            db_part = shlex.quote(database) if database else ""
            script = (
                f"echo '{sql_b64}' | base64 -d | "
                f"docker exec -i {shlex.quote(container)} sh -c "
                f"'mysql -u{shlex.quote(db_user)} {pw_part} {db_part}'"
            )
        elif engine.lower() in ("postgres", "postgresql", "psql"):
            db_part = f"-d {shlex.quote(database)}" if database else ""
            script = (
                f"echo '{sql_b64}' | base64 -d | "
                f"docker exec -i {shlex.quote(container)} psql -U {shlex.quote(db_user)} {db_part}"
            )
        else:
            raise ValueError(f"Unsupported database engine: {engine}")

        return self.exec_node(
            node,
            script,
            as_root=as_root,
            confirm_destructive=confirm_destructive,
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
        """Execute an HTTP request from inside a TargetNode and return status + body."""
        hdr_flags: list[str] = []
        for k, v in (headers or {}).items():
            hdr_flags.append(f"-H {shlex.quote(f'{k}: {v}')}")
        k_flag = "-k" if insecure_tls else ""
        body_part = ""
        if body:
            b64_body = base64.b64encode(body.encode("utf-8")).decode("ascii")
            body_part = f"--data-binary \"$(echo '{b64_body}' | base64 -d)\""

        curl_cmd = (
            f"curl -sS {k_flag} -X {shlex.quote(method.upper())} "
            f"{' '.join(hdr_flags)} {body_part} "
            f"-w '\\n---HTTP_STATUS:%{{http_code}}---\\n' {shlex.quote(url)}"
        )
        return self.exec_node(node, curl_cmd, as_root=False, actor=actor)

    def _resolve_target(self, name: str) -> TargetNodeSpec:
        if name not in self.config.targets:
            available = ", ".join(sorted(self.config.targets.keys())) or "none"
            raise KeyError(
                f"Unknown TargetNode '{name}'. Configured targets: {available}"
            )
        return self.config.targets[name]
