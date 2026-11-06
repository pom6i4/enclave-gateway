"""High-level Enclave Gateway orchestration engine and multi-hop router."""

from __future__ import annotations

import base64
import os
import collections
import urllib.parse
import fnmatch
import json
import re
import secrets
import shlex
import tarfile
import time
import threading
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Any

DEFAULT_SYNC_EXCLUDES = (
    ".git",
    "__pycache__",
    ".DS_Store",
    ".venv",
    "node_modules",
    "*.pyc",
    ".env",
    ".env.*",
    ".ssh",
    ".aws",
)
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.operations.context import OperationError, budget, checkpoint, current, mark_dispatched, principal, timed, owned_cleanup
from enclave_gateway.operations.journal import TransactionJournal, TERMINAL
from enclave_gateway.operations.runner import tracked
from enclave_gateway.providers import provider_adapter
from enclave_gateway.config import EnclaveConfig, TargetNodeSpec
from enclave_gateway.routing import resolve_target_route
from enclave_gateway.control.qga_client import (
    ControlChannel,
    DirectHostControlChannel,
    ExecResult,
    QgaClient,
)
from enclave_gateway.hypervisor.driver import ApplianceHypervisor
from enclave_gateway.security.secrets import SecretVault, verify_command_safety
from enclave_gateway.security.quoting import ps_quote, ssh_config_quote
from enclave_gateway.security.policy import active_grant, below, remote_path, canonical_node
from enclave_gateway.transports.ssh_hop import _node_uri, _build_b64_decode_expr
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, generate_tx_id
from enclave_gateway.transports.ssh_hop import SshHopExecutor


def safe_extract_tar(archive: tarfile.TarFile, destination: Path, excluded=None) -> int:
    root = destination.resolve()
    members = archive.getmembers()
    if len(members) > 100000 or sum(item.size for item in members) > 16 * 1024**3:
        raise ValueError("Archive exceeds extraction limits")
    for item in members:
        path = PurePosixPath(item.name)
        target = (root / item.name).resolve()
        if (path.is_absolute() or PureWindowsPath(item.name).drive or "\\" in item.name
                or ".." in path.parts or not target.is_relative_to(root)
                or not (item.isfile() or item.isdir())):
            raise ValueError(f"Refusing unsafe tar member: {item.name}")
    root.mkdir(parents=True, exist_ok=True)
    count = 0
    for item in members:
        if excluded is not None and excluded(item.name, PurePosixPath(item.name).name):
            continue
        target = root / item.name
        if item.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(item) as source, target.open("wb") as output:
                import shutil
                shutil.copyfileobj(source, output, 1024 * 1024)
            target.chmod(item.mode & 0o777)
            count += 1
    return count


class EnclaveEngine:
    """Routes commands, file transfers, database queries, and HTTP requests across the enclave."""

    def __init__(
        self,
        config: EnclaveConfig | None = None,
        vault: SecretVault | None = None,
        recorder: FlightRecorder | None = None,
        control_override: ControlChannel | None = None,
        journal: TransactionJournal | None = None,
        state_dir: str | Path | None = None,
    ) -> None:
        self.config = config or EnclaveConfig.load()
        from enclave_gateway.config import state_directory
        self.state_dir=state_directory(self.config,state_dir)
        if self.state_dir is not None and (vault is None or recorder is None):
            from enclave_gateway.operations.retention import private_directory
            private_directory(self.state_dir)
        self.vault = vault or SecretVault(env_file=self.state_dir/'.env' if self.state_dir is not None else None)
        self.recorder = recorder or FlightRecorder(self.state_dir/'audit.jsonl' if self.state_dir is not None else None)
        self.recorder.scrubber = self.vault.scrubber
        from enclave_gateway.operations.retention import RetentionPolicy
        self.journal = journal or TransactionJournal(self.recorder.log_path.with_suffix(".transactions.sqlite3"), RetentionPolicy(**self.config.journal_retention))
        self._operations_lock = threading.RLock()
        self._operations = {}
        self._pending_cancels = set()
        self.hypervisor = ApplianceHypervisor(self.config.appliance)

        if control_override is not None:
            self.control: ControlChannel = control_override
        elif self.config.appliance.hypervisor == "direct":
            self.control = DirectHostControlChannel(runtime_helper_path=self.config.security.runtime_helper_path,
                trusted_signers=self.config.security.trusted_signers,require_signed=self.config.security.require_signed_helpers,
                use_native_runtime=self.config.security.mode!='standard' or self.config.security.require_process_isolation)
        else:
            self.control = QgaClient(
                self.config.appliance.qga_socket,
                self.config.appliance.qga_lock_file,
            )

        self.rdp_vfs = RdpVfsTransport(self.control, self.config.bastion)
        self._worker_ready_at=0.0
        self.rdp_vfs.readiness_guard=self._assert_worker_ready
        if self.config.security.enforce_worker_attestation:
            self.rdp_vfs.attestation_guard=lambda:self.attest_worker(timeout_sec=budget(10))
        self.bastion_ssh = SshHopExecutor(
            exec_hop_fn=self.rdp_vfs.exec_bastion,
            push_hop_fn=self._push_bastion_vfs_stage,
            pull_hop_fn=self._pull_bastion_vfs_stage,
            stage_dir=self.config.bastion.bastion_spool_dir,
            cleanup_hop_fn=self._cleanup_bastion_vfs_stage,
            helper_path=self.config.security.askpass_helper_path,
            trusted_signers=self.config.security.trusted_signers,
            require_signed=self.config.security.require_signed_helpers,
            security_mode=self.config.security.mode,
            owned_commands=self.config.security.owned_ssh_commands,
            runtime_helper_path=self.config.security.runtime_helper_path,
        )
        if self.config.bastion.execution_profile=='structured_only':
            from enclave_gateway.transports.structured import StructuredTransport,StructuredSshExecutor
            self.rdp_vfs=StructuredTransport(self.control,self.config.bastion)
            self.rdp_vfs.readiness_guard=self._assert_worker_ready
            if self.config.security.enforce_worker_attestation:
                self.rdp_vfs.attestation_guard=lambda:self.attest_worker(timeout_sec=budget(10))
            self.bastion_ssh=StructuredSshExecutor(self.rdp_vfs,self.control,self.config.bastion,owned_commands=self.config.security.owned_ssh_commands)
        local_posix=self.config.appliance.hypervisor=='direct' and os.name!='nt' and isinstance(self.control,DirectHostControlChannel)
        self._direct_posix=local_posix
        if local_posix:
            from enclave_gateway.transports.posix_ssh import PosixSshExecutor
        appliance_executor=PosixSshExecutor if local_posix else SshHopExecutor
        self.appliance_ssh = appliance_executor(
            exec_hop_fn=self.control.exec_powershell,
            push_hop_fn=self._push_to_appliance_with_sha,
            pull_hop_fn=self._pull_from_appliance_with_sha,
            helper_path=self.config.security.askpass_helper_path,
            trusted_signers=self.config.security.trusted_signers,
            require_signed=self.config.security.require_signed_helpers,
            security_mode=self.config.security.mode,
            owned_commands=self.config.security.owned_ssh_commands,
            runtime_helper_path=self.config.security.runtime_helper_path,
        )

    def _push_bastion_vfs_stage(
        self, local_path: Path, hop_stage: str, timeout: float
    ) -> str:
        vfs_root = self.config.bastion.bastion_spool_dir.rstrip("\\/")
        if hop_stage.startswith(vfs_root):
            filename = hop_stage.replace("/", "\\").rsplit("\\", 1)[-1]
            app_spool_file = (
                f"{self.config.bastion.appliance_spool_dir.rstrip(chr(92) + '/')}\\{filename}"
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
                f"{self.config.bastion.appliance_spool_dir.rstrip(chr(92) + '/')}\\{filename}"
            )
            return self._pull_from_appliance_with_sha(
                app_spool_file, local_path, timeout
            )
        return self.rdp_vfs.pull_file(hop_stage, local_path, timeout_sec=timeout)

    def _cleanup_bastion_vfs_stage(self,stage):
        root=self.config.bastion.bastion_spool_dir.rstrip('\\/')
        normalized=stage.replace('/','\\')
        if not normalized.startswith(root+'\\'):raise ValueError('Stage is outside the managed spool')
        name=normalized[len(root)+1:]
        if not re.fullmatch(r'egw_(?:stage|pull)_[a-f0-9]{24}',name):raise ValueError('Unowned stage name')
        path=self.config.bastion.appliance_spool_dir.rstrip('\\/')+'\\'+name
        self.control.exec_powershell('[IO.File]::Delete('+ps_quote(path)+')',timeout_sec=budget(10,'appliance.stage_cleanup'))

    def _push_to_appliance_with_sha(
        self, local_path: Path, guest_path: str, _timeout: float
    ) -> str:
        from enclave_gateway.transports.rdp_vfs import compute_file_sha256

        checkpoint("appliance.upload")
        sha = compute_file_sha256(local_path)
        mark_dispatched()
        self.control.write_file(local_path, guest_path)
        return sha

    def _pull_from_appliance_with_sha(
        self, guest_path: str, local_path: Path, _timeout: float
    ) -> str:
        from enclave_gateway.transports.rdp_vfs import compute_file_sha256

        checkpoint("appliance.download")
        self.control.read_file(guest_path, local_path)
        return compute_file_sha256(local_path)

    def _scrub_result(self, res: ExecResult) -> ExecResult:
        return ExecResult(
            exit_code=res.exit_code,
            stdout=self.vault.scrubber.scrub(res.stdout),
            stderr=self.vault.scrubber.scrub(res.stderr),
            duration_ms=res.duration_ms,
            tx_id=res.tx_id, timings_ms=dict(res.timings_ms),
        )

    def _assert_worker_ready(self):
        from enclave_gateway.worker_channel import require_running_worker
        if time.monotonic()-self._worker_ready_at<1:return
        state=require_running_worker(self.control,self.config.bastion)
        self._worker_ready_at=time.monotonic()
        return state

    def _ssh_password(self,target):
        if not target.password_env:return ''
        from enclave_gateway.onboarding import key_only_authentication
        if key_only_authentication(self.config,target):return ''
        return self.vault.get(target.password_env) or ''

    @tracked('stop_worker')
    def stop_worker(self, *, actor='cli', timeout_sec=45, unregister_autostart=False):
        if not self.config.bastion.enabled:raise ValueError('Bastion is disabled')
        result=self._scrub_result(self.rdp_vfs.exec_bastion('',op='stop',timeout_sec=timeout_sec,extra_fields={'unregister_autostart':True} if unregister_autostart else None))
        self._worker_ready_at=0
        expected='WORKER_STOP_ACCEPTED;AUTOSTART_UNREGISTERED' if unregister_autostart else 'WORKER_STOP_ACCEPTED'
        if result.exit_code==0 and result.stdout!=expected:
            raise OperationError('worker_stop_unsupported','worker.stop',message='Worker did not acknowledge the requested stop/autostart removal. Upgrade the worker; check its HKCU Run entry before considering decommission complete.')
        return result

    def status(self) -> dict[str, Any]:
        """Collect health telemetry across Appliance, VPN provider, and Bastion."""
        vm_running, pid = self.hypervisor.is_running()
        report: dict[str, Any] = {
            "profile": self.config.profile,
            "security": {"mode":self.config.security.mode,"attestation_enforced":self.config.security.enforce_worker_attestation,"worker_trust":"not_verified_by_status"},
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
                "worker_required": self.config.bastion.enabled,
                "transport":'rdp_vfs' if self.config.bastion.enabled else 'disabled',
                "host": self.config.bastion.host if self.config.bastion.enabled else None,
                "worker_healthy": False if self.config.bastion.enabled else None,
                "worker_state": None,
            },
            "targets": list(self.config.targets.keys()),
            "automatic_route_fallback":False,
        }

        if not vm_running and self.config.appliance.hypervisor != "direct":
            return report

        if self._direct_posix:
            import socket
            try:
                with socket.create_connection((self.config.provider.probe_host,self.config.provider.probe_port),timeout=3):pass
                report['provider']['tunnel_up']=True
                report['provider']['details']='Reachability only; VPN/provider identity was not verified'
            except OSError:
                report['provider']['details']='Network probe unreachable; configure provider.probe_host and probe_port'
            return report

        provider = self.config.provider
        worker_probe=(f"""
$statePath = Join-Path {ps_quote(self.config.bastion.appliance_spool_dir)} 'worker_state.json'
if (Test-Path -LiteralPath $statePath) {{
    $age = ((Get-Date) - (Get-Item -LiteralPath $statePath).LastWriteTime).TotalSeconds
    if ($age -ge 0 -and $age -lt {self.config.bastion.heartbeat_max_age_sec}) {{ $stateJson = [IO.File]::ReadAllText($statePath).Trim() }}
}}
""" if self.config.bastion.enabled else '')
        adapter = provider_adapter(provider.type)
        probe_ps = adapter.probe_script(provider) + f"""
$adapterName = {ps_quote(provider.adapter_name)}
$adapter = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -eq $adapterName -or $_.InterfaceDescription -like "*$adapterName*" }})
$tcp = Test-NetConnection -ComputerName {ps_quote(provider.probe_host)} -Port {provider.probe_port} -WarningAction SilentlyContinue
$stateJson = ""
{worker_probe}
$vpnRoute = @($adapter | Where-Object {{ $_.Status -eq 'Up' -and $_.Name -eq $tcp.InterfaceAlias }}).Count -gt 0
$out = @{{
    tunnel_up = [bool]($tcp.TcpTestSucceeded -and $vpnRoute)
    probe_reachable = [bool]$tcp.TcpTestSucceeded
    source_ip = if($tcp.SourceAddress -is [Net.IPAddress]){{$tcp.SourceAddress.ToString()}}else{{[string]$tcp.SourceAddress.IPAddress}}
    source_interface = [string]$tcp.InterfaceAlias
    vpn_info = $info
    provider_evidence = $providerEvidence
    worker = $stateJson
}}
ConvertTo-Json $out -Compress -Depth 8
"""
        try:
            res = self.control.exec_powershell(probe_ps, timeout_sec=20.0)
            if res.exit_code == 0 and res.stdout:
                data = json.loads(res.stdout.splitlines()[-1])
                report["provider"]["tunnel_up"] = bool(data.get("probe_reachable",data.get("tunnel_up"))) if provider.type=="custom" else bool(data.get("tunnel_up"))
                report["provider"]["evidence"] = data.get("provider_evidence", {})
                report["provider"]["capabilities"] = adapter.capabilities()
                report["provider"]["source_ip"] = data.get("source_ip", "")
                report["provider"]["probe_reachable"] = data.get("probe_reachable", False)
                report["provider"]["source_interface"] = data.get("source_interface", "")
                report["provider"]["details"] = self.vault.scrubber.scrub(
                    str(data.get("vpn_info", ""))
                )
                worker_raw = data.get("worker")
                if self.config.bastion.enabled and worker_raw:
                    try:
                        report["bastion"]["worker_state"] = json.loads(worker_raw)
                        report["bastion"]["worker_healthy"] = report["bastion"]["worker_state"].get('status','running')=='running'
                    except json.JSONDecodeError:
                        pass
        except Exception as exc:
            report["provider"]["details"] = f"Status probe error: {exc}"

        if self.config.bastion.enabled and self.config.bastion.spool_protocol=='stream':
            from enclave_gateway.worker_channel import stream_worker_state
            try:snapshot=stream_worker_state(self.control,self.config.bastion)
            except Exception:snapshot=None
            report['bastion']['worker_state']=snapshot or {}
            report['bastion']['worker_healthy']=bool(snapshot and snapshot.get('status')=='running')
        return report

    def _refresh_rdp_credentials(self, domain_user, password):
        native=getattr(type(self.control),'exec_guest',None)
        if not callable(native):
            raise OperationError('credential_channel_unavailable','heal.credentials',
                                 message='Credential refresh requires a native stdin control channel. Provision Windows Credential Manager in the approved user session.')
        security=self.config.security
        trusted=','.join(ps_quote(item.replace(' ','').upper()) for item in security.trusted_signers)
        check=(f"$s=Get-AuthenticodeSignature -LiteralPath $helper;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -notin @({trusted})){{throw 'Credential runtime publisher is not trusted'}};"
               if security.require_signed_helpers else '')
        if security.runtime_sha256:
            check+=f"if((Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{security.runtime_sha256.lower()}'){{throw 'Credential runtime hash mismatch'}};"
        probe=("$ErrorActionPreference='Stop';$helper=[Environment]::ExpandEnvironmentVariables("+ps_quote(security.runtime_helper_path)+
               ");if(-not [IO.Path]::IsPathRooted($helper) -or -not [IO.File]::Exists($helper)){throw 'Install the approved credential runtime'};"+check+
               "$task=Get-ScheduledTask -TaskName "+ps_quote(self.config.bastion.scheduled_task_name)+
               ";$sid=if($task.Principal.UserId -match '^S-1-'){$task.Principal.UserId}else{([Security.Principal.NTAccount]::new($task.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value};"+
               "@{runtime=$helper;expected_sid=$sid}|ConvertTo-Json -Compress")
        result=self.control.exec_powershell(probe,timeout_sec=budget(15,'heal.credentials'))
        try:
            info=json.loads(result.stdout)
            if result.exit_code or not isinstance(info,dict) or not isinstance(info.get('runtime'),str) or not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+',info['expected_sid']):
                raise ValueError('Invalid credential runtime identity')
        except (ValueError,KeyError,TypeError) as error:
            raise OperationError('credential_runtime_unavailable','heal.credentials',message='Approve the native credential runtime and the managed RDP task user before refreshing credentials.') from error
        request={'expected_sid':info['expected_sid'],'target':'TERMSRV/'+self.config.bastion.host,
                 'username':domain_user,'password':password}
        try:
            result=native(self.control,info['runtime'],['credentials'],input_data=json.dumps(request).encode(),timeout_sec=budget(15,'heal.credentials'))
            acknowledgement=json.loads(result.stdout)
            if result.exit_code or not isinstance(acknowledgement,dict) or set(acknowledgement)!={'credential_updated'} or acknowledgement['credential_updated'] is not True:
                raise ValueError('Credential update was not acknowledged')
        except Exception as error:
            raise OperationError('credential_update_failed','heal.credentials',indeterminate=True,
                                 message='Native credential update was not acknowledged. Verify the managed user session and stored credential before retrying; no script fallback was used.') from error

    @tracked("heal")
    def heal(self, *, update_credentials: bool = False, actor: str = "cli") -> ExecResult:
        """Self-heal clock drift, MTU, RDP UDP policy, interactive credentials, and Bastion RDP session."""
        if update_credentials and not self.config.bastion.enabled:
            self.rdp_vfs.require_worker()
        if self._direct_posix:
            return ExecResult(0,'No managed Windows settings to repair in POSIX Direct mode. Run egw doctor --probe-targets.','',0)
        tx_id = current().tx_id if current() else generate_tx_id()
        deployment=None
        if self.config.bastion.enabled and self.config.security.mode!='custom':
            deployment=self.stage_agents()
        sync_fn = getattr(self.control, "sync_guest_clock", None)
        if callable(sync_fn):
            sync_fn()

        agents_dir = Path(__file__).resolve().parent / "agents"
        init_script = (agents_dir / "appliance_init.ps1").read_text(encoding="utf-8")
        sup_script = (agents_dir / "session_supervisor.ps1").read_text(encoding="utf-8") if self.config.bastion.enabled else ''

        domain = self.vault.get(self.config.bastion.domain_env) if self.config.bastion.enabled else ''
        user = self.vault.get(self.config.bastion.user_env) if self.config.bastion.enabled else ''
        password = self.vault.get(self.config.bastion.password_env) if self.config.bastion.enabled else ''
        domain_user = f"{domain}\\{user}" if domain and user else user

        if update_credentials and domain_user and password:
            self._refresh_rdp_credentials(domain_user,password)

        host_epoch = int(time.time())
        routes_csv = ",".join(self.config.provider.routes)
        dns_csv = ",".join(self.config.provider.dns_servers)

        combined_ps = f"""
& {{
{init_script}
}} -Mtu {self.config.appliance.mtu} -AdapterName {ps_quote(self.config.provider.adapter_name)} -BastionHost {ps_quote(self.config.bastion.host)} -BastionPort {self.config.bastion.port} -SkipBastion:${str(not self.config.bastion.enabled).lower()} -HostEpochUtc {host_epoch} -RoutesCsv {ps_quote(routes_csv)} -DnsServersCsv {ps_quote(dns_csv)}
"""
        if self.config.bastion.enabled:
            combined_ps+=f"""
& {{
{sup_script}
}} -BastionHost {ps_quote(self.config.bastion.host)} -BastionPort {self.config.bastion.port} -SpoolDir {ps_quote(self.config.bastion.appliance_spool_dir)} -ScheduledTaskName {ps_quote(self.config.bastion.scheduled_task_name)} -HeartbeatMaxAgeSec {self.config.bastion.heartbeat_max_age_sec} -SpoolProtocol {self.config.bastion.spool_protocol.title()} -ForceReconnect
"""
        res = self._scrub_result(self.control.exec_powershell(combined_ps, timeout_sec=60.0))
        if deployment:
            res.stdout+='\nBastion worker staged. In the Bastion RDP session run:\n'+deployment['start_command']+'\n'
        self.recorder.record(
            tx_id=tx_id,
            actor=actor,
            operation="heal",
            node="@appliance",
            summary="Heal appliance clock, MTU, UDP policy, and Bastion session" if self.config.bastion.enabled else "Heal appliance clock and network settings; Bastion disabled",
            exit_code=res.exit_code,
            duration_ms=res.duration_ms,
        )
        return res

    @tracked('stage_agents')
    def stage_agents(self, *, actor='cli', **options):
        from enclave_gateway.onboarding import stage_agents
        return stage_agents(self.control,self.config,**options)

    @tracked('prune_agents')
    def prune_agents(self, *, actor='cli', **options):
        self.rdp_vfs.require_worker()
        from enclave_gateway.agent_maintenance import prune_agent_bundles
        return prune_agent_bundles(self.control,self.config,**options)

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
                prefix_lines.append(f"export {k}=\"$( {_build_b64_decode_expr(val_b64)} )\"")
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

    @tracked("exec_node")
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
        tx_id = current().tx_id if current() else generate_tx_id()
        is_ps = self._is_powershell_node(node)
        full_script = self._inject_env_into_script(
            script, is_powershell=is_ps, env=env, secret_env=secret_env
        )

        if node in ("@appliance", "appliance"):
            mark_dispatched()
            with timed("appliance.exec"):
                raw_res = self.control.exec_powershell(full_script, timeout_sec=budget(timeout_sec))
        elif node in ("@bastion", "bastion"):
            with timed("bastion.exec"):
                raw_res = self.rdp_vfs.exec_bastion(full_script, timeout_sec=budget(timeout_sec))
        else:
            target = self._resolve_target(node)
            ssh_pw = (
                self._ssh_password(target)
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

    @tracked("transfer_file")
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
        tx_id = current().tx_id if current() else generate_tx_id()
        started = time.monotonic()
        lpath = Path(local_path).expanduser().resolve()
        self._verify_scoped_path(node, remote_path, timeout_sec)

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
                    self._ssh_password(target)
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
                    self._ssh_password(target)
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

    @tracked("read_remote_file")
    def read_remote_file(
        self,
        node: str,
        remote_path: str,
        *,
        start_line: int = 1,
        end_line: int = 0,
        as_root: bool = False,
        timeout_sec: float = 120.0,
        actor: str = "cli",
    ) -> dict[str, Any]:
        """Read a UTF-8 file (or line range) from @appliance, @bastion, or a TargetNode with secret scrubbing."""
        with TemporaryDirectory() as tmp_dir:
            tmp_file = Path(tmp_dir) / "remote_read.bin"
            meta = self.transfer_file(
                "pull",
                tmp_file,
                node,
                remote_path,
                as_root=as_root,
                timeout_sec=timeout_sec,
                actor=actor,
            )
            raw_text = tmp_file.read_text(encoding="utf-8", errors="replace")
            lines = raw_text.splitlines(keepends=True)
            total_lines = len(lines)
            s_idx = max(1, int(start_line))
            e_idx = int(end_line) if int(end_line) > 0 else total_lines
            e_idx = min(max(s_idx, e_idx), max(1, total_lines))
            # Redact before slicing, otherwise a line range can reveal the body
            # of a private key whose delimiters fall outside the selected lines.
            scrubbed_lines = self.vault.scrubber.scrub(raw_text).splitlines(keepends=True)
            scrubbed = "".join(scrubbed_lines[s_idx - 1:e_idx])
            return {
                "node": node,
                "remote_path": remote_path,
                "sha256": meta["sha256"],
                "total_lines": total_lines,
                "start_line": s_idx,
                "end_line": e_idx if total_lines > 0 else 0,
                "content": scrubbed,
            }

    @tracked("patch_remote_file")
    def patch_remote_file(
        self,
        node: str,
        remote_path: str,
        target: str,
        replacement: str,
        *,
        as_root: bool = False,
        expected_sha256: str = "",
        timeout_sec: float = 120.0,
        actor: str = "cli",
    ) -> dict[str, Any]:
        """Atomically patch a remote file by replacing target substring with replacement and verifying SHA-256."""
        if not target:
            raise ValueError("patch_remote_file requires a non-empty 'target' string.")
        with TemporaryDirectory() as tmp_dir:
            tmp_file = Path(tmp_dir) / "remote_patch.bin"
            pull_meta = self.transfer_file(
                "pull",
                tmp_file,
                node,
                remote_path,
                as_root=as_root,
                timeout_sec=timeout_sec,
                actor=actor,
            )
            old_sha = pull_meta["sha256"]
            if expected_sha256 and old_sha.lower() != expected_sha256.strip().lower():
                raise ValueError(
                    f"Precondition SHA-256 mismatch for {node}:{remote_path}: "
                    f"expected {expected_sha256}, actual {old_sha}"
                )
            raw_bytes = tmp_file.read_bytes()
            uses_crlf = b"\r\n" in raw_bytes
            raw_text = raw_bytes.decode("utf-8")
            normalized_text = raw_text.replace("\r\n", "\n")
            normalized_target = target.replace("\r\n", "\n")
            normalized_replacement = replacement.replace("\r\n", "\n")

            occurrences = normalized_text.count(normalized_target)
            if occurrences == 0:
                raise ValueError(
                    f"Target block not found in {node}:{remote_path}."
                )
            updated_text = normalized_text.replace(
                normalized_target, normalized_replacement
            )
            if uses_crlf:
                updated_text = updated_text.replace("\n", "\r\n")
            tmp_file.write_bytes(updated_text.encode("utf-8"))

            stage = remote_path + ".egw_patch_" + secrets.token_hex(12)
            try:
                push_meta = self.transfer_file(
                    "push", tmp_file, node, stage, as_root=as_root,
                    use_delta=False, timeout_sec=timeout_sec, actor=actor,
                )
                direct_commit = getattr(self.control, "compare_replace_file", None)
                if node in ("@appliance", "appliance") and callable(direct_commit):
                    direct_commit(stage, remote_path, old_sha)
                else:
                    if self._is_powershell_node(node):
                        commit = f"""
$ErrorActionPreference='Stop'
$dst={ps_quote(remote_path)}
$stage={ps_quote(stage)}
$mutexName='Local\\EnclavePatch_' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($dst)).Replace('/','_')
$mutex = New-Object Threading.Mutex($false, $mutexName)
$locked = $false
try {{
    $locked=$mutex.WaitOne(30000)
    if (-not $locked) {{ throw 'Patch lock timeout' }}
    $actual=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne '{old_sha}') {{ throw 'Patch conflict: destination changed' }}
    [IO.File]::Replace($stage, $dst, $null)
    Write-Output 'EGW_PATCH_COMMIT_OK'
}} finally {{ if ($locked) {{ $mutex.ReleaseMutex() }}; $mutex.Dispose() }}
"""
                    else:
                        from enclave_gateway.transports.ssh_hop import _hash_sh
                        lock = remote_path + ".egw-lock"
                        commit = f"""set -e
mkdir -- {shlex.quote(lock)} || exit 1
trap {shlex.quote('rmdir -- ' + shlex.quote(lock))} EXIT
{_hash_sh(remote_path)}
if [ "$sha" != '{old_sha}' ]; then echo 'Patch conflict: destination changed' >&2; exit 1; fi
mv -f -- {shlex.quote(stage)} {shlex.quote(remote_path)}
echo EGW_PATCH_COMMIT_OK
"""
                    committed = self.exec_node(node, commit, as_root=as_root, timeout_sec=timeout_sec, actor=actor)
                    if committed.exit_code or "EGW_PATCH_COMMIT_OK" not in committed.stdout:
                        raise RuntimeError("Patch conflict or commit failure: " + (committed.stderr or committed.stdout))
            finally:
                cleanup = (f"Remove-Item -LiteralPath {ps_quote(stage)} -Force -ErrorAction SilentlyContinue" if self._is_powershell_node(node)
                           else f"rm -f -- {shlex.quote(stage)}")
                self._cleanup_owned(node, cleanup, as_root=as_root, actor=actor)
            return {
                "node": node,
                "remote_path": remote_path,
                "old_sha256": old_sha,
                "new_sha256": push_meta["sha256"],
                "replacements": occurrences,
                "as_root": as_root,
            }

    @tracked("sync_directory")
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
        if active_grant() and not active_grant().unrestricted_paths:
            return self._scoped_sync(direction,local_dir,node,remote_dir,as_root=as_root,exclude=exclude,timeout_sec=timeout_sec,actor=actor)
        tx_id = current().tx_id if current() else generate_tx_id()
        started = time.monotonic()
        ldir = Path(local_dir).expanduser().resolve()
        patterns = list(DEFAULT_SYNC_EXCLUDES) + list(exclude or [])
        sync_id = secrets.token_hex(6)
        is_windows_node = self._is_powershell_node(node)

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
                        if item.is_symlink():
                            raise ValueError(f"Directory sync does not accept symbolic links: {rel}")
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
$dst = [Environment]::ExpandEnvironmentVariables({ps_quote(remote_dir)})
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
trap {shlex.quote("rm -f -- " + shlex.quote(remote_stage))} EXIT
mkdir -p {shlex.quote(remote_dir)}
tar -xzf '{remote_stage}' -C {shlex.quote(remote_dir)}
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
                    windows_excludes = " ".join(ps_quote("--exclude=" + pattern) for pattern in patterns)
                    pack_ps = f"""
$src = [Environment]::ExpandEnvironmentVariables({ps_quote(remote_dir)})
$stage = [Environment]::ExpandEnvironmentVariables('{remote_stage}')
$parent = Split-Path -Parent $stage
if ($parent -and -not (Test-Path $parent)) {{ New-Item -ItemType Directory -Force -Path $parent | Out-Null }}
tar.exe -czf $stage {windows_excludes} -C $src .
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
                        f"chown -- {shlex.quote(target_user)} '{remote_stage}' && chmod 600 '{remote_stage}'"
                        if as_root
                        else f"chmod 600 '{remote_stage}'"
                    )
                    pack_sh = f"""
set -e
tar -czf '{remote_stage}' {excl_flags} -C {shlex.quote(remote_dir)} .
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
                    self._cleanup_owned(node, cleanup_cmd, as_root=as_root and not is_windows_node, actor=actor)

                ldir.mkdir(parents=True, exist_ok=True)
                with tarfile.open(archive_path, "r:gz") as tf:
                    files_synced = safe_extract_tar(tf, ldir, _is_excluded)
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

    @tracked("bootstrap_ssh_key")
    def bootstrap_ssh_key(self, node: str, *, actor: str = "cli") -> ExecResult:
        """Generate hop host SSH keypair if missing and install public key onto TargetNode."""
        tx_id = current().tx_id if current() else generate_tx_id()
        target = self._resolve_target(node)
        if target.password_env and not self.config.security.askpass_helper_path:
            raise ValueError('ssh-copy-id password bootstrap requires an approved security.askpass_helper_path; normal key-based execution remains available')
        ssh_pw = self._ssh_password(target)
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
        nodes: set[str] | None = None,
    ) -> dict[str, Any]:
        """Run end-to-end L1-L7 diagnostic checklist across Host, Appliance, VPN, Bastion, and Targets."""
        from enclave_gateway.diagnostics import remediation,diagnostic_code
        st=self.status();checks=[];needs_heal=False
        def add(name,ok,detail,applicable=True):
            row={'check':name,'ok':bool(ok),'detail':self.vault.scrubber.scrub(str(detail)),'applicable':applicable}
            if not ok:row.update(remediation=remediation(detail),code=diagnostic_code(detail))
            checks.append(row)
        vm_ok=bool(st['appliance']['running']) or st['appliance']['hypervisor']=='direct'
        add('appliance_vm',vm_ok,'Hypervisor='+st['appliance']['hypervisor'])
        clock_skew=None;udp_disabled=False
        if vm_ok and not self._direct_posix:
            try:
                result=self.control.exec_powershell(r"""
$epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$udp=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client' -Name fClientDisableUDP -ErrorAction SilentlyContinue).fClientDisableUDP
Write-Output ("DIAG_CLOCK:"+$epoch+":UDP:"+[int]$udp)
""",timeout_sec=15)
                markers=[line for line in result.stdout.splitlines() if line.startswith('DIAG_CLOCK:')]
                if result.exit_code==0 and markers:
                    parts=markers[0].split(':');clock_skew=abs(int(time.time())-int(parts[1]));udp_disabled=int(parts[3])==1
            except Exception as error:add('appliance_control_channel',False,str(error))
        clock_ok=self._direct_posix or (clock_skew is not None and clock_skew<120)
        add('appliance_clock_sync',clock_ok,'Local Host clock' if self._direct_posix else 'Clock skew='+str(clock_skew)+'s',not self._direct_posix)
        udp_applicable=self.config.bastion.enabled and not self._direct_posix
        add('rdp_udp_blackhole_guard',udp_disabled or not udp_applicable,'RDP UDP disabled='+str(udp_disabled) if udp_applicable else 'No Windows RDP client in this route',udp_applicable)
        needs_heal=not clock_ok or (udp_applicable and not udp_disabled)
        add('vpn_tunnel_probe',st['provider']['tunnel_up'],'Target='+st['provider']['probe_host']+':'+str(st['provider']['probe_port'])+'; '+st['provider'].get('details',''))
        wrk_ok=False
        if self.config.bastion.enabled:
            wrk_ok=bool(st['bastion']['worker_healthy']);detail='No fresh worker heartbeat; spool or worker unavailable'
            if wrk_ok:
                try:
                    if self.config.security.enforce_worker_attestation:
                        self.attest_worker();add('worker_attestation',True,'Fresh signed worker/runtime/SID evidence verified')
                    ping=(self.rdp_vfs.ping(timeout_sec=45) if self.config.bastion.execution_profile=='structured_only'
                          else self.rdp_vfs.exec_bastion("Write-Output 'VFS_PONG'",timeout_sec=45))
                    wrk_ok=ping.exit_code==0 and 'VFS_PONG' in ping.stdout
                    detail='VFS round trip='+str(ping.duration_ms)+'ms' if wrk_ok else ping.stderr
                except Exception as error:wrk_ok=False;detail=str(error)
            add('bastion_rdp_vfs_ipc',wrk_ok,detail);needs_heal=needs_heal or not wrk_ok
        else:add('bastion_rdp_vfs_ipc',True,'Bastion disabled; no RDP worker needed',False)
        if probe_targets and vm_ok:
            for name,target in self.config.targets.items():
                if nodes is not None and name not in nodes:continue
                hop,_=self._resolve_hop_and_jump(target)
                if hop is self.bastion_ssh and not wrk_ok:
                    add('target_ssh:'+name,False,'Bastion worker unavailable; provision verified known_hosts and keys on Bastion first');continue
                try:
                    result=self.exec_node(name,'echo TARGET_SSH_OK',timeout_sec=45,actor=actor)
                    add('target_ssh:'+name,result.exit_code==0 and 'TARGET_SSH_OK' in result.stdout,result.stdout or result.stderr)
                except Exception as error:add('target_ssh:'+name,False,str(error))
        if fix and needs_heal and vm_ok and not self._direct_posix:
            try:
                result=self.heal(actor=actor)
                if result.exit_code==0:
                    refreshed=self.doctor(fix=False,probe_targets=probe_targets,actor=actor,nodes=nodes);refreshed['auto_healed']=True;return refreshed
                add('self_heal',False,result.stderr or result.stdout)
            except Exception as error:add('self_heal',False,str(error))
        return {'healthy':all(c['ok'] for c in checks),'auto_healed':False,'security_mode':self.config.security.mode,'checks':checks}

    @tracked("clean_session")
    def clean_session(self, *, actor: str = "cli") -> dict[str, Any]:
        """Purge transient spool chunks, staging files, and idle multiplexed sockets across tiers."""
        tx_id = current().tx_id if current() else generate_tx_id()
        started = time.monotonic()

        if not self.config.bastion.enabled:
            self.recorder.record(tx_id=tx_id,actor=actor,operation='clean',node='@appliance',
                                 summary='SSH route selected; no RDP spool cleanup is applicable',exit_code=0,duration_ms=0)
            return {'tx_id':tx_id,'ok':True,'appliance_cleaned':False,'bastion_cleaned':False,
                    'bastion_cleanup':'disabled','applicable':False,'duration_ms':0,'details':{},'errors':[]}

        from enclave_gateway.spool_cleanup import cleanup_script
        errors=[];app_ok=False;bastion_ok=not self.config.bastion.enabled;details={}
        # The controller can clean expired unclaimed requests even when the
        # Bastion queue or the redirected drive is unavailable.
        try:
            app=self.control.exec_powershell(cleanup_script(self.config.bastion.appliance_spool_dir,execution_profile=self.config.bastion.execution_profile),timeout_sec=budget(15,'clean.appliance'))
            app_ok=app.exit_code==0
            if app.stdout.startswith('APPLIANCE_CLEAN_OK:'):
                details=json.loads(app.stdout.split(':',1)[1])
            if not app_ok:errors.append('appliance_cleanup_failed')
        except Exception:
            app_ok=False
            errors.append('appliance_cleanup_unavailable')
        stopped=app_ok and isinstance(details,dict) and details.get('stopped_worker_verified') is True
        bastion_cleanup='disabled' if not self.config.bastion.enabled else 'skipped_worker_stopped' if stopped else 'failed'
        if self.config.bastion.enabled and not stopped:
            try:
                if self.config.bastion.execution_profile=='structured_only':
                    result=self.rdp_vfs.clean(timeout_sec=45)
                else:
                    self.rdp_vfs.close_mux_sessions(timeout_sec=45)
                    result=self.rdp_vfs.exec_bastion("""
$stage=Join-Path $env:LOCALAPPDATA 'EnclaveGateway\\stage'
if([IO.Directory]::Exists($stage)){
 foreach($file in [IO.Directory]::EnumerateFiles($stage)){
  $name=[IO.Path]::GetFileName($file)
  if($name -match '^egw_(stage|pull)_[a-f0-9]{24}$' -and ([DateTime]::UtcNow-[IO.File]::GetLastWriteTimeUtc($file)).TotalHours -gt 24){[IO.File]::Delete($file)}
 }
}
Write-Output 'BASTION_CLEAN_OK'
""",timeout_sec=45)
                bastion_ok=result.exit_code==0
                if bastion_ok:bastion_cleanup='completed'
                if not bastion_ok:errors.append('bastion_cleanup_failed')
            except Exception:
                errors.append('bastion_cleanup_unavailable')
        duration_ms=int((time.monotonic()-started)*1000)
        ok=app_ok and (bastion_ok or stopped)
        self.recorder.record(tx_id=tx_id,actor=actor,operation='clean',node='@all',
            summary='Clean expired unclaimed files; Bastion cleanup='+bastion_cleanup+'; preserve durable outcomes and active processing',
            exit_code=0 if ok else 1,duration_ms=duration_ms)
        return {'tx_id':tx_id,'ok':ok,'appliance_cleaned':app_ok,'bastion_cleaned':bastion_ok,'bastion_cleanup':bastion_cleanup,
                'duration_ms':duration_ms,'details':details,'errors':errors}

    def generate_ssh_config(
        self,
        *,
        config_path: str | None = None,
        prefix: str = "enclave-",
        nodes: set[str] | None = None,
    ) -> str:
        """Generate RDP ProxyCommand configuration without changing selected routes."""
        from enclave_gateway.routing import resolve_target_route
        for name, target in self.config.targets.items():
            if (nodes is None or name in nodes) and resolve_target_route(self.config, target).execution_hop != 'bastion':
                raise OperationError('interactive_ssh_unavailable', 'ssh.config', node=name,
                    message='ssh-config currently exports only RDP TCP mux routes. Use egw ssh for Direct SSH; no RDP fallback was attempted.')
        self.rdp_vfs.require_tcp_mux()
        cfg_flag = f" -c {shlex.quote(config_path)}" if config_path else ""
        lines = [
            f"# Enclave Gateway OpenSSH ProxyCommand Configuration (profile: {self.config.profile})"
        ]
        if not re.fullmatch(r"[A-Za-z0-9_-]*", prefix):
            raise ValueError("Invalid SSH alias prefix")
        for name, spec in sorted(self.config.targets.items()):
            if nodes is not None and name not in nodes:
                continue
            if nodes is not None and spec.via in self.config.targets and spec.via not in nodes:
                raise OperationError("access_denied", "ssh.config", message="Jump node is outside the grant")
            host_alias = f"{prefix}{name}" if prefix else name
            lines.extend(
                [
                    f"Host {host_alias}",
                    f"    HostName {ssh_config_quote(spec.host)}",
                    f"    Port {spec.port}",
                    f"    User {ssh_config_quote(spec.user)}",
                ]
            )
            if spec.via in self.config.targets and spec.via != name:
                jump_alias = f"{prefix}{spec.via}" if prefix else spec.via
                lines.append(f"    ProxyJump {jump_alias}")
            else:
                lines.append(f"    ProxyCommand egw{cfg_flag} stdio-proxy %h %p")
            lines.extend(
                [
                    "    StrictHostKeyChecking yes",
                ]
            )
            if spec.ssh_key_path:
                lines.append(f"    IdentityFile {ssh_config_quote(spec.ssh_key_path)}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def build_ssh_command(
        self,
        node: str,
        extra_args: list[str] | None = None,
        *,
        config_path: str | None = None,
    ) -> list[str]:
        """Use the selected route; native Direct SSH needs no RDP TCP mux."""
        target = self._resolve_target(node)
        hop, chain = self._resolve_hop_and_jump(target)
        if hop is self.appliance_ssh:
            if self.config.appliance.hypervisor != 'direct' or not isinstance(self.control, DirectHostControlChannel):
                raise OperationError('interactive_ssh_unavailable', 'ssh.route', node=node,
                    message='Interactive SSH through a QGA Appliance is not implemented. Use egw exec on this approved route; no RDP fallback was attempted.')
            from enclave_gateway.transports.ssh_hop import _ssh_args
            return ['ssh', *_ssh_args(target, jump_node=chain, windows=os.name == 'nt', ignore_user_config=True),
                    *list(extra_args or []), _node_uri(target)]
        self.rdp_vfs.require_tcp_mux()
        import subprocess
        join = subprocess.list2cmdline if os.name == "nt" else shlex.join
        base = ["egw"] + (["-c", config_path] if config_path else [])
        _, chain = self._resolve_hop_and_jump(target)
        hops = list(chain or [])
        # Explicit nested ProxyCommand keeps every jump behind the VFS channel.
        # ProxyJump and ProxyCommand on the same destination are mutually exclusive.
        def channel(host, port, index):
            if index < 0:
                return join(base + ["stdio-proxy", host, str(port)])
            jump = hops[index]
            args = ["ssh", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
                    "-o", "ProxyCommand=" + channel(jump.host, jump.port, index - 1),
                    "-p", str(jump.port)]
            if jump.ssh_key_path:
                args += ["-i", jump.ssh_key_path]
            args += ["-W", f"[{host}]:{port}", _node_uri(jump)]
            return join(args)
        proxy = channel(target.host, target.port, len(hops) - 1) if hops else join(base + ["stdio-proxy", "%h", "%p"])
        cmd = ["ssh", "-o", "ProxyCommand=" + proxy, "-o", "StrictHostKeyChecking=yes", "-p", str(target.port)]
        if target.ssh_key_path:
            cmd += ["-i", target.ssh_key_path]
        cmd += list(extra_args or [])
        cmd.append(_node_uri(target))
        return cmd

    def watch(
        self,
        *,
        interval_sec: float = 15.0,
        max_iterations: int | None = None,
        probe_targets: bool = False,
    ) -> list[dict[str, Any]]:
        """Autonomous self-healing watchdog loop that monitors health and heals drift."""
        history = collections.deque(maxlen=None if max_iterations is not None else 128)
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
        return list(history)

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
        as_root: bool = False,
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
            db_part = shlex.quote("--database=" + database) if database else ""
            if container:
                env_flag = '-e MYSQL_PWD="$EGW_DB_PWD"' if db_password_env else ""
                mysql_args = ["mysql", "--user=" + db_user] + (["--database=" + database] if database else [])
                inner = ("MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" " if not db_password_env else "") + shlex.join(mysql_args)
                script = (f"{ctr_resolver}echo '{sql_b64}' | base64 -d | "
                          f'"$CTR_BIN" exec -i {env_flag} {shlex.quote(container)} sh -c {shlex.quote(inner)}')
            else:
                env_prefix = 'MYSQL_PWD="$EGW_DB_PWD" ' if db_password_env else ""
                script = (
                    f"echo '{sql_b64}' | base64 -d | "
                    f"{env_prefix}mysql {shlex.quote('--user=' + db_user)} {db_part}"
                )
        elif eng in ("postgres", "postgresql", "psql"):
            db_part = shlex.quote("--dbname=" + database) if database else ""
            if container:
                env_flag = '-e PGPASSWORD="$EGW_DB_PWD"' if db_password_env else ""
                script = (
                    f"{ctr_resolver}echo '{sql_b64}' | base64 -d | "
                    f'"$CTR_BIN" exec -i {env_flag} {shlex.quote(container)} psql -X -v ON_ERROR_STOP=1 {shlex.quote("--username=" + db_user)} {db_part}'
                )
            else:
                env_prefix = 'PGPASSWORD="$EGW_DB_PWD" ' if db_password_env else ""
                script = (
                    f"echo '{sql_b64}' | base64 -d | "
                    f"{env_prefix}psql -X -v ON_ERROR_STOP=1 {shlex.quote('--username=' + db_user)} {db_part}"
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
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("HTTP requests require an absolute http/https URL")
        method = method.upper()
        if not re.fullmatch(r"[A-Z]+", method):
            raise ValueError("Invalid HTTP method")
        for key, value in (headers or {}).items():
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or any(c in value for c in "\r\n\0"):
                raise ValueError("Invalid HTTP header")
        if self._is_powershell_node(node):
            if insecure_tls:
                raise ValueError("insecure_tls requires a configured PowerShell 7 HTTP adapter")
            entries = "; ".join(f"{ps_quote(k)}={ps_quote(v)}" for k, v in (headers or {}).items())
            body_arg = ""
            if body:
                encoded = base64.b64encode(body.encode()).decode("ascii")
                body_arg = f"-Body ([Convert]::FromBase64String('{encoded}'))"
            redirect_option = "-MaximumRedirection 0" if active_grant() else ""
            script = f"$ErrorActionPreference='Stop'; $resp=Invoke-WebRequest -Uri {ps_quote(url)} -Method {ps_quote(method)} -Headers @{{{entries}}} {body_arg} {redirect_option} -UseBasicParsing; Write-Output $resp.Content; Write-Output \"---HTTP_STATUS:$($resp.StatusCode)---\""
            return self.exec_node(node, script, actor=actor)
        data = {"url": url, "method": method, "headers": headers or {}, "body": body, "insecure": insecure_tls}
        encoded = base64.b64encode(json.dumps(data).encode()).decode("ascii")
        python = ("import base64,json,urllib.request,urllib.error,ssl; "
                  f"d=json.loads(base64.b64decode('{encoded}')); "
                  "r=urllib.request.Request(d['url'],data=d['body'].encode() if d['body'] else None,headers=d['headers'],method=d['method']); "
                  "ctx=ssl._create_unverified_context() if d['insecure'] else None; "
                  "\nclass NoRedirect(urllib.request.HTTPRedirectHandler):\n def redirect_request(self,*args,**kwargs): return None\n"
                  "opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),NoRedirect)\n"
                  "try: p=opener.open(r,timeout=30)\nexcept urllib.error.HTTPError as e: p=e\n"
                  "print(p.read().decode('utf-8','replace')); print('---HTTP_STATUS:'+str(p.status)+'---')")
        header_args = " ".join("-H " + shlex.quote(f"{k}: {v}") for k, v in (headers or {}).items())
        body64 = base64.b64encode(body.encode()).decode("ascii")
        curl = f"curl -sS --max-time 30 --proto '=http,https' {'-k' if insecure_tls else ''} -X {shlex.quote(method)} {header_args} {'--data-binary @-' if body else ''} -w '\\n---HTTP_STATUS:%{{http_code}}---\\n' -- {shlex.quote(url)}"
        if body:
            curl = _build_b64_decode_expr(body64) + " | " + curl
        wget = (f"wget --timeout=30 --max-redirect=0 -S -O- {'--no-check-certificate' if insecure_tls else ''} -- {shlex.quote(url)}" if method == "GET" and not headers and not body
                else "echo 'No HTTP client supports the requested method/headers/body' >&2; exit 1")
        script = f"if command -v curl >/dev/null 2>&1; then {curl}; elif command -v python3 >/dev/null 2>&1; then python3 -c {shlex.quote(python)}; else {wget}; fi"
        return self.exec_node(node, script, actor=actor)

    @tracked('provider_manage')
    def provider_manage(self,action,*,apply=False,approval_digest='',timeout_sec=900,actor='cli'):
        from enclave_gateway.providers.lifecycle import plan,powershell
        document=plan(self.config.provider,action)
        if not apply: return {**document,'status':'planned'}
        if not secrets.compare_digest(approval_digest,document['approval_digest']):
            raise OperationError('provider_approval_mismatch','provider',message='Apply requires the digest of the reviewed plan')
        outcomes=[]; staged=[]; replacements={}; cleanup_pending=[]
        try:
            for artifact in document['artifacts']:
                base=PureWindowsPath(artifact['remote_path'])
                if not base.is_absolute() or '%' in str(base): raise ValueError('Staged provider artifacts require an absolute Windows path')
                stage=str(base.with_name(base.stem[:64]+'.egw_'+__import__('hashlib').sha256((current().tx_id+artifact['input']).encode()).hexdigest()[:24]+base.suffix))
                staged.append(stage)
                metadata=self.transfer_file('push',artifact['local_path'],'@appliance',stage,use_delta=False,timeout_sec=budget(timeout_sec,'provider.stage'),actor=actor)
                if metadata['sha256']!=artifact['sha256']: raise OperationError('provider_artifact_changed','provider.stage',indeterminate=True)
                if artifact['publisher']:
                    check=f"$s=Get-AuthenticodeSignature -LiteralPath {ps_quote(stage)}; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -ne {ps_quote(artifact['publisher'])}) {{throw 'Installer publisher mismatch'}}"
                    checked=self.exec_node('@appliance',check,timeout_sec=budget(30),actor=actor)
                    if checked.exit_code: raise OperationError('provider_publisher_mismatch','provider.stage')
                replacements[artifact['remote_path']]=stage
            for original in document['steps']:
                step={**original,'arguments':[replacements.get(arg,arg) for arg in original['arguments']],
                      'timeout_sec':budget(min(original.get('timeout_sec',120),timeout_sec),'provider.step')}
                secret=self.vault.get(step.get('stdin_env','')) if step.get('stdin_env') else ''
                if step.get('stdin_env') and not secret: raise OperationError('provider_credential_missing','provider')
                result=self.exec_node('@appliance',powershell(step,self.config.security,secret),timeout_sec=budget(timeout_sec,'provider.step'),actor=actor)
                if result.exit_code: raise OperationError('provider_step_failed','provider',indeterminate=True)
                status=json.loads(result.stdout)
                if status['exit_code'] not in step['success_codes']:
                    raise OperationError('provider_step_failed','provider',indeterminate=True,message='Controller did not report an approved success status')
                outcomes.append(status)
        finally:
            for stage in staged:
                try:
                    with owned_cleanup():
                        cleanup=self.exec_node('@appliance',f"$ErrorActionPreference='Stop'; if (Test-Path -LiteralPath {ps_quote(stage)}) {{Remove-Item -LiteralPath {ps_quote(stage)} -Force}}; Write-Output 'STAGE_REMOVED'",timeout_sec=2,actor=actor)
                        if cleanup.exit_code or 'STAGE_REMOVED' not in cleanup.stdout: cleanup_pending.append(stage)
                except Exception: cleanup_pending.append(stage)
        return {'status':'completed_cleanup_pending' if cleanup_pending else 'completed','cleanup_pending':cleanup_pending,'action':action,'provider':self.config.provider.type,'steps':outcomes,
                'reboot_required':any(item['reboot_required'] for item in outcomes),'reboot_performed':False,
                'approval_digest':document['approval_digest']}

    def attest_worker(self, *, timeout_sec=10):
        from enclave_gateway.security.attestation import verify
        nonce=secrets.token_hex(32)
        evidence=self.rdp_vfs.attest(nonce,timeout_sec=timeout_sec)
        settings=self.config.security
        return verify(evidence,nonce,expected_sha256=settings.worker_sha256,
                      trusted_signers=settings.trusted_signers,require_signed=settings.require_signed_agents,
                      expected_account=settings.worker_account,require_process_isolation=settings.require_process_isolation,expected_runtime_sha256=settings.runtime_sha256,expected_version=settings.worker_version,
                      expected_execution_profile='structured_only' if self.config.bastion.execution_profile=='structured_only' else '',
                      expected_policy_sha256=self.config.bastion.worker_policy_sha256 if self.config.bastion.execution_profile=='structured_only' else '')

    def _scoped_sync(self,direction,local_dir,node,remote_dir,*,as_root,exclude,timeout_sec,actor):
        from enclave_gateway.agents.rooted_fs import request
        from enclave_gateway.security.scoped_sync import synchronize,remote_script
        grant=active_grant()
        node=canonical_node(node)
        remote_roots=(grant.write_roots if direction=='push' else grant.read_roots)
        candidates=remote_roots.get(node,[])+remote_roots.get('*',[])
        allowed=[root for root in candidates if below(remote_dir,[root])]
        local_roots=grant.local_read_roots if direction=='push' else grant.local_write_roots
        local=Path(local_dir).expanduser().resolve()
        local_allowed=[Path(root).expanduser().resolve() for root in local_roots if below(str(local),[root],local=True)]
        if not allowed or not local_allowed: raise OperationError('access_denied','sync',node=node)
        remote_base=max(allowed,key=len); local_base=max(local_allowed,key=lambda p:len(str(p)))
        remote_relative=remote_path(remote_dir).relative_to(remote_path(remote_base)).as_posix()
        if remote_relative=='.': remote_relative=''
        local_relative=local.relative_to(local_base).as_posix()
        if local_relative=='.': local_relative=''
        def endpoint(root,windows,remote):
            def execute(payload):
                payload={**payload,'root':str(root)}
                if payload['action'] not in ('list','read'): mark_dispatched()
                if not remote and os.name!='nt': return request(payload)
                script=remote_script(payload,windows,helper_path=self.config.security.runtime_helper_path,
                                     trusted_signers=self.config.security.trusted_signers,require_signed=self.config.security.require_signed_helpers)
                if remote: result=self.exec_node(node,script,as_root=as_root,timeout_sec=timeout_sec,actor=actor)
                else: result=DirectHostControlChannel(runtime_helper_path=self.config.security.runtime_helper_path,trusted_signers=self.config.security.trusted_signers,require_signed=self.config.security.require_signed_helpers).exec_powershell(script,timeout_sec=budget(timeout_sec))
                if result.exit_code: raise OperationError('rooted_filesystem_failed','sync',node=node)
                data=json.loads(result.stdout)
                if 'error' in data: raise OperationError('rooted_filesystem_failed','sync',node=node)
                return data
            return execute
        host=endpoint(local_base,os.name=='nt',False)
        guest=endpoint(remote_base,self._is_powershell_node(node),True)
        source,destination=(host,guest) if direction=='push' else (guest,host)
        src,dst=(local_relative,remote_relative) if direction=='push' else (remote_relative,local_relative)
        destination({'action':'mkdir','path':dst})
        return {**synchronize(source,destination,src,dst,list(DEFAULT_SYNC_EXCLUDES)+list(exclude or [])),
                'node':node,'direction':direction,'local_dir':str(local),'remote_dir':remote_dir}

    def _cleanup_owned(self, node, script, *, as_root=False, actor="cli"):
        try:
            with owned_cleanup():
                self.exec_node(node, script, as_root=as_root, confirm_destructive=True, timeout_sec=2, actor=actor)
        except Exception:
            # Cleanup of a tx-specific stage is bounded and best effort. It must
            # not mask a conflict, cancellation, or the original remote failure.
            pass

    def _verify_scoped_path(self, node: str, path: str, timeout: float) -> None:
        grant = active_grant()
        if not grant or grant.unrestricted_paths:
            return
        # Path grants cover structured file operations only. Reject reparse points
        # and symlink ancestors instead of treating lexical containment as proof.
        if isinstance(self.control, DirectHostControlChannel) and node in ("@appliance", "appliance"):
            target = self.control._map_path(path)
            if self.control.root_dir is not None:
                raw = path.replace("\\", "/")
                if len(raw) > 1 and raw[1] == ":":
                    raw = raw[2:]
                target = self.control.root_dir / raw.lstrip("/")
            for item in [target] + list(target.parents):
                if item.is_symlink():
                    raise OperationError("access_denied", "path", node=node, message="Symlink paths are not granted")
            return
        if self._is_powershell_node(node):
            script = f"""
$ErrorActionPreference='Stop'
$p=[IO.Path]::GetFullPath({ps_quote(path)})
while ($p) {{
    if (Test-Path -LiteralPath $p) {{
        $item=Get-Item -LiteralPath $p -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {{ throw 'Reparse-point paths are not granted' }}
    }}
    $parent=[IO.Path]::GetDirectoryName($p)
    if ($parent -eq $p) {{ break }}
    $p=$parent
}}
Write-Output 'PATH_GRANT_OK'
"""
        else:
            script = "p=" + shlex.quote(path) + "; while [ \"$p\" != / ]; do [ ! -L \"$p\" ] || exit 1; p=$(dirname -- \"$p\") || exit 1; done; echo PATH_GRANT_OK"
        result = self.exec_node(node, script, timeout_sec=budget(timeout, "path.verify"))
        if result.exit_code or "PATH_GRANT_OK" not in result.stdout:
            raise OperationError("access_denied", "path", node=node, message="Cannot prove remote path containment")

    def capabilities(self):
        import platform
        import shutil
        import sys
        return {"host": {"os": platform.system(), "arch": platform.machine(), "python": sys.version.split()[0]},
                "tools": {name: bool(shutil.which(name)) for name in ("ssh", "pwsh", "powershell.exe", "qemu-img")},
                "provider": provider_adapter(self.config.provider.type).capabilities(),
                "virtualization":ApplianceHypervisor.tpm_capabilities(),
                "bastion_execution": {"enabled":self.config.bastion.enabled,"profile":self.config.bastion.execution_profile if self.config.bastion.enabled else None,"arbitrary_powershell":self.config.bastion.enabled and self.config.bastion.execution_profile!='structured_only',"tcp_mux":self.config.bastion.enabled and self.config.bastion.execution_profile!='structured_only',"edr_qualified":False},
                "interactive_ssh": {"direct_host":self.config.appliance.hypervisor=='direct' and isinstance(self.control,DirectHostControlChannel),
                                    "qga_bridge":False,"rdp_tcp_mux":self.config.bastion.enabled and self.config.bastion.execution_profile!='structured_only'},
                "automatic_route_fallback":False,
                "transactions": {"durable": True, "replay_ambiguous": False, "cancellation": "requested-until-confirmed"},
                "security": {"signed_helper_required": self.config.security.require_signed_helpers,
                             "signed_agents_required": self.config.security.require_signed_agents,
                             "trusted_publishers_configured": bool(self.config.security.trusted_signers)},
                "retention": {"automatic_archiving":True,"payload_bytes":self.journal.retention.max_payload_bytes,"archive_bytes":self.journal.retention.max_archive_bytes,"identity_capacity":self.journal.retention.max_identities},
                "worker_verification": {"applicable":self.config.bastion.enabled,"configured":bool(self.config.security.worker_sha256),"enforced":self.config.bastion.enabled and self.config.security.enforce_worker_attestation,"running_worker":"query-enclave_agent" if self.config.bastion.enabled else "not_applicable"},
                "qualification": {"windows_guest": "not_verified", "rdpdr": "not_verified", "vendor_driver": "not_verified"}}

    def transaction_status(self, tx_id: str | None = None, *, limit: int = 25):
        if tx_id:
            record = self.journal.get(tx_id, principal())
            if record is None:
                raise OperationError("transaction_not_found", "journal", tx_id=tx_id)
            return record
        return self.journal.recent(principal(), limit)

    def request_cancel_pending(self, tx_id: str):
        owner = principal()
        with self._operations_lock:
            context = self._operations.get(tx_id)
            if context is None:
                self._pending_cancels.add((owner, tx_id))
        if context and context.principal == owner:
            context.cancel()

    def cancel_transaction(self, tx_id: str):
        record = self.journal.get(tx_id, principal())
        if record is None:
            raise OperationError("transaction_not_found", "cancel", tx_id=tx_id)
        if record["state"] in TERMINAL:
            return record
        with self._operations_lock:
            context = self._operations.get(tx_id)
        if context and context.principal == principal():
            context.cancel()
            # Cancellation request is not confirmation of remote process exit.
            self.journal.request_cancel(tx_id, principal())
        else:
            self.journal.reconcile_expired(principal())
        return self.transaction_status(tx_id)

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
        route=resolve_target_route(self.config,target)
        return (self.appliance_ssh if route.execution_hop=='appliance' else self.bastion_ssh,
                list(route.jumps) if route.jumps else None)
