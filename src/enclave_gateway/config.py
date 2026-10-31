"""Topology and appliance configuration loader."""

from __future__ import annotations

import json
import os
import tempfile
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _default_runtime_dir() -> str:
    return str(Path(tempfile.gettempdir()) / ("enclave-gateway-" + str(getattr(os, "getuid", lambda: "user")())))


@dataclass(slots=True)
class ApplianceSpec:
    name: str = "enclave-appliance"
    hypervisor: str = "auto"
    arch: str = "auto"
    cpus: int = 4
    memory_mb: int = 4096
    disk_path: str = "~/.local/share/enclave-gateway/disk.qcow2"
    efi_code_path: str = ""
    efi_vars_path: str = "~/.local/share/enclave-gateway/efi_vars.fd"
    golden_snapshot: str = "golden_ready"
    mtu: int = 1350
    socks5_port: int = 1080
    rdp_forward_port: int = 13389
    vm_rdp_forward_port: int = 13390
    vnc_display: int = 1
    runtime_dir: str = field(default_factory=_default_runtime_dir)

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", self.name):
            raise ValueError("Invalid appliance name")
        if self.cpus < 1 or self.memory_mb < 128 or not 576 <= self.mtu <= 9000:
            raise ValueError("Invalid appliance resources or MTU")

    @property
    def resolved_disk_path(self) -> Path:
        return Path(os.path.expanduser(self.disk_path)).resolve()

    @property
    def resolved_efi_vars_path(self) -> Path:
        return Path(os.path.expanduser(self.efi_vars_path)).resolve()

    @property
    def pid_file(self) -> Path:
        return Path(self.runtime_dir) / f"{self.name}-qemu.pid"

    @property
    def qmp_socket(self) -> Path:
        return Path(self.runtime_dir) / f"{self.name}-qmp.sock"

    @property
    def qga_socket(self) -> Path:
        return Path(self.runtime_dir) / f"{self.name}-qga.sock"

    @property
    def qga_lock_file(self) -> Path:
        return Path(self.runtime_dir) / f"{self.name}-qga.lock"


@dataclass(slots=True)
class ProviderSpec:
    type: str = "vipnet"
    binary_path: str = ""
    installer_path: str = "./vendor/ViPNet_Client.msi"
    dst_key_path: str = "./secrets/client.dst"
    dst_password_env: str = "ENCLAVE_VPN_KEY_PASSWORD"
    adapter_name: str = "Infotecs"
    service_name: str = ""
    qualified_versions: list[str] = field(default_factory=list)
    qualified_architectures: list[str] = field(default_factory=list)
    expected_publisher: str = ""
    lifecycle_manifest: str = ''
    lifecycle_manifest_sha256: str = ''
    lifecycle_inputs: dict[str,str] = field(default_factory=dict)
    lifecycle_local_artifacts: dict[str,str] = field(default_factory=dict)
    lifecycle_artifact_publishers: dict[str,str] = field(default_factory=dict)
    probe_host: str = "10.0.1.10"
    probe_port: int = 3389
    routes: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)


    def __post_init__(self):
        for entries in (self.qualified_versions, self.qualified_architectures):
            if not isinstance(entries, list) or any(not isinstance(value, str) for value in entries):
                raise ValueError("Qualified provider versions/architectures must be string lists")
        if not isinstance(self.expected_publisher, str):
            raise ValueError("Provider publisher must be a string")


@dataclass(slots=True)
class BastionSpec:
    enabled: bool = True
    host: str = "10.0.1.10"
    port: int = 3389
    domain_env: str = "ENCLAVE_BASTION_DOMAIN"
    user_env: str = "ENCLAVE_BASTION_USER"
    password_env: str = "ENCLAVE_BASTION_PASSWORD"
    transport: str = "rdp_vfs"
    appliance_spool_dir: str = r"C:\EnclaveGateway\spool"
    bastion_spool_dir: str = r"\\tsclient\C\EnclaveGateway\spool"
    scheduled_task_name: str = "StartEnclaveBastionRDP"
    parallel_streams: int = 4
    compress: bool = True
    block_size_bytes: int = 4 * 1024 * 1024

    def __post_init__(self):
        # A binary block is embedded in a script, then in the 8 MiB envelope.
        # Four MiB also fits the native worker's bounded stdin after encoding.
        if type(self.block_size_bytes) is not int or not 1 <= self.block_size_bytes <= 4 * 1024 * 1024:
            raise ValueError("block_size_bytes must be in 1..4194304")
        if type(self.parallel_streams) is not int or not 1 <= self.parallel_streams <= 64:
            raise ValueError("parallel_streams must be in 1..64")


@dataclass(slots=True)
class TargetNodeSpec:
    name: str
    host: str
    port: int = 22
    user: str = "root"
    via: str = "bastion"
    os: str = "linux"
    password_env: str = ""
    sudo_password_env: str = ""
    ssh_key_path: str = ""

    def __post_init__(self):
        from enclave_gateway.security.quoting import validate_endpoint
        validate_endpoint(self.host, self.port)
        if not re.fullmatch(r"[A-Za-z0-9_.@\\-]+", self.user) or self.user.startswith("-"):
            raise ValueError("Invalid target user")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.name):
            raise ValueError("Invalid target name")


@dataclass(slots=True)
class PortForwardSpec:
    name: str
    local_port: int
    target_host: str
    target_port: int
    bind_host: str = "127.0.0.1"


@dataclass(slots=True)
class SecuritySpec:
    askpass_helper_path: str = r"%LOCALAPPDATA%\EnclaveGateway\bin\egw-askpass.exe"
    trusted_signers: list[str] = field(default_factory=list)
    runtime_helper_path: str = r"%LOCALAPPDATA%\EnclaveGateway\bin\egw-runtime.exe"
    require_signed_helpers: bool = True
    require_signed_agents: bool = True
    worker_sha256: str = ''
    worker_version: str = '0.3.0'
    runtime_sha256: str = ''
    worker_account: str = ''
    enforce_worker_attestation: bool = False
    require_process_isolation: bool = False
    owned_ssh_commands: bool = False


    def __post_init__(self):
        if any(type(getattr(self,name)) is not bool for name in ('require_signed_helpers','require_signed_agents','enforce_worker_attestation','require_process_isolation','owned_ssh_commands')):
            raise ValueError("Security requirements must be boolean")
        if any(value and not re.fullmatch('[a-fA-F0-9]{64}',value) for value in (self.worker_sha256,self.runtime_sha256)):
            raise ValueError('Worker SHA-256 must be a release digest')
        if not isinstance(self.worker_version,str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?',self.worker_version):
            raise ValueError('Worker version must be explicit')
        if self.worker_account and not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+',self.worker_account):
            raise ValueError('Pin a Windows worker SID; display names are not identity')
        if not isinstance(self.worker_account,str) or not isinstance(self.runtime_helper_path,str):
            raise ValueError('Worker identity/runtime path must be strings')
        if not isinstance(self.trusted_signers, list) or any(not isinstance(value, str) or not re.fullmatch(r"[A-Fa-f0-9]{40,64}", value.replace(" ", "")) for value in self.trusted_signers):
            raise ValueError("Trusted signers must be certificate thumbprints")


@dataclass(slots=True)
class EnclaveConfig:
    profile: str = "default"
    appliance: ApplianceSpec = field(default_factory=ApplianceSpec)
    provider: ProviderSpec = field(default_factory=ProviderSpec)
    bastion: BastionSpec = field(default_factory=BastionSpec)
    security: SecuritySpec = field(default_factory=SecuritySpec)
    journal_retention: dict = field(default_factory=dict)
    targets: dict[str, TargetNodeSpec] = field(default_factory=dict)
    forwards: dict[str, PortForwardSpec] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EnclaveConfig:
        app_raw = dict(raw.get("appliance") or {})
        prov_raw = dict(raw.get("provider") or {})
        bast_raw = dict(raw.get("bastion") or {})
        security_raw=dict(raw.get('security') or {})
        if set(security_raw)-set(SecuritySpec.__dataclass_fields__):
            raise ValueError('Unknown security setting')
        targets_raw = dict(raw.get("targets") or {})
        forwards_raw = dict(raw.get("forwards") or {})

        for list_field in ("routes", "dns_servers"):
            if list_field in prov_raw:
                val = prov_raw[list_field]
                if isinstance(val, dict):
                    prov_raw[list_field] = list(val.values())
                elif isinstance(val, str):
                    prov_raw[list_field] = [
                        x.strip() for x in val.split(",") if x.strip()
                    ]

        targets: dict[str, TargetNodeSpec] = {}
        for t_name, t_cfg in targets_raw.items():
            if isinstance(t_cfg, dict):
                targets[t_name] = TargetNodeSpec(
                    name=t_name,
                    host=str(t_cfg.get("host", "10.0.20.11")),
                    port=int(t_cfg.get("port", 22)),
                    user=str(t_cfg.get("user", "root")),
                    via=str(t_cfg.get("via", "bastion")),
                    os=str(t_cfg.get("os", "linux")).lower(),
                    password_env=str(t_cfg.get("password_env", "")),
                    sudo_password_env=str(t_cfg.get("sudo_password_env", "")),
                    ssh_key_path=str(t_cfg.get("ssh_key_path", "")),
                )

        forwards: dict[str, PortForwardSpec] = {}
        for f_name, f_cfg in forwards_raw.items():
            if isinstance(f_cfg, str) and f_cfg.count(":") == 2:
                lport_s, thost_s, tport_s = f_cfg.split(":")
                resolved_host = targets[thost_s].host if thost_s in targets else thost_s
                forwards[f_name] = PortForwardSpec(
                    name=f_name,
                    local_port=int(lport_s),
                    target_host=resolved_host,
                    target_port=int(tport_s),
                )
            elif isinstance(f_cfg, dict):
                raw_thost = str(f_cfg.get("target_host") or f_cfg.get("host", "10.0.20.11"))
                resolved_host = targets[raw_thost].host if raw_thost in targets else raw_thost
                forwards[f_name] = PortForwardSpec(
                    name=f_name,
                    local_port=int(f_cfg.get("local_port", 8080)),
                    target_host=resolved_host,
                    target_port=int(f_cfg.get("target_port") or f_cfg.get("port", 80)),
                    bind_host=str(f_cfg.get("bind_host", "127.0.0.1")),
                )

        return cls(
            profile=str(raw.get("profile", "default")),
            journal_retention=dict(raw.get("journal_retention") or {}),
            security=SecuritySpec(**security_raw),
            appliance=ApplianceSpec(
                **{k: v for k, v in app_raw.items() if k in ApplianceSpec.__dataclass_fields__}
            ),
            provider=ProviderSpec(
                **{k: v for k, v in prov_raw.items() if k in ProviderSpec.__dataclass_fields__}
            ),
            bastion=BastionSpec(
                **{k: v for k, v in bast_raw.items() if k in BastionSpec.__dataclass_fields__}
            ),
            targets=targets,
            forwards=forwards,
        )

    @classmethod
    def load(cls, path: str | Path | None = None) -> EnclaveConfig:
        candidates = (
            [Path(path)]
            if path
            else [
                Path("enclave.yaml"),
                Path("config/enclave.yaml"),
                Path("config/enclave.example.yaml"),
            ]
        )
        if path is not None and not Path(path).is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        for candidate in candidates:
            if candidate.is_file():
                text = candidate.read_text(encoding="utf-8")
                data = parse_yaml_or_json(text)
                return cls.from_dict(data)
        return cls()


def _parse_scalar(val: str) -> Any:
    val = val.strip()
    if not val:
        return ""
    if (val.startswith("'") and val.endswith("'")) or (
        val.startswith('"') and val.endswith('"')
    ):
        return val[1:-1]
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(x) for x in inner.split(",") if x.strip()]
    low = val.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none", "~"):
        return None
    if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
        return int(val)
    try:
        if "." in val and all(p.isdigit() for p in val.lstrip("-").split(".", 1)):
            return float(val)
    except ValueError:
        pass
    return val


def _strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def parse_yaml_or_json(text: str) -> dict[str, Any]:
    """Parse YAML or JSON configuration without requiring external packages."""
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped.startswith("{"):
        return dict(json.loads(stripped))

    try:
        import yaml  # type: ignore[import-untyped]

        loaded = yaml.safe_load(stripped)
        return dict(loaded) if isinstance(loaded, dict) else {}
    except ImportError:
        pass

    tokens = []
    for line in stripped.splitlines():
        clean = _strip_inline_comment(line)
        if not clean.strip():
            continue
        if "\t" in clean[:len(clean) - len(clean.lstrip())]:
            raise ValueError("Tabs are unsupported in YAML indentation")
        tokens.append((len(clean) - len(clean.lstrip(" ")), clean.strip()))

    def parse_block(index, indent):
        is_list = tokens[index][1].startswith("- ")
        result = [] if is_list else {}
        while index < len(tokens):
            level, text = tokens[index]
            if level < indent:
                break
            if level != indent:
                raise ValueError("Invalid YAML indentation")
            if is_list:
                if not text.startswith("- "):
                    raise ValueError("Mixed YAML sequence and mapping")
                result.append(_parse_scalar(text[2:]))
                index += 1
            else:
                key, colon, value = text.partition(":")
                if not colon or not key or key in result:
                    raise ValueError("Invalid or duplicate YAML mapping key")
                index += 1
                if value.strip():
                    result[key] = _parse_scalar(value)
                elif index < len(tokens) and tokens[index][0] > level:
                    result[key], index = parse_block(index, tokens[index][0])
                else:
                    result[key] = {}
        return result, index

    result, end = parse_block(0, tokens[0][0])
    if not isinstance(result, dict) or end != len(tokens):
        raise ValueError("Configuration must be a YAML mapping")
    return result
