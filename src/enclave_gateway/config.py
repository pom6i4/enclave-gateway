"""Topology and appliance configuration loader."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _default_runtime_dir() -> str:
    return "/tmp" if os.name != "nt" and Path("/tmp").is_dir() else tempfile.gettempdir()


@dataclass(slots=True)
class ApplianceSpec:
    name: str = "enclave-appliance"
    hypervisor: str = "auto"
    arch: str = "auto"
    cpus: int = 4
    memory_mb: int = 4096
    disk_path: str = "~/.local/share/enclave-gateway/disk.qcow2"
    efi_code_path: str = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
    efi_vars_path: str = "~/.local/share/enclave-gateway/efi_vars.fd"
    golden_snapshot: str = "golden_ready"
    mtu: int = 1350
    socks5_port: int = 1080
    rdp_forward_port: int = 13389
    vm_rdp_forward_port: int = 13390
    vnc_display: int = 1
    runtime_dir: str = field(default_factory=_default_runtime_dir)

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
    binary_path: str = r"C:\Program Files\Mobile\bin\vipnetclient.exe"
    installer_path: str = "./vendor/ViPNet_Client.msi"
    dst_key_path: str = "./secrets/client.dst"
    dst_password_env: str = "ENCLAVE_VPN_KEY_PASSWORD"
    adapter_name: str = "Infotecs"
    probe_host: str = "10.0.1.10"
    probe_port: int = 3389
    routes: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)


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


@dataclass(slots=True)
class PortForwardSpec:
    name: str
    local_port: int
    target_host: str
    target_port: int
    bind_host: str = "127.0.0.1"


@dataclass(slots=True)
class EnclaveConfig:
    profile: str = "default"
    appliance: ApplianceSpec = field(default_factory=ApplianceSpec)
    provider: ProviderSpec = field(default_factory=ProviderSpec)
    bastion: BastionSpec = field(default_factory=BastionSpec)
    targets: dict[str, TargetNodeSpec] = field(default_factory=dict)
    forwards: dict[str, PortForwardSpec] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EnclaveConfig:
        app_raw = dict(raw.get("appliance") or {})
        prov_raw = dict(raw.get("provider") or {})
        bast_raw = dict(raw.get("bastion") or {})
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

    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any], str]] = [(-1, root, "")]

    for raw_line in stripped.splitlines():
        clean = _strip_inline_comment(raw_line)
        if not clean.strip():
            continue
        indent = len(clean) - len(clean.lstrip(" "))
        trimmed = clean.strip()

        if trimmed.startswith("- "):
            item_val = _parse_scalar(trimmed[2:].strip())
            while len(stack) > 1 and stack[-1][0] >= indent:
                stack.pop()
            parent_dict = stack[-1][1]
            last_key = stack[-1][2]
            if last_key and isinstance(parent_dict.get(last_key), dict) and not parent_dict[last_key]:
                parent_dict[last_key] = [item_val]
            elif last_key and isinstance(parent_dict.get(last_key), list):
                parent_dict[last_key].append(item_val)
            continue

        key_part, sep, val_part = trimmed.partition(":")
        if not sep:
            continue
        key = key_part.strip()
        val_str = val_part.strip()

        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()

        current_dict = stack[-1][1]
        stack[-1] = (stack[-1][0], current_dict, key)
        if not val_str:
            child: dict[str, Any] = {}
            current_dict[key] = child
            stack.append((indent, child, ""))
        else:
            current_dict[key] = _parse_scalar(val_str)

    return root
