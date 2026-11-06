"""Topology and appliance configuration loader."""

from __future__ import annotations

import json
import os
import tempfile
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, get_type_hints, get_origin, get_args


def _default_runtime_dir() -> str:
    # Keep AF_UNIX paths below platform limits without sharing users' state.
    if os.name!='nt':return str(Path('/tmp')/('enclave-gateway-'+str(os.getuid())))
    return str(Path(os.environ.get('LOCALAPPDATA',tempfile.gettempdir()))/'egw-run')


@dataclass(slots=True)
class ApplianceSpec:
    name: str = "enclave-appliance"
    hypervisor: str = "auto"
    arch: str = "auto"
    cpus: int = 4
    memory_mb: int = 4096
    disk_path: str = "~/.local/share/enclave-gateway/disk.qcow2"
    efi_code_path: str = ""
    efi_vars_template_path: str = ""
    secure_boot: bool = False
    efi_vars_path: str = "~/.local/share/enclave-gateway/efi_vars.fd"
    golden_snapshot: str = "golden_ready"
    snapshot_dir: str = ""
    profile_base_bundle: str = ""
    profile_base_manifest_sha256: str = ""
    tpm_state_dir: str = ""
    display_device: str = "ramfb"
    network_restrict: bool = False
    ssh_forward_port: int = 0
    mtu: int = 1350
    socks5_port: int = 1080
    rdp_forward_port: int = 13389
    vm_rdp_forward_port: int = 13390
    vnc_display: int = 1
    runtime_dir: str = field(default_factory=_default_runtime_dir)
    qga_socket_path: str = ""
    qmp_socket_path: str = ""
    pid_file_path: str = ""

    def __post_init__(self):
        self.runtime_dir=str(Path(self.runtime_dir).expanduser().absolute())
        for name in ('qga_socket_path','qmp_socket_path','pid_file_path'):
            value=getattr(self,name)
            if not isinstance(value,str) or any(c in value for c in '\r\n\0'):raise ValueError('Invalid appliance control path: '+name)
            if value:setattr(self,name,str(Path(value).expanduser().absolute()))
        if self.arch not in ('auto','arm64','x86_64') or self.hypervisor not in ('auto','hvf','kvm','whpx','tcg','direct'):
            raise ValueError('Select a supported appliance architecture and hypervisor')
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", self.name):
            raise ValueError("Invalid appliance name")
        if bool(self.profile_base_bundle)!=bool(self.profile_base_manifest_sha256) or (self.profile_base_manifest_sha256 and not re.fullmatch('[a-f0-9]{64}',self.profile_base_manifest_sha256)):
            raise ValueError('Profile backing bundle requires its manifest digest')
        if type(self.ssh_forward_port) is not int or not 0 <= self.ssh_forward_port <= 65535:
            raise ValueError('Invalid optional SSH forward port')
        if self.display_device not in ('ramfb','virtio-gpu-pci') or type(self.network_restrict) is not bool or type(self.secure_boot) is not bool:
            raise ValueError('Invalid display or network isolation setting')
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
        return Path(self.pid_file_path) if self.pid_file_path else Path(self.runtime_dir) / f"{self.name}-qemu.pid"

    @property
    def qmp_socket(self) -> Path:
        return Path(self.qmp_socket_path) if self.qmp_socket_path else Path(self.runtime_dir) / f"{self.name}-qmp.sock"

    @property
    def qga_socket(self) -> Path:
        return Path(self.qga_socket_path) if self.qga_socket_path else Path(self.runtime_dir) / f"{self.name}-qga.sock"

    @property
    def tpm_socket(self) -> Path:
        return Path(self.runtime_dir) / f"{self.name}-tpm.sock"

    @property
    def qga_lock_file(self) -> Path:
        return self.qga_socket.with_suffix('.lock') if self.qga_socket_path else Path(self.runtime_dir) / f"{self.name}-qga.lock"


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
        from enclave_gateway.providers.adapters import provider_adapter
        from enclave_gateway.security.quoting import validate_endpoint
        if not isinstance(self.type,str):
            raise ValueError('Unsupported VPN provider type')
        provider_adapter(self.type)
        validate_endpoint(self.probe_host,self.probe_port)
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
    heartbeat_max_age_sec: int = 45
    spool_protocol: str = "files"
    execution_profile: str = 'legacy'
    worker_policy_path: str = r'C:\ProgramData\EnclaveGateway\worker-policy.json'
    worker_policy_sha256: str = ''

    def __post_init__(self):
        if self.execution_profile not in ('legacy','structured_only'):
            raise ValueError('execution_profile must be legacy or structured_only')
        if self.execution_profile=='structured_only':
            if self.spool_protocol!='files':raise ValueError('structured_only currently requires files; Stream and TCP mux have no fallback')
            if not re.fullmatch('[a-f0-9]{64}',self.worker_policy_sha256):raise ValueError('Pin the independently approved Bastion worker policy SHA-256')
        if self.spool_protocol not in ("files", "stream"):
            raise ValueError("spool_protocol must be files or stream")
        if type(self.heartbeat_max_age_sec) is not int or not 5<=self.heartbeat_max_age_sec<=300:
            raise ValueError('heartbeat_max_age_sec must be in 5..300')
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
    ssh_known_hosts_path: str = ""

    def __post_init__(self):
        from enclave_gateway.security.quoting import validate_endpoint
        validate_endpoint(self.host, self.port)
        if not re.fullmatch(r"[A-Za-z0-9_.@\\-]+", self.user) or self.user.startswith("-"):
            raise ValueError("Invalid target user")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.name):
            raise ValueError("Invalid target name")
        if any(char in self.ssh_known_hosts_path for char in '\r\n\0'):
            raise ValueError('Invalid SSH known_hosts path')


@dataclass(slots=True)
class PortForwardSpec:
    name: str
    local_port: int
    target_host: str
    target_port: int
    bind_host: str = "127.0.0.1"


@dataclass(slots=True)
class SecuritySpec:
    # Custom preserves the defaults of configurations written before named modes.
    mode: str = 'custom'
    agent_package_dir: str = ''
    bootstrap_sha256: str = ''
    askpass_helper_path: str | None = None
    trusted_signers: list[str] = field(default_factory=list)
    runtime_helper_path: str = r"%LOCALAPPDATA%\EnclaveGateway\bin\egw-runtime.exe"
    require_signed_helpers: bool | None = None
    require_signed_agents: bool | None = None
    worker_sha256: str = ''
    worker_version: str = '0.3.0'
    runtime_sha256: str = ''
    worker_account: str = ''
    enforce_worker_attestation: bool | None = None
    require_process_isolation: bool | None = None
    owned_ssh_commands: bool | None = None


    def __post_init__(self):
        if self.askpass_helper_path is None:
            self.askpass_helper_path='' if self.mode=='standard' else r'%LOCALAPPDATA%\EnclaveGateway\bin\egw-askpass.exe'
        if not isinstance(self.askpass_helper_path,str) or any(c in self.askpass_helper_path for c in '\r\n\0'):
            raise ValueError('Askpass helper path must be a string without control characters')
        if self.mode not in ('standard','enterprise','custom'):
            raise ValueError('security.mode must be standard, enterprise or custom')
        for name in ('require_signed_helpers','require_signed_agents','enforce_worker_attestation','require_process_isolation','owned_ssh_commands'):
            if getattr(self,name) is None:
                setattr(self,name,self.mode=='enterprise' or (self.mode=='custom' and name.startswith('require_signed_')))
        if any(type(getattr(self,name)) is not bool for name in ('require_signed_helpers','require_signed_agents','enforce_worker_attestation','require_process_isolation','owned_ssh_commands')):
            raise ValueError("Security requirements must be boolean")
        if any(value and not re.fullmatch('[a-fA-F0-9]{64}',value) for value in (self.worker_sha256,self.runtime_sha256,self.bootstrap_sha256)):
            raise ValueError('Worker SHA-256 must be a release digest')
        if not isinstance(self.worker_version,str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?',self.worker_version):
            raise ValueError('Worker version must be explicit')
        if self.worker_account and not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+',self.worker_account):
            raise ValueError('Pin a Windows worker SID; display names are not identity')
        if not isinstance(self.worker_account,str) or not isinstance(self.runtime_helper_path,str):
            raise ValueError('Worker identity/runtime path must be strings')
        if not isinstance(self.trusted_signers, list) or any(not isinstance(value, str) or not re.fullmatch(r"[A-Fa-f0-9]{40,64}", value.replace(" ", "")) for value in self.trusted_signers):
            raise ValueError("Trusted signers must be certificate thumbprints")
        if self.mode=='enterprise':
            required=('require_signed_helpers','require_signed_agents','enforce_worker_attestation',
                      'require_process_isolation','owned_ssh_commands','worker_sha256','runtime_sha256',
                      'worker_account','trusted_signers')
            missing=[name for name in required if not getattr(self,name)]
            if missing:raise ValueError('Enterprise mode requires security settings: '+', '.join(missing))

    @classmethod
    def from_dict(cls, raw):
        raw=dict(raw)
        if 'askpass_helper_path' in raw and not isinstance(raw['askpass_helper_path'],str):raise ValueError('Askpass helper path must be a string')
        for name in ('require_signed_helpers','require_signed_agents','enforce_worker_attestation','require_process_isolation','owned_ssh_commands'):
            if name in raw and type(raw[name]) is not bool:raise ValueError('Security requirements must be boolean')
        if raw.get('mode')=='standard':
            raw={**{name:False for name in ('require_signed_helpers','require_signed_agents',
                 'enforce_worker_attestation','require_process_isolation','owned_ssh_commands')},**raw}
        return cls(**raw)


def global_config_path() -> Path:
    base=os.environ.get('XDG_CONFIG_HOME','')
    directory=Path(base).expanduser() if base and Path(base).expanduser().is_absolute() else Path.home()/'.config'
    return directory/'enclave-gateway'/'enclave.yaml'


def configuration_path(path=None) -> Path | None:
    selected=path if path is not None else os.environ.get('ENCLAVE_CONFIG') or None
    candidates=[Path(selected).expanduser()] if selected is not None else [Path('enclave.yaml'),Path('config/enclave.yaml'),global_config_path()]
    if selected is not None and not candidates[0].is_file():raise FileNotFoundError(f'Configuration file not found: {selected}')
    return next((candidate.absolute() for candidate in candidates if candidate.is_file()),None)


def state_directory(config=None, explicit=None, *, source_path=None) -> Path | None:
    value=explicit if explicit is not None else os.environ.get('ENCLAVE_STATE_DIR')
    if value is not None and str(value):return Path(value).expanduser().absolute()
    origin=config.source_path if config is not None else source_path
    if origin==global_config_path().absolute():return global_config_path().parent/'state'
    return None


class _ConfigurationOrigin:
    # Runtime provenance is deliberately absent from dataclass serialization.
    __slots__=('_source_path',)


@dataclass(slots=True)
class EnclaveConfig(_ConfigurationOrigin):
    profile: str = "default"
    appliance: ApplianceSpec = field(default_factory=ApplianceSpec)
    provider: ProviderSpec = field(default_factory=ProviderSpec)
    bastion: BastionSpec = field(default_factory=BastionSpec)
    security: SecuritySpec = field(default_factory=SecuritySpec)
    journal_retention: dict = field(default_factory=dict)
    targets: dict[str, TargetNodeSpec] = field(default_factory=dict)
    forwards: dict[str, PortForwardSpec] = field(default_factory=dict)

    def __post_init__(self):
        if self.bastion.execution_profile=='structured_only':
            security=self.security
            if not self.bastion.enabled or security.mode!='standard' or security.require_process_isolation:
                raise ValueError('structured_only requires Bastion and does not provide Enterprise native process isolation')
            if not security.require_signed_agents or not security.worker_sha256 or not security.trusted_signers or not security.enforce_worker_attestation:
                raise ValueError('structured_only requires signed agents, trusted publishers, a worker SHA-256 and fresh worker attestation')
            if any(t.os not in ('linux','posix','unix') or t.via not in ('bastion','@bastion') for t in self.targets.values()):
                raise ValueError('structured_only requires direct Linux TargetNodes via Bastion')

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EnclaveConfig:
        def known(value, names, section):
            if not isinstance(value,dict):raise ValueError(section+' must be a mapping')
            if any(not isinstance(name,str) for name in value):raise ValueError(section+' setting names must be strings')
            if set(value)-set(names):raise ValueError('Unknown settings in '+section+': '+', '.join(sorted(set(value)-set(names))))
        def typed(value, model, section):
            for name,kind in get_type_hints(model).items():
                if name not in value:continue
                item=value[name]
                if kind in (str,int,bool) and type(item) is not kind:
                    raise ValueError(section+'.'+name+' must be '+kind.__name__)
                if get_origin(kind) is list and (not isinstance(item,list) or (get_args(kind)==(str,) and any(not isinstance(v,str) for v in item))):
                    raise ValueError(section+'.'+name+' must be a list of strings')
        known(raw,cls.__dataclass_fields__,'configuration')
        for section in ('appliance','provider','bastion','security','targets','forwards','journal_retention'):
            if section in raw and raw[section] is not None and not isinstance(raw[section],dict):
                raise ValueError(section+' must be a mapping')
        app_raw = dict(raw.get("appliance") or {})
        prov_raw = dict(raw.get("provider") or {})
        bast_raw = dict(raw.get("bastion") or {})
        if ('probe_host' not in prov_raw or prov_raw['probe_host']=='') and bast_raw.get('enabled',True):
            prov_raw['probe_host']=bast_raw.get('host','10.0.1.10')
        if ('probe_port' not in prov_raw or (type(prov_raw['probe_port']) is int and prov_raw['probe_port']==0)) and bast_raw.get('enabled',True):
            prov_raw['probe_port']=bast_raw.get('port',3389)
        if 'probe_host' in prov_raw and not prov_raw['probe_host']:
            raise ValueError('Set provider.probe_host explicitly when Bastion is disabled')
        security_raw=dict(raw.get('security') or {})
        if set(security_raw)-set(SecuritySpec.__dataclass_fields__):
            raise ValueError('Unknown security setting')
        targets_raw = dict(raw.get("targets") or {})
        forwards_raw = dict(raw.get("forwards") or {})
        for section,values,model in (('appliance',app_raw,ApplianceSpec),('provider',prov_raw,ProviderSpec),('bastion',bast_raw,BastionSpec)):
            known(values,model.__dataclass_fields__,section)

        for list_field in ("routes", "dns_servers"):
            if list_field in prov_raw:
                val = prov_raw[list_field]
                if isinstance(val, dict):
                    prov_raw[list_field] = list(val.values())
                elif isinstance(val, str):
                    prov_raw[list_field] = [
                        x.strip() for x in val.split(",") if x.strip()
                    ]
        for section,values,model in (('appliance',app_raw,ApplianceSpec),('provider',prov_raw,ProviderSpec),('bastion',bast_raw,BastionSpec),('security',security_raw,SecuritySpec)):
            typed(values,model,section)

        targets: dict[str, TargetNodeSpec] = {}
        for t_name, t_cfg in targets_raw.items():
            if not isinstance(t_name,str):raise ValueError('Target names must be strings')
            if isinstance(t_cfg, dict):
                t_cfg=dict(t_cfg)
                known(t_cfg,TargetNodeSpec.__dataclass_fields__,'targets.'+t_name)
                if isinstance(t_cfg.get('port'),str) and t_cfg['port'].isdigit():t_cfg['port']=int(t_cfg['port'])
                typed(t_cfg,TargetNodeSpec,'targets.'+t_name)
                if not t_cfg.get('host'):raise ValueError('targets.'+t_name+'.host is required')
                if 'name' in t_cfg and t_cfg['name']!=t_name:raise ValueError('Target name must match its mapping key')
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
                    ssh_known_hosts_path=str(t_cfg.get('ssh_known_hosts_path','')),
                )
            else:raise ValueError('targets.'+t_name+' must be a mapping')

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
            security=SecuritySpec.from_dict(security_raw),
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

    @property
    def source_path(self) -> Path | None:
        return getattr(self,'_source_path',None)

    @classmethod
    def load(cls, path: str | Path | None = None) -> EnclaveConfig:
        candidate=configuration_path(path)
        if candidate is not None:
            text=candidate.read_text(encoding='utf-8-sig')
            try:data=parse_yaml_or_json(text)
            except Exception as error:
                raise ValueError('Cannot parse configuration; use unique mapping keys and valid YAML/JSON. See docs/GUIDE.md.') from error
            result=cls.from_dict(data);result._source_path=candidate;return result
        raise FileNotFoundError('No enclave.yaml found. Run egw config init (local) or egw config init --global, set ENCLAVE_CONFIG, or pass --config /path/to/enclave.yaml.')


def _parse_scalar(val: str) -> Any:
    val = val.strip()
    if not val:
        return ""
    if val.startswith("'"):
        if not val.endswith("'") or len(val)<2:raise ValueError('Unterminated YAML single-quoted string')
        inner=val[1:-1];result=[];index=0
        while index<len(inner):
            if inner[index]=="'":
                if inner[index:index+2]!="''":raise ValueError('Invalid YAML single quote')
                result.append("'");index+=2
            else:result.append(inner[index]);index+=1
        return ''.join(result)
    if val.startswith('"'):
        if not val.endswith('"') or len(val)<2:raise ValueError('Unterminated YAML double-quoted string')
        escapes={'0':'\0','a':'\a','b':'\b','t':'\t','n':'\n','v':'\v','f':'\f','r':'\r','e':'\x1b',' ':' ','"':'"','/':'/','\\':'\\','N':'\x85','_':'\xa0','L':'\u2028','P':'\u2029'}
        result=[];inner=val[1:-1];index=0
        while index<len(inner):
            char=inner[index];index+=1
            if char=='"':raise ValueError('Unescaped YAML double quote')
            if char!='\\':result.append(char);continue
            if index==len(inner):raise ValueError('Incomplete YAML escape')
            char=inner[index];index+=1
            if char in escapes:result.append(escapes[char])
            elif char in 'xuU':
                count={'x':2,'u':4,'U':8}[char];digits=inner[index:index+count]
                if len(digits)!=count or not re.fullmatch('[0-9A-Fa-f]+',digits):raise ValueError('Invalid YAML hexadecimal escape')
                result.append(chr(int(digits,16)));index+=count
            else:raise ValueError('Unknown YAML escape; use literal single quotes for Windows paths')
        return ''.join(result)
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
    quote=None;index=0;start=True
    while index<len(line):
        char=line[index]
        if quote=='"' and char=='\\':index+=2;continue
        if quote=="'" and line[index:index+2]=="''":index+=2;continue
        if quote:
            if char==quote:quote=None
        elif char in ("'",'"') and start:quote=char;start=False
        elif char=='#' and (index==0 or line[index-1].isspace()):return line[:index].rstrip()
        elif char in '[,' or (char==':' and (index+1==len(line) or line[index+1].isspace())):start=True
        elif char=='-' and start and index+1<len(line) and line[index+1].isspace():start=True
        elif not char.isspace():start=False
        index+=1
    return line.rstrip()


def parse_yaml_or_json(text: str) -> dict[str, Any]:
    """Parse YAML or JSON configuration without requiring external packages."""
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped.startswith("{"):
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('Duplicate JSON mapping key')
                result[key]=value
            return result
        return dict(json.loads(stripped,object_pairs_hook=unique))

    try:
        import yaml  # type: ignore[import-untyped]

        class UniqueLoader(yaml.SafeLoader):pass
        def mapping(loader,node,deep=False):
            loader.flatten_mapping(node);result={}
            for key_node,value_node in node.value:
                key=loader.construct_object(key_node,deep=deep)
                if key in result:raise ValueError('Duplicate YAML mapping key')
                result[key]=loader.construct_object(value_node,deep=deep)
            return result
        UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
        loaded = yaml.load(stripped,Loader=UniqueLoader)
        if not isinstance(loaded,dict):raise ValueError('Configuration must be a mapping')
        return dict(loaded)
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

    if not tokens:return {}
    result, end = parse_block(0, tokens[0][0])
    if not isinstance(result, dict) or end != len(tokens):
        raise ValueError("Configuration must be a YAML mapping")
    return result
