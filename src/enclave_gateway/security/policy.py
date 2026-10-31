"""Explicit tool, node, path and network grants bound to authenticated principals."""

from __future__ import annotations

import contextvars
import ipaddress
import json
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit

from enclave_gateway.operations.context import OperationError


@dataclass(frozen=True)
class Grant:
    name: str
    tools: tuple[str, ...]
    nodes: tuple[str, ...] = ()
    tool_nodes: dict[str,list[str]] = field(default_factory=dict)
    read_roots: dict[str, list[str]] = field(default_factory=dict)
    write_roots: dict[str, list[str]] = field(default_factory=dict)
    local_read_roots: tuple[str, ...] = ()
    local_write_roots: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    token_env: str = ""
    allow_root: bool = False
    allow_arbitrary_exec: bool = False
    unrestricted_paths: bool = False
    unrestricted_network: bool = False
    allow_cancel: bool = False
    allow_provider_management: bool = False
    allow_repair: bool = False

    def permits_tool(self, tool: str) -> bool:
        return tool in self.tools or "*" in self.tools

    def permits_tool_node(self,tool,node):
        allowed=self.tool_nodes.get(tool)
        if allowed is None: return self.permits_node(node)
        return self.permits_node(node) and (canonical_node(node) in {canonical_node(item) for item in allowed} or '*' in allowed)

    def permits_node(self, node: str) -> bool:
        node = canonical_node(node)
        return node in self.nodes or "*" in self.nodes


def canonical_node(node: str) -> str:
    return "@" + node.lstrip("@") if node.lstrip("@") in ("appliance", "bastion") else node


def remote_path(value: str):
    if any(char in value for char in ("\0", "%")):
        raise ValueError("Ambiguous remote path")
    windows = bool(PureWindowsPath(value).drive) or "\\" in value
    path = PureWindowsPath(value) if windows else PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Remote path must be absolute without traversal")
    if windows:
        for part in path.parts[1:]:
            if (part.endswith((".", " ")) or ":" in part
                    or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part, re.I)):
                raise ValueError("Ambiguous Windows path")
    return path


def below(value: str, roots, *, local: bool = False) -> bool:
    try:
        path = Path(value).expanduser().resolve() if local else remote_path(value)
        for root in roots:
            parent = Path(root).expanduser().resolve() if local else remote_path(root)
            if type(path) is type(parent) and path.is_relative_to(parent):
                return True
    except (ValueError, OSError):
        pass
    return False


_grant: contextvars.ContextVar[Grant | None] = contextvars.ContextVar("egw_grant", default=None)


def active_grant() -> Grant | None:
    return _grant.get()


@contextmanager
def grant_scope(grant: Grant | None):
    token = _grant.set(grant)
    try:
        yield
    finally:
        _grant.reset(token)


class AccessPolicy:
    def __init__(self, grants: dict[str, Grant]):
        if not grants:
            raise ValueError("Policy requires at least one principal")
        self.grants = grants

    @classmethod
    def load(cls, path: Path):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) != {"principals"} or not isinstance(raw["principals"], dict):
            raise ValueError("Policy must contain a principals mapping")
        grants = {}
        fields = set(Grant.__dataclass_fields__) - {"name"}
        for name, values in raw["principals"].items():
            if not isinstance(name, str) or not name or not isinstance(values, dict) or set(values) - fields:
                raise ValueError("Invalid policy principal")
            if "tools" not in values:
                raise ValueError("Principal requires an explicit tools list")
            for key in ("tools", "nodes", "destinations", "local_read_roots", "local_write_roots"):
                entries = values.get(key, [])
                if not isinstance(entries, list) or any(not isinstance(item, str) for item in entries):
                    raise ValueError("Policy lists must contain strings")
            overrides=values.get('tool_nodes',{})
            if not isinstance(overrides,dict) or any(not isinstance(key,str) or not isinstance(nodes,list) or any(not isinstance(node,str) for node in nodes) for key,nodes in overrides.items()):
                raise ValueError('Invalid per-tool node grants')
            for key in ("read_roots", "write_roots"):
                roots = values.get(key, {})
                if not isinstance(roots, dict) or any(not isinstance(v, list) or any(not isinstance(p, str) for p in v) for v in roots.values()):
                    raise ValueError("Invalid policy path roots")
                for paths in roots.values():
                    for item in paths:
                        remote_path(item)
            for key in ("allow_root", "allow_arbitrary_exec", "unrestricted_paths", "unrestricted_network", "allow_cancel", "allow_provider_management", "allow_repair"):
                if key in values and type(values[key]) is not bool:
                    raise ValueError("Policy flags must be booleans")
            for network in values.get("destinations", []):
                ipaddress.ip_network(network, strict=True)
            if not isinstance(values.get("token_env", ""), str):
                raise ValueError("token_env must be a vault key name")
            grants[name] = Grant(name=name, **values)
        return cls(grants)

    def grant(self, principal: str) -> Grant:
        if principal not in self.grants:
            raise OperationError("access_denied", "policy", message="Unknown authenticated principal")
        return self.grants[principal]

    @staticmethod
    def require(allowed: bool, reason: str):
        if not allowed:
            raise OperationError("access_denied", "policy", message=reason)

    def authorize_destination(self, grant: Grant, host: str, port: int):
        self.require(type(port) is int and 1 <= port <= 65535, "Invalid destination port")
        if grant.unrestricted_network:
            return
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise OperationError("access_denied", "policy", message="Scoped network destinations require an IP literal; DNS is not trusted as CIDR authorization")
        self.require(any(address in ipaddress.ip_network(net) for net in grant.destinations), "Destination is outside granted networks")

    def authorize(self, principal: str, tool: str, args: dict, config) -> Grant:
        grant = self.grant(principal)
        self.require(grant.permits_tool(tool), "Tool is not granted")
        if tool=='enclave_provider':
            self.require(grant.allow_provider_management and grant.permits_node('@appliance'),'Provider management requires an explicit administrative grant')
        if tool=='enclave_agent': self.require(grant.permits_node('@bastion'),'Worker verification requires the Bastion grant')
        if tool in ("enclave_status", "enclave_doctor"):
            self.require(grant.permits_node("@appliance") and grant.permits_node("@bastion"), "Diagnostics access Appliance and Bastion")
        if tool == "enclave_audit":
            self.require("*" in grant.nodes, "The shared audit requires an explicit all-nodes grant")
        node = canonical_node(str(args.get("node", "")))
        if node:
            self.require(grant.permits_tool_node(tool,node), "Node is not granted for this tool")
        self.require(not (args.get("as_root") or args.get("confirm_destructive")) or grant.allow_root, "Elevated or destructive execution is not granted")
        if tool in ("node_exec", "node_db_query"):
            self.require(grant.allow_arbitrary_exec, "Arbitrary command/SQL execution requires an explicit grant")
        if tool == "enclave_transaction" and args.get("action", "get") in ("cancel", "reconcile", "maintain"):
            self.require(grant.allow_cancel, "Transaction cancellation/reconciliation is not granted")
        if tool=='enclave_transaction' and args.get('action')=='maintain':
            self.require('*' in grant.nodes,'Journal maintenance requires an explicit all-nodes grant')
        path = args.get("remote_path") or args.get("remote_dir")
        if path and not grant.unrestricted_paths:
            writing = tool == "node_patch_file" or args.get("direction") == "push"
            roots = grant.write_roots if writing else grant.read_roots
            self.require(below(path, roots.get(node, []) + roots.get("*", [])), "Remote path is outside granted roots")
            if tool == "node_patch_file":
                self.require(below(path, grant.read_roots.get(node, []) + grant.read_roots.get("*", [])), "Patching also requires read access")
        local = args.get("local_path") or args.get("local_dir")
        if local and not grant.unrestricted_paths:
            roots = grant.local_read_roots if args.get("direction") == "push" else grant.local_write_roots
            self.require(below(local, roots, local=True), "Host path is outside granted roots")
        if tool == "enclave_tunnel" and args.get("action") == "start" and args.get("mode", "tcp") == "tcp":
            host = args.get("target_host", "")
            if host in config.targets:
                self.require(grant.permits_node(host), "Target alias is not granted")
                host = config.targets[host].host
            self.authorize_destination(grant, host, args.get("target_port", 0))
        if tool == "node_http_request":
            url = urlsplit(args.get("url", ""))
            self.authorize_destination(grant, url.hostname or "", url.port or (443 if url.scheme == "https" else 80))
        if tool in ("enclave_heal", "enclave_clean") or (tool == "enclave_doctor" and args.get("fix")):
            self.require(grant.allow_repair,'Controller repair requires an explicit grant')
            self.require(grant.permits_node("@appliance") and grant.permits_node("@bastion"), "Repair requires Appliance and Bastion grants")
        return grant


class ScopedMuxTransport:
    """Keep destination grants attached when listener work moves to a new thread."""
    def __init__(self, transport, policy: AccessPolicy, grant: Grant):
        self.transport, self.policy, self.grant = transport, policy, grant

    def mux_open(self, host, port, *args, **kwargs):
        self.policy.authorize_destination(self.grant, host, port)
        return self.transport.mux_open(host, port, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.transport, name)
