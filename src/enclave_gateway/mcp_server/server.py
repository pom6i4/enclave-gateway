"""Model Context Protocol (MCP) JSON-RPC 2.0 Server over stdio and Streamable HTTP / OpenAPI."""

from __future__ import annotations

import json
import re
import sys
import threading
import time
import hmac
import math
import urllib.parse
import secrets
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TextIO

from enclave_gateway import __version__
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.operations.context import OperationError, identity, principal as operation_principal
from enclave_gateway.security.policy import AccessPolicy, ScopedMuxTransport, grant_scope, canonical_node
from enclave_gateway.transports.rdp_vfs import RdpVfsTunnelServer
from enclave_gateway.transports.socks5_mux import Socks5VfsServer

MCP_PROTOCOL_VERSION = "2025-03-26"
MCP_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26")
MAX_RPC_BYTES = 8 * 1024 * 1024


def strict_json_loads(raw):
    def invalid_constant(_value):
        raise ValueError("Invalid JSON constant")
    return json.loads(raw, parse_constant=invalid_constant)


class BoundedHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(64)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self._slots.release()

DEFAULT_MAX_OUTPUT_CHARS = 32000

def validate_tool_arguments(name: str, args: Any) -> str | None:
    definition = next((item for item in TOOL_DEFINITIONS if item["name"] == name), None)
    if definition is None:
        return "Unknown tool"
    schema = definition["inputSchema"]
    if not isinstance(args, dict):
        return "Tool arguments must be an object"
    if set(schema.get("required", ())) - args.keys():
        return "Missing required tool arguments"
    if set(args) - schema["properties"].keys():
        return "Unknown tool arguments"
    types = {"string": str, "object": dict, "array": list, "boolean": bool, "integer": int, "number": (int, float)}
    for key, value in args.items():
        prop = schema["properties"][key]
        kind = prop["type"]
        if not isinstance(value, types[kind]) or (kind in ("integer", "number") and isinstance(value, bool)):
            return f"Invalid type for {key}"
        if kind == "number" and not math.isfinite(value):
            return f"Invalid number for {key}"
        if "enum" in prop and value not in prop["enum"]:
            return f"Invalid value for {key}"
        if kind == "array" and any(not isinstance(item, str) for item in value):
            return f"Invalid array items for {key}"
        if key in ("env", "secret_env", "headers") and any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
            return f"Invalid mapping for {key}"
        if key.endswith("port") and not 0 <= value <= 65535:
            return f"Invalid port for {key}"
        if key == "timeout_sec" and not 0 < value <= 86400:
            return "timeout_sec must be in (0, 86400]"
    return None


def truncate_for_context(text: str, max_chars: int = DEFAULT_MAX_OUTPUT_CHARS) -> str:
    """Preserve head (60%) and tail (40%) when tool output exceeds max_chars to protect LLM context window."""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    head_len = max(1, int(max_chars * 0.6))
    tail_len = max(1, max_chars - head_len)
    omitted = len(text) - head_len - tail_len
    if omitted <= 0:
        return text
    middle = text[head_len : len(text) - tail_len]
    omitted_lines = middle.count("\n")
    return (
        f"{text[:head_len]}\n"
        f"... [TRUNCATED {omitted} chars ({omitted_lines} lines) to protect LLM context window] ...\n"
        f"{text[len(text) - tail_len :]}"
    )

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "enclave_status",
        "description": "Retrieve health telemetry for the Appliance VM, VPN tunnel, Bastion RDP VFS worker, and configured TargetNodes.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "enclave_doctor",
        "description": "Run L1-L7 diagnostics across Host, Appliance clock skew, RDP UDP blackhole guard, VPN tunnel, Bastion VFS RTT, and optional TargetNode SSH.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "fix": {
                    "type": "boolean",
                    "description": "Automatically self-heal if clock skew, UDP policy, or Bastion session issues are detected.",
                    "default": False,
                },
                "probe_targets": {
                    "type": "boolean",
                    "description": "Also probe SSH reachability to configured TargetNodes.",
                    "default": False,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "enclave_heal",
        "description": "Heal Appliance MTU (1350), disable RDP-over-UDP, optionally refresh interactive session credentials, and reconnect the Bastion RDP session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "update_credentials": {
                    "type": "boolean",
                    "description": "Inject updated Bastion credentials into the interactive desktop session before reconnecting.",
                    "default": False,
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "enclave_clean",
        "description": "Purge transient spool chunks, staging files, and open multiplexed sockets across Appliance and Bastion.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "node_exec",
        "description": "Execute a shell/PowerShell script on '@appliance', '@bastion', or a configured TargetNode with Base64 transport and secret scrubbing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {
                    "type": "string",
                    "description": "Target node identifier ('@appliance', '@bastion', or a target name from enclave.yaml).",
                },
                "script": {
                    "type": "string",
                    "description": "Script content to execute on the specified node.",
                },
                "as_root": {
                    "type": "boolean",
                    "description": "Execute with elevated sudo privileges on a Linux TargetNode.",
                    "default": False,
                },
                "confirm_destructive": {
                    "type": "boolean",
                    "description": "Explicitly authorize destructive commands (DROP, TRUNCATE, rm -rf, reboot).",
                    "default": False,
                },
                "env": {
                    "type": "object",
                    "description": "Optional non-secret environment variables injected in-memory before running the script.",
                    "default": {},
                },
                "secret_env": {
                    "type": "object",
                    "description": "Optional mapping of target env var name -> SecretVault key name injected from OS Keychain/.env and auto-scrubbed from output.",
                    "default": {},
                },
                "timeout_sec": {
                    "type": "number",
                    "description": "Execution timeout in seconds.",
                    "default": 120.0,
                },
            },
            "required": ["node", "script"],
            "additionalProperties": False,
        },
    },
    {
        "name": "node_transfer",
        "description": "Push or pull a file between the Host and '@appliance', '@bastion', or a TargetNode with SHA-256 verification and optional block delta sync.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "direction": {
                    "type": "string",
                    "enum": ["push", "pull"],
                    "description": "Transfer direction ('push' from Host to Node, 'pull' from Node to Host).",
                },
                "local_path": {
                    "type": "string",
                    "description": "Path to the file on the Host filesystem.",
                },
                "node": {
                    "type": "string",
                    "description": "Target node identifier ('@appliance', '@bastion', or TargetNode name).",
                },
                "remote_path": {
                    "type": "string",
                    "description": "Destination or source path on the remote node.",
                },
                "as_root": {
                    "type": "boolean",
                    "description": "Stage via sudo on Linux TargetNode for root-owned paths.",
                    "default": False,
                },
                "use_delta": {
                    "type": "boolean",
                    "description": "Use 4 MB block-level SHA-256 delta synchronization on push.",
                    "default": True,
                },
            },
            "required": ["direction", "local_path", "node", "remote_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "node_sync",
        "description": "Batch-synchronize an entire directory between the Host and '@appliance', '@bastion', or a TargetNode via streaming tar.gz.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "direction": {
                    "type": "string",
                    "enum": ["push", "pull"],
                    "description": "Sync direction ('push' from Host to Node, 'pull' from Node to Host).",
                },
                "local_dir": {
                    "type": "string",
                    "description": "Path to the directory on the Host filesystem.",
                },
                "node": {
                    "type": "string",
                    "description": "Target node identifier ('@appliance', '@bastion', or TargetNode name).",
                },
                "remote_dir": {
                    "type": "string",
                    "description": "Destination or source directory path on the remote node.",
                },
                "as_root": {
                    "type": "boolean",
                    "description": "Extract or pack with sudo privileges on a Linux TargetNode.",
                    "default": False,
                },
                "exclude": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional glob patterns to exclude from synchronization.",
                    "default": [],
                },
            },
            "required": ["direction", "local_dir", "node", "remote_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "enclave_ssh_config",
        "description": "Generate an OpenSSH ~/.ssh/config snippet using `egw stdio-proxy %h %p` for native ssh/rsync/IDE Remote-SSH.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Host alias prefix (default: 'enclave-').",
                    "default": "enclave-",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "node_db_query",
        "description": "Execute a SQL statement on a TargetNode (either directly on the host or inside a Docker container) without CLI password exposure.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {"type": "string", "description": "TargetNode name."},
                "container": {
                    "type": "string",
                    "description": "Optional Docker container name. Leave empty to run psql/mysql directly on the TargetNode.",
                    "default": "",
                },
                "engine": {
                    "type": "string",
                    "enum": ["mysql", "mariadb", "postgres", "postgresql"],
                    "description": "Database engine.",
                },
                "query": {"type": "string", "description": "SQL statement to execute."},
                "database": {"type": "string", "default": ""},
                "db_user": {"type": "string", "default": "root"},
                "db_password_env": {"type": "string", "default": ""},
                "confirm_destructive": {"type": "boolean", "default": False},
            },
            "required": ["node", "engine", "query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "node_http_request",
        "description": "Perform an HTTP/HTTPS request from inside a TargetNode to inspect internal services.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {"type": "string", "description": "TargetNode name."},
                "url": {"type": "string", "description": "Target URL."},
                "method": {"type": "string", "default": "GET"},
                "headers": {"type": "object", "default": {}},
                "body": {"type": "string", "default": ""},
                "insecure_tls": {"type": "boolean", "default": False},
            },
            "required": ["node", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "node_read_file",
        "description": "Read a UTF-8 file (or line range) from '@appliance', '@bastion', or a TargetNode with SHA-256 hash and secret scrubbing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {
                    "type": "string",
                    "description": "Target node identifier ('@appliance', '@bastion', or TargetNode name).",
                },
                "remote_path": {
                    "type": "string",
                    "description": "Path to the file on the remote node.",
                },
                "start_line": {
                    "type": "integer",
                    "description": "1-based start line (inclusive, default: 1).",
                    "default": 1,
                },
                "end_line": {
                    "type": "integer",
                    "description": "1-based end line (inclusive, 0 = until end of file).",
                    "default": 0,
                },
                "as_root": {
                    "type": "boolean",
                    "description": "Read with elevated sudo privileges on a Linux TargetNode.",
                    "default": False,
                },
            },
            "required": ["node", "remote_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "node_patch_file",
        "description": "Atomically replace a target block inside a remote UTF-8 file on '@appliance', '@bastion', or a TargetNode with optional SHA-256 precondition check.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {
                    "type": "string",
                    "description": "Target node identifier ('@appliance', '@bastion', or TargetNode name).",
                },
                "remote_path": {
                    "type": "string",
                    "description": "Path to the file on the remote node.",
                },
                "target": {
                    "type": "string",
                    "description": "Exact substring/block to replace.",
                },
                "replacement": {
                    "type": "string",
                    "description": "Replacement content.",
                },
                "expected_sha256": {
                    "type": "string",
                    "description": "Optional SHA-256 precondition from node_read_file to prevent concurrent overwrite.",
                    "default": "",
                },
                "as_root": {
                    "type": "boolean",
                    "description": "Write with elevated sudo privileges on a Linux TargetNode.",
                    "default": False,
                },
            },
            "required": ["node", "remote_path", "target", "replacement"],
            "additionalProperties": False,
        },
    },
    {
        "name": "enclave_tunnel",
        "description": "Dynamically start, stop, or list background TCP port forwards or universal SOCKS5/HTTP proxies over RdpVfsTransport.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "list"],
                    "description": "Action to perform ('start', 'stop', or 'list').",
                },
                "mode": {
                    "type": "string",
                    "enum": ["tcp", "proxy"],
                    "description": "'tcp' forwards a single port to target_host:target_port; 'proxy' starts a universal SOCKS5/SOCKS4a/HTTP CONNECT proxy.",
                    "default": "tcp",
                },
                "local_port": {
                    "type": "integer",
                    "description": "Local TCP port on 127.0.0.1 (0 = auto-assign on 'start', or stop all tunnels on 'stop').",
                    "default": 0,
                },
                "target_host": {
                    "type": "string",
                    "description": "TargetNode alias or IP/FQDN (required when action='start' and mode='tcp').",
                    "default": "",
                },
                "target_port": {
                    "type": "integer",
                    "description": "Remote TCP port (required when action='start' and mode='tcp').",
                    "default": 0,
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "enclave_audit",
        "description": "Retrieve recent session audit log entries from the FlightRecorder and verify its SHA-256 hash chain integrity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of recent audit entries to return (default: 25).",
                    "default": 25,
                }
            },
            "additionalProperties": False,
        },
    },
]


for definition in TOOL_DEFINITIONS:
    if definition["name"] in {"node_exec", "node_transfer", "node_sync", "node_read_file", "node_patch_file", "enclave_heal", "enclave_clean"}:
        definition["inputSchema"]["properties"]["tx_id"] = {"type": "string", "description": "Optional stable transaction id. Reuse retrieves the original operation and never replays ambiguous work."}

TOOL_DEFINITIONS.append({
    "name": "enclave_transaction", "description": "Get/list operation state and retained result, request cancellation, or mark expired execution indeterminate. Identity comes from the authenticated connection.",
    "inputSchema": {"type": "object", "properties": {
        "action": {"type": "string", "enum": ["get", "list", "cancel", "reconcile"], "default": "get"},
        "tx_id": {"type": "string"}, "limit": {"type": "integer", "default": 25}}, "additionalProperties": False},
})


TOOL_DEFINITIONS.append({"name": "enclave_capabilities", "description": "Report local capabilities and explicit unverified qualification boundaries without probing a live enclave.",
                         "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}})


class McpJsonRpcServer:
    """Handles MCP JSON-RPC 2.0 requests and dispatches tool calls to EnclaveEngine."""

    def __init__(
        self,
        engine: EnclaveEngine,
        *,
        read_only: bool = False,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        policy: AccessPolicy | None = None,
        principal: str = "local",
    ) -> None:
        self.engine = engine
        self.policy, self.principal = policy, principal
        if policy:
            policy.grant(principal)
        self.read_only = read_only
        self.max_output_chars = max_output_chars
        self._tunnel_lock = threading.RLock()
        self._request_lock = threading.Lock()
        self._request_transactions = {}
        self._queued_requests = set()
        self._queued_cancels = set()
        self._active_tunnels: dict[int, tuple[Any, threading.Thread, dict[str, Any]]] = {}

    def handle_message(self, msg: Any, *, principal: str | None = None) -> Any:
        verified = principal or self.principal
        with identity(verified), grant_scope(self.policy.grant(verified) if self.policy else None):
            return self._handle_message_impl(msg)

    def _handle_message_impl(self, msg: Any) -> Any:
        if isinstance(msg, list):
            if not msg or len(msg) > 128:
                return self._error(None, -32600, "Invalid Request")
            responses = [self._error(None, -32600, "Invalid Request") if isinstance(item, list) else self._handle_message_impl(item) for item in msg]
            return [item for item in responses if item is not None] or None
        if not isinstance(msg, dict):
            return self._error(None, -32600, "Invalid Request")
        req_id = msg.get("id")
        if (msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str)
                or isinstance(req_id, (dict, list, bool))
                or (isinstance(req_id, float) and not math.isfinite(req_id))):
            return self._error(None, -32600, "Invalid Request")
        if "params" in msg and not isinstance(msg["params"], (dict, list)):
            return None if "id" not in msg else self._error(req_id, -32602, "Invalid params")
        if not isinstance(msg.get("params", {}), dict):
            return None if "id" not in msg else self._error(req_id, -32602, "Named params required")
        if "id" not in msg:
            # Lifecycle notifications have no result. Other valid notifications
            # execute once, but their result must never be sent to the client.
            if msg["method"] == "notifications/cancelled":
                target = msg.get("params", {}).get("requestId")
                if not isinstance(target, (dict, list)):
                    with self._request_lock:
                        key = (operation_principal(), target)
                        tx_id = self._request_transactions.get(key)
                        if not tx_id and key in self._queued_requests:
                            self._queued_cancels.add(key)
                    if tx_id:
                        self.engine.request_cancel_pending(tx_id)
                return None
            if msg["method"].startswith("notifications/"):
                return None
            self._handle_request({**msg, "id": "notification"})
            return None
        result = self._handle_request(msg)
        if result and "result" in result:
            result["result"] = self.engine.vault.scrubber.scrub(result["result"])
        if result and "error" in result:
            result["error"] = self.engine.vault.scrubber.scrub(result["error"])
        return result

    def _handle_request(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method", "")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        try:
            if method == "initialize":
                client = params.get("clientInfo")
                if (not isinstance(params.get("protocolVersion"), str) or not isinstance(params.get("capabilities"), dict)
                        or not isinstance(client, dict) or not isinstance(client.get("name"), str) or not isinstance(client.get("version"), str)):
                    return self._error(req_id, -32602, "initialize requires protocolVersion, capabilities and clientInfo")
                return self._ok(
                    req_id,
                    {
                        "protocolVersion": params.get("protocolVersion") if params.get("protocolVersion") in MCP_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {"listChanged": False},
                            "resources": {"subscribe": False, "listChanged": False},
                            "prompts": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": "enclave-gateway",
                            "version": __version__,
                        },
                    },
                )
            if method in ("ping", "logging/setLevel"):
                return self._ok(req_id, {})
            if method == "tools/list":
                return self._ok(req_id, {"tools": self.visible_tools()})
            if method == "tools/call":
                tool_name = str(params.get("name", ""))
                args = params.get("arguments", {})
                error = validate_tool_arguments(tool_name, args)
                if error:
                    return self._error(req_id, -32602, error)
                if self.policy:
                    self.policy.authorize(operation_principal(), tool_name, args, self.engine.config)
                return self._call_tool(req_id, tool_name, args)
            if method == "resources/list":
                return self._ok(
                    req_id,
                    {
                        "resources": [
                            {
                                "uri": "enclave://topology",
                                "name": "Enclave Topology",
                                "description": "Configured Appliance, Bastion, TargetNodes, and PortForwards.",
                                "mimeType": "application/json",
                            },
                            {
                                "uri": "enclave://status",
                                "name": "Enclave Health Telemetry",
                                "description": "Live health status across Appliance, VPN, and Bastion.",
                                "mimeType": "application/json",
                            },
                        ]
                    },
                )
            if method == "resources/templates/list":
                return self._ok(req_id, {"resourceTemplates": []})
            if method == "resources/read":
                uri = str(params.get("uri", ""))
                if self.policy:
                    required = "enclave_status" if uri == "enclave://status" else "enclave_ssh_config"
                    self.policy.authorize(operation_principal(), required, {}, self.engine.config)
                if uri == "enclave://topology":
                    topo = {
                        "profile": self.engine.config.profile,
                        "targets": {
                            k: {
                                "host": v.host,
                                "port": v.port,
                                "user": v.user,
                                "via": v.via,
                                "os": v.os,
                            }
                            for k, v in self.engine.config.targets.items() if self.node_visible(k)
                        },
                        "forwards": {
                            k: {
                                "local_port": f.local_port,
                                "target_host": f.target_host,
                                "target_port": f.target_port,
                            }
                            for k, f in self.engine.config.forwards.items() if not self.policy
                        },
                    }
                    text = self._json_dump(topo, indent=2)
                elif uri == "enclave://status":
                    text = self._json_dump(self.public_status(), indent=2)
                else:
                    return self._error(req_id, -32602, f"Unknown resource URI: {uri}")
                return self._ok(
                    req_id,
                    {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": text,
                            }
                        ]
                    },
                )
            if method == "prompts/list":
                return self._ok(
                    req_id,
                    {
                        "prompts": [
                            {
                                "name": "enclave-diagnose",
                                "description": "Run L1-L7 diagnostics and self-heal any enclave connectivity drift.",
                                "arguments": [],
                            }
                        ]
                    },
                )
            if method == "prompts/get":
                if params.get("name") != "enclave-diagnose":
                    return self._error(req_id, -32602, "Unknown prompt")
                return self._ok(
                    req_id,
                    {
                        "description": "Diagnose and self-heal Enclave Gateway connectivity.",
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": "Call enclave_doctor with fix=false and probe_targets=true, then summarize the L1-L7 status.",
                                },
                            }
                        ],
                    },
                )

            return self._error(req_id, -32601, f"Method not found: {method}")
        except OperationError as exc:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32003 if exc.code == "access_denied" else -32001,
                    "message": self.engine.vault.scrubber.scrub(str(exc)), "data": exc.as_dict()}}
        except Exception as exc:
            metadata = getattr(exc, "operation_error", None)
            if metadata is not None:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001,
                        "message": self.engine.vault.scrubber.scrub(str(metadata)), "data": metadata.as_dict()}}
            return self._ok(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": self.engine.vault.scrubber.scrub(f"Error: {exc}"),
                        }
                    ],
                    "isError": True,
                },
            )

    def _call_tool(self, req_id, tool_name, args):
        transactional = tool_name in {"node_exec", "node_transfer", "node_sync", "node_read_file", "node_patch_file", "enclave_heal", "enclave_clean"}
        key = (operation_principal(), req_id)
        if transactional:
            args = dict(args)
            args["tx_id"] = args.get("tx_id") or "tx_" + secrets.token_hex(16)
            with self._request_lock:
                if key in self._request_transactions:
                    raise OperationError("duplicate_request_id", "dispatch")
                self._request_transactions[key] = args["tx_id"]
                cancel_queued = key in self._queued_cancels
            if cancel_queued:
                self.engine.request_cancel_pending(args["tx_id"])
        try:
            if tool_name == "enclave_tunnel":
                with self._tunnel_lock:
                    return self._dispatch_tool(req_id, tool_name, args)
            return self._dispatch_tool(req_id, tool_name, args)
        finally:
            if transactional:
                with self._request_lock:
                    self._request_transactions.pop(key, None)

    def stop_all_tunnels(self, owner: str | None = None) -> list[int]:
        """Stop all background tunnels managed by this MCP server."""
        stopped: list[int] = []
        for port, (srv, th, info) in list(self._active_tunnels.items()):
            if owner is not None and info.get("principal", self.principal) != owner:
                continue
            try:
                srv.stop()
                th.join(timeout=1.5)
            except Exception:
                pass
            stopped.append(port)
            self._active_tunnels.pop(port, None)
        return stopped

    def _check_read_only_violation(
        self, tool_name: str, args: dict[str, Any]
    ) -> str | None:
        if not self.read_only:
            return None
        permitted = {"enclave_status", "enclave_audit", "enclave_ssh_config", "node_read_file", "enclave_doctor", "enclave_tunnel", "enclave_transaction", "enclave_capabilities"}
        if tool_name not in permitted:
            return f"Tool '{tool_name}' is blocked in --read-only mode."
        if tool_name == "enclave_transaction" and args.get("action", "get") not in ("get", "list"):
            return "Transaction changes are blocked in --read-only mode."
        if tool_name == "enclave_tunnel" and args.get("action") != "list":
            return "Tunnel changes are blocked in --read-only mode."
        if tool_name == "enclave_doctor" and args.get("fix", False):
            return "enclave_doctor with fix=true is blocked in --read-only mode."
        if args.get("as_root", False) or args.get("confirm_destructive", False):
            return "Privilege escalation is blocked in --read-only mode."
        return None

    def _dispatch_tool(
        self, req_id: Any, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        ro_err = self._check_read_only_violation(tool_name, args)
        if ro_err is not None:
            return self._tool_result(req_id, ro_err, is_error=True)

        if tool_name == "enclave_capabilities":
            return self._tool_result(req_id, self._json_dump(self.engine.capabilities(), indent=2))

        if tool_name == "enclave_transaction":
            action = args.get("action", "get")
            tx_id = args.get("tx_id")
            if action in ("get", "cancel") and not tx_id:
                raise OperationError("invalid_arguments", "journal", message="tx_id is required")
            if self.policy and action in ("get", "cancel"):
                record = self.engine.transaction_status(tx_id)
                if not self.node_visible(record["node"]):
                    raise OperationError("access_denied", "policy")
            if action == "cancel":
                value = self.engine.cancel_transaction(tx_id)
            elif action == "reconcile":
                grant = self.policy.grant(operation_principal()) if self.policy else None
                nodes = ({canonical_node(node) for node in grant.nodes} if grant and "*" not in grant.nodes else None)
                value = {"indeterminate": self.engine.journal.reconcile_expired(operation_principal(), nodes=nodes)}
            else:
                value = self.engine.transaction_status(tx_id if action == "get" else None, limit=args.get("limit", 25))
            if self.policy and isinstance(value, list):
                value = [item for item in value if self.node_visible(item["node"])]
            if self.policy and isinstance(value, dict) and "node" in value and not self.node_visible(value["node"]):
                raise OperationError("access_denied", "policy")
            return self._tool_result(req_id, self._json_dump(value, indent=2))

        if tool_name == "enclave_status":
            status_data = self.public_status()
            return self._tool_result(req_id, self._json_dump(status_data, indent=2))

        if tool_name == "enclave_doctor":
            diag_data = self.engine.doctor(
                fix=bool(args.get("fix", False)),
                probe_targets=bool(args.get("probe_targets", False)),
                actor="mcp",
                nodes={name for name in self.engine.config.targets if self.node_visible(name)} if self.policy else None,
            )
            return self._tool_result(
                req_id,
                self._json_dump(diag_data, indent=2),
                is_error=not bool(diag_data.get("healthy", False)),
            )

        if tool_name == "enclave_heal":
            res = self.engine.heal(
                update_credentials=bool(args.get("update_credentials", False)),
                tx_id=args.get("tx_id"), actor="mcp",
            )
            return self._exec_to_tool_result(req_id, res)

        if tool_name == "enclave_clean":
            clean_data = self.engine.clean_session(tx_id=args.get("tx_id"), actor="mcp")
            return self._tool_result(req_id, self._json_dump(clean_data, indent=2))

        if tool_name == "node_exec":
            raw_env = dict(args.get("env") or {})
            raw_sec_env = dict(args.get("secret_env") or {})
            res = self.engine.exec_node(
                str(args["node"]),
                str(args["script"]),
                as_root=bool(args.get("as_root", False)),
                confirm_destructive=bool(args.get("confirm_destructive", False)),
                env={str(k): str(v) for k, v in raw_env.items()},
                secret_env={str(k): str(v) for k, v in raw_sec_env.items()},
                timeout_sec=float(args.get("timeout_sec", 120.0)),
                tx_id=args.get("tx_id"), actor="mcp",
            )
            return self._exec_to_tool_result(req_id, res)

        if tool_name == "node_transfer":
            meta = self.engine.transfer_file(
                str(args["direction"]),
                str(args["local_path"]),
                str(args["node"]),
                str(args["remote_path"]),
                as_root=bool(args.get("as_root", False)),
                use_delta=bool(args.get("use_delta", True)),
                tx_id=args.get("tx_id"), actor="mcp",
            )
            return self._tool_result(req_id, self._json_dump(meta, indent=2))

        if tool_name == "node_sync":
            raw_excl = list(args.get("exclude") or [])
            meta = self.engine.sync_directory(
                str(args["direction"]),
                str(args["local_dir"]),
                str(args["node"]),
                str(args["remote_dir"]),
                as_root=bool(args.get("as_root", False)),
                exclude=[str(x) for x in raw_excl],
                tx_id=args.get("tx_id"), actor="mcp",
            )
            return self._tool_result(req_id, self._json_dump(meta, indent=2))

        if tool_name == "node_read_file":
            meta = self.engine.read_remote_file(
                str(args["node"]),
                str(args["remote_path"]),
                start_line=int(args.get("start_line", 1)),
                end_line=int(args.get("end_line", 0)),
                as_root=bool(args.get("as_root", False)),
                tx_id=args.get("tx_id"), actor="mcp",
            )
            return self._tool_result(req_id, self._json_dump(meta, ensure_ascii=False, indent=2))

        if tool_name == "node_patch_file":
            meta = self.engine.patch_remote_file(
                str(args["node"]),
                str(args["remote_path"]),
                str(args["target"]),
                str(args["replacement"]),
                as_root=bool(args.get("as_root", False)),
                expected_sha256=str(args.get("expected_sha256", "")),
                tx_id=args.get("tx_id"), actor="mcp",
            )
            return self._tool_result(req_id, self._json_dump(meta, ensure_ascii=False, indent=2))

        if tool_name == "enclave_tunnel":
            action = str(args.get("action", "list")).lower()
            if action == "list":
                active = [info for _, _, info in self._active_tunnels.values() if info.get("principal", self.principal) == operation_principal()]
                return self._tool_result(
                    req_id, self._json_dump({"active_tunnels": active}, indent=2)
                )
            if action == "stop":
                port = int(args.get("local_port", 0))
                if port == 0:
                    stopped = self.stop_all_tunnels(owner=operation_principal())
                elif port in self._active_tunnels:
                    if self._active_tunnels[port][2].get("principal", self.principal) != operation_principal():
                        raise OperationError("access_denied", "policy", message="Tunnel belongs to another principal")
                    srv, th, _ = self._active_tunnels.pop(port)
                    srv.stop()
                    th.join(timeout=1.5)
                    stopped = [port]
                else:
                    stopped = []
                return self._tool_result(
                    req_id, self._json_dump({"stopped_ports": stopped}, indent=2)
                )
            if action == "start":
                mode = str(args.get("mode", "tcp")).lower()
                req_port = int(args.get("local_port", 0))
                if mode == "proxy":
                    aliases = {
                        name: spec.host
                        for name, spec in self.engine.config.targets.items() if self.node_visible(name)
                    }
                    transport = self.scoped_transport()
                    proxy_srv = Socks5VfsServer(
                        transport,
                        bind_host="127.0.0.1",
                        bind_port=req_port,
                        target_aliases=aliases,
                    )
                    th = threading.Thread(target=proxy_srv.serve_forever, daemon=True)
                    th.start()
                    proxy_srv.wait_ready()
                    bound = proxy_srv.bind_port
                    info = {
                        "mode": "proxy",
                        "local_port": bound,
                        "endpoint": f"127.0.0.1:{bound}",
                        "protocols": ["SOCKS5", "SOCKS4a", "HTTP CONNECT", "HTTP Proxy"],
                    }
                    info["principal"] = operation_principal()
                    self._active_tunnels[bound] = (proxy_srv, th, info)
                    return self._tool_result(req_id, self._json_dump(info, indent=2))

                target_host_raw = str(args.get("target_host", "")).strip()
                target_port = int(args.get("target_port", 0))
                if not target_host_raw or target_port <= 0:
                    return self._tool_result(
                        req_id,
                        "enclave_tunnel(action='start', mode='tcp') requires target_host and target_port > 0.",
                        is_error=True,
                    )
                resolved_host = (
                    self.engine.config.targets[target_host_raw].host
                    if target_host_raw in self.engine.config.targets
                    else target_host_raw
                )
                tun_srv = RdpVfsTunnelServer(
                    self.scoped_transport(),
                    local_port=req_port,
                    target_host=resolved_host,
                    target_port=target_port,
                    multiplexed=True,
                )
                th = threading.Thread(target=tun_srv.serve_forever, daemon=True)
                th.start()
                tun_srv.wait_ready()
                bound = tun_srv.local_port
                info = {
                    "mode": "tcp",
                    "local_port": bound,
                    "local_endpoint": f"127.0.0.1:{bound}",
                    "target_host": target_host_raw,
                    "resolved_host": resolved_host,
                    "target_port": target_port,
                }
                info["principal"] = operation_principal()
                self._active_tunnels[bound] = (tun_srv, th, info)
                return self._tool_result(req_id, self._json_dump(info, indent=2))

        if tool_name == "enclave_audit":
            limit = max(1, int(args.get("limit", 25)))
            chain_ok, verified_records = self.engine.recorder.verify_integrity()
            entries = self.engine.recorder.read_recent(limit=limit)
            return self._tool_result(
                req_id,
                self._json_dump(
                    {
                        "integrity_verified": chain_ok,
                        "verified_records": verified_records,
                        "entries": entries,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
            )

        if tool_name == "enclave_ssh_config":
            prefix = str(args.get("prefix", "enclave-"))
            return self._tool_result(
                req_id, self.engine.generate_ssh_config(prefix=prefix, nodes={name for name in self.engine.config.targets if self.node_visible(name)})
            )

        if tool_name == "node_db_query":
            res = self.engine.query_database(
                str(args["node"]),
                str(args.get("container", "")),
                str(args["engine"]),
                str(args["query"]),
                database=str(args.get("database", "")),
                db_user=str(args.get("db_user", "root")),
                db_password_env=str(args.get("db_password_env", "")),
                confirm_destructive=bool(args.get("confirm_destructive", False)),
                actor="mcp",
            )
            return self._exec_to_tool_result(req_id, res)

        if tool_name == "node_http_request":
            res = self.engine.http_request(
                str(args["node"]),
                str(args["url"]),
                method=str(args.get("method", "GET")),
                headers=dict(args.get("headers") or {}),
                body=str(args.get("body", "")),
                insecure_tls=bool(args.get("insecure_tls", False)),
                actor="mcp",
            )
            return self._exec_to_tool_result(req_id, res)

        return self._error(req_id, -32602, f"Unknown tool: {tool_name}")

    def _exec_to_tool_result(self, req_id: Any, res: Any) -> dict[str, Any]:
        payload = {
            "exit_code": res.exit_code,
            "duration_ms": res.duration_ms,
            "tx_id": getattr(res, "tx_id", ""),
            "timings_ms": getattr(res, "timings_ms", {}),
            "stdout": truncate_for_context(self.engine.vault.scrubber.scrub(res.stdout), self.max_output_chars),
            "stderr": truncate_for_context(self.engine.vault.scrubber.scrub(res.stderr), self.max_output_chars),
        }
        return self._tool_result(
            req_id,
            self._json_dump(payload, ensure_ascii=False, indent=2),
            is_error=(res.exit_code != 0),
        )

    def _tool_result(self, req_id: Any, text: str, *, is_error: bool = False) -> dict[str, Any]:
        bounded_text = truncate_for_context(self.engine.vault.scrubber.scrub(text), self.max_output_chars)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": bounded_text}],
                "isError": is_error,
            },
        }

    def public_status(self):
        value = self.engine.status()
        if self.policy:
            value["targets"] = [name for name in value.get("targets", []) if self.node_visible(name)]
        return value

    def node_visible(self, node: str) -> bool:
        return not self.policy or self.policy.grant(operation_principal()).permits_node(node)

    def visible_tools(self):
        return [tool for tool in TOOL_DEFINITIONS if not self.policy or self.policy.grant(operation_principal()).permits_tool(tool["name"])]

    def scoped_transport(self):
        if self.policy:
            return ScopedMuxTransport(self.engine.rdp_vfs, self.policy, self.policy.grant(operation_principal()))
        return self.engine.rdp_vfs

    def _json_dump(self, value, **kwargs):
        return json.dumps(self.engine.vault.scrubber.scrub(value), **kwargs)

    @staticmethod
    def _ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }

    def serve_stdio(
        self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout
    ) -> None:
        """Serve MCP JSON-RPC 2.0 over stdio supporting both newline-JSON and Content-Length framing."""
        # Use binary buffers when available: Content-Length counts UTF-8 bytes.
        source = getattr(stdin, "buffer", stdin)
        sink = getattr(stdout, "buffer", stdout)
        binary_input = not isinstance(source.read(0), str)
        def emit(response, framed):
            raw = json.dumps(response, ensure_ascii=False)
            message = (f"Content-Length: {len(raw.encode('utf-8'))}\r\n\r\n" if framed else "") + raw + ("" if framed else "\n")
            try:
                sink.write(message)
            except TypeError:
                sink.write(message.encode("utf-8"))
            sink.flush()
        write_lock = threading.Lock()
        original_emit = emit
        def emit(response, framed):
            with write_lock:
                original_emit(response, framed)
        slots = threading.BoundedSemaphore(16)
        def process(message, framed):
            try:
                response = self.handle_message(message)
                if response is not None:
                    emit(response, framed)
            finally:
                if isinstance(message, dict) and isinstance(message.get("id"), (str, int, float, type(None))):
                    key = (self.principal, message.get("id"))
                    with self._request_lock:
                        self._queued_requests.discard(key)
                        self._queued_cancels.discard(key)
                slots.release()
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="egw-stdio") as executor:
            try:
                self._read_stdio(source, binary_input, emit, process, executor, slots)
            except KeyboardInterrupt:
                with self._request_lock:
                    pending = list(self._request_transactions.values())
                with identity(self.principal):
                    for tx_id in pending:
                        self.engine.request_cancel_pending(tx_id)
                raise

    def _read_stdio(self, source, binary_input, emit, process, executor, slots):
        while True:
            line = source.readline(MAX_RPC_BYTES + 1)
            if not line:
                break
            line_bytes = line.encode("utf-8") if isinstance(line, str) else line
            if len(line_bytes) > MAX_RPC_BYTES:
                emit(self._error(None, -32600, "Request too large"), False)
                break
            if not line_bytes.strip():
                continue
            framed = line_bytes.lower().startswith(b"content-length:")
            try:
                if framed:
                    length = int(line_bytes.split(b":", 1)[1])
                    if not 0 < length <= MAX_RPC_BYTES:
                        raise ValueError("Invalid Content-Length")
                    header_size = len(line_bytes)
                    while True:
                        header = source.readline(MAX_RPC_BYTES + 1)
                        header_size += len(header)
                        if not header or header_size > MAX_RPC_BYTES:
                            raise ValueError("Invalid frame headers")
                        if header in (b"\r\n", b"\n", "\r\n", "\n"):
                            break
                    data = bytearray()
                    while len(data) < length:
                        part = source.read(length - len(data)) if binary_input else source.read(1)
                        if not part:
                            raise ValueError("Truncated frame")
                        data.extend(part.encode("utf-8") if isinstance(part, str) else part)
                    if len(data) != length:
                        raise ValueError("Invalid UTF-8 frame length")
                    payload = bytes(data)
                else:
                    payload = line_bytes
                msg = strict_json_loads(payload)
            except (ValueError, UnicodeError, RecursionError):
                emit(self._error(None, -32700, "Parse error"), framed)
                if framed:
                    break
                continue
            if isinstance(msg, dict) and "id" not in msg:
                self.handle_message(msg)
            elif slots.acquire(blocking=False):
                if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int, float, type(None))):
                    key = (self.principal, msg.get("id"))
                    with self._request_lock:
                        duplicate = key in self._queued_requests
                        if not duplicate:
                            self._queued_requests.add(key)
                    if duplicate:
                        slots.release()
                        emit(self._error(msg["id"], -32600, "Duplicate active request id"), framed)
                        continue
                executor.submit(process, msg, framed)
            else:
                emit(self._error(msg.get("id") if isinstance(msg, dict) else None, -32000, "Server request queue is full"), framed)


def export_openai_tools() -> list[dict[str, Any]]:
    """Export MCP TOOL_DEFINITIONS in OpenAI / Ollama / vLLM / llama.cpp function-calling schema."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["inputSchema"],
            },
        }
        for tool in TOOL_DEFINITIONS
    ]


def export_openapi_spec(server_url: str = "http://127.0.0.1:8765") -> dict[str, Any]:
    """Export OpenAPI 3.1.0 specification for Open WebUI, AnythingLLM, and local LLM Tool Servers."""
    paths: dict[str, Any] = {}
    for tool in TOOL_DEFINITIONS:
        t_name = tool["name"]
        paths[f"/tools/{t_name}"] = {
            "post": {
                "operationId": t_name,
                "summary": tool["description"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": tool["inputSchema"],
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Tool execution output",
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"},
                            }
                        },
                    }
                },
            }
        }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Enclave Gateway Tool Server",
            "version": __version__,
            "description": "MCP & OpenAPI bridge for local LLMs (Ollama, Open WebUI, LM Studio, vLLM, llama.cpp).",
        },
        "servers": [{"url": server_url}],
        "paths": paths,
    }


class McpHttpServer:
    """Local HTTP bridge exposing Streamable HTTP MCP (/mcp), OpenAI Tools (/v1/tools), and OpenAPI (/openapi.json)."""

    def __init__(
        self,
        rpc_server: McpJsonRpcServer,
        bind_host: str = "127.0.0.1",
        bind_port: int = 8765,
        *,
        bearer_token: str = "",
        allowed_origins: tuple[str, ...] = (),
        principal_tokens: dict[str, str] | None = None,
    ) -> None:
        self.rpc_server = rpc_server
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.bearer_token = bearer_token
        self.principal_tokens = dict(principal_tokens or {})
        if bearer_token in self.principal_tokens and self.principal_tokens[bearer_token] != rpc_server.principal:
            raise ValueError("One token cannot identify multiple principals")
        if rpc_server.policy:
            for token, owner in self.principal_tokens.items():
                if len(token) < 16:
                    raise ValueError("Principal token must contain at least 16 characters")
                rpc_server.policy.grant(owner)
            if not bearer_token and not self.principal_tokens:
                raise ValueError("A scoped HTTP server requires authenticated principal tokens")
            if bearer_token and len(bearer_token) < 16:
                raise ValueError("Scoped bearer token must contain at least 16 characters")
        self.allowed_origins = frozenset(allowed_origins)
        if bind_host not in ("127.0.0.1", "localhost", "::1") and not bearer_token and not self.principal_tokens:
            raise ValueError("Non-loopback HTTP listeners require a bearer token")
        self._httpd: ThreadingHTTPServer | None = None

    def serve_forever(self) -> None:
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(15.0)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _check_auth(self, *, require_token: bool = True) -> bool:
                authority = f"{parent.bind_host}:{parent.bind_port}"
                local_authorities = {authority}
                if parent.bind_host in ("127.0.0.1", "localhost"):
                    local_authorities.update({f"127.0.0.1:{parent.bind_port}", f"localhost:{parent.bind_port}"})
                if len(self.headers.get_all("Host", [])) != 1 or len(self.headers.get_all("Origin", [])) > 1 or self.headers.get("Host", "") not in local_authorities:
                    self._send_json(403, {"error": "Invalid Host"})
                    return False
                origin = self.headers.get("Origin")
                permitted = parent.allowed_origins | {f"http://{host}" for host in local_authorities}
                if origin is not None and origin not in permitted:
                    self._send_json(403, {"error": "Invalid Origin"})
                    return False
                self.principal = parent.rpc_server.principal
                if not require_token:
                    return True
                if not parent.bearer_token and not parent.principal_tokens:
                    return True
                if len(self.headers.get_all("Authorization", [])) != 1:
                    self._send_json(401, {"error": "One authorization credential is required"})
                    return False
                auth = self.headers.get("Authorization", "").encode()
                matched = None
                for token, owner in parent.principal_tokens.items():
                    if hmac.compare_digest(auth, ("Bearer " + token).encode()):
                        matched = owner
                if parent.bearer_token and hmac.compare_digest(auth, ("Bearer " + parent.bearer_token).encode()):
                    matched = parent.rpc_server.principal
                if matched is not None:
                    self.principal = matched
                    return True
                self._send_json(401, {"error": "Unauthorized"})
                return False

            def _send_json(self, status: int, data: Any) -> None:
                raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                origin = self.headers.get("Origin")
                if origin and origin in parent.allowed_origins:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                self.send_header(
                    "Access-Control-Allow-Headers", "Content-Type, Authorization"
                )
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()
                self.wfile.write(raw)

            def do_OPTIONS(self) -> None:
                if self._check_auth(require_token=False):
                    self._send_json(200, {"ok": True})

            def do_GET(self) -> None:
                if not self._check_auth():
                    return
                path = self.path.split("?", 1)[0]
                if path == "/mcp":
                    self.send_response(405)
                    self.send_header("Allow", "POST")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path == "/openapi.json":
                    url = f"http://{parent.bind_host}:{parent.bind_port}"
                    spec = export_openapi_spec(url)
                    if parent.rpc_server.policy:
                        grant = parent.rpc_server.policy.grant(self.principal)
                        spec["paths"] = {path: item for path, item in spec["paths"].items() if grant.permits_tool(path.rsplit("/", 1)[-1])}
                    self._send_json(200, spec)
                    return
                if path == "/v1/tools":
                    listing = export_openai_tools()
                    if parent.rpc_server.policy:
                        grant = parent.rpc_server.policy.grant(self.principal)
                        listing = [tool for tool in listing if grant.permits_tool(tool["function"]["name"])]
                    self._send_json(200, {"tools": listing})
                    return
                if path == "/healthz":
                    self._send_json(200, {"status": "ok", "version": __version__})
                    return
                self._send_json(404, {"error": f"Unknown endpoint: {path}"})

            def do_POST(self) -> None:
                if not self._check_auth():
                    return
                if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                    self._send_json(400, {"error": "One Content-Length is required; chunked requests are unsupported"})
                    return
                try:
                    length = int(self.headers["Content-Length"])
                except ValueError:
                    self._send_json(400, {"error": "Invalid Content-Length"})
                    return
                if not 0 < length <= MAX_RPC_BYTES:
                    self._send_json(413, {"error": "Invalid body size"})
                    return
                if self.headers.get_content_type() != "application/json":
                    self._send_json(415, {"error": "Expected application/json"})
                    return
                try:
                    raw_body = self.rfile.read(length)
                    if len(raw_body) != length:
                        raise ValueError("Truncated request")
                    body = strict_json_loads(raw_body)
                except (ValueError, UnicodeError, OSError, RecursionError):
                    self._send_json(400, {"error": "Invalid JSON body"})
                    return

                path = self.path.split("?", 1)[0]
                if path == "/mcp":
                    if self.headers.get("MCP-Protocol-Version", MCP_PROTOCOL_VERSION) not in MCP_PROTOCOL_VERSIONS:
                        self._send_json(400, {"error": "Unsupported protocol version"})
                        return
                    resp = parent.rpc_server.handle_message(body, principal=self.principal)
                    if resp is None:
                        self.send_response(202)
                        self.end_headers()
                    else:
                        self._send_json(200, resp)
                    return

                if path == "/v1/tools/call":
                    if not isinstance(body, dict):
                        self._send_json(400, {"error": "Expected an object"})
                        return
                    t_name = str(body.get("name", ""))
                    t_args = body.get("arguments", {})
                    rpc_resp = parent.rpc_server.handle_message(
                        {
                            "jsonrpc": "2.0",
                            "id": "http-tool-call",
                            "method": "tools/call",
                            "params": {"name": t_name, "arguments": t_args},
                        }, principal=self.principal
                    )
                    self._send_json(200, rpc_resp or {})
                    return

                if path.startswith("/tools/"):
                    t_name = path.partition("/tools/")[2].strip("/")
                    rpc_resp = parent.rpc_server.handle_message(
                        {
                            "jsonrpc": "2.0",
                            "id": f"openapi-{t_name}",
                            "method": "tools/call",
                            "params": {"name": t_name, "arguments": body},
                        }, principal=self.principal
                    )
                    if "error" in (rpc_resp or {}):
                        code = rpc_resp["error"]["code"]
                        self._send_json(403 if code == -32003 else 422 if code == -32001 else 400, rpc_resp["error"])
                        return
                    result = (rpc_resp or {}).get("result", {})
                    content = result.get("content") or []
                    text_out = content[0].get("text", "") if content else ""
                    try:
                        parsed = json.loads(text_out)
                    except Exception:
                        parsed = {"output": text_out}
                    self._send_json(422 if result.get("isError") else 200, parsed if isinstance(parsed, dict) else {"output": parsed})
                    return

                self._send_json(404, {"error": f"Unknown endpoint: {path}"})

        httpd = BoundedHttpServer((self.bind_host, self.bind_port), _Handler)
        self.bind_port = httpd.server_address[1]
        self._httpd = httpd
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()

    def stop(self) -> None:
        if self._httpd is not None:
            threading.Thread(target=self._httpd.shutdown, daemon=True).start()


def generate_client_configs(
    config_path: str | Path = "./enclave.yaml",
    http_url: str = "http://127.0.0.1:8765",
) -> dict[str, Any]:
    """Generate ready-to-use MCP / Tool configurations for all major IDEs and local LLM stacks."""
    resolved_cfg = str(Path(config_path or "./enclave.yaml").expanduser().resolve())
    args = ["-c", resolved_cfg, "mcp"]

    return {
        "cursor": {
            "mcpServers": {
                "enclave-gateway": {"command": "egw", "args": args}
            }
        },
        "vscode": {
            "servers": {
                "enclave-gateway": {
                    "type": "stdio",
                    "command": "egw",
                    "args": args,
                }
            }
        },
        "zed": {
            "context_servers": {
                "enclave-gateway": {
                    "command": {"path": "egw", "args": args, "env": {}}
                }
            }
        },
        "continue": (
            "mcpServers:\n"
            "  - name: enclave-gateway\n"
            "    command: egw\n"
            "    args:\n"
            f'      - "-c"\n'
            f'      - {json.dumps(resolved_cfg)}\n'
            '      - "mcp"\n'
        ),
        "codex": (
            "[mcp_servers.enclave-gateway]\n"
            'command = "egw"\n'
            f'args = {json.dumps(["-c", resolved_cfg, "mcp"])}\n'
        ),
        "claude-code": f'claude mcp add enclave-gateway -- egw -c "{resolved_cfg}" mcp',
        "lm-studio": {
            "mcpServers": {
                "enclave-gateway": {"command": "egw", "args": args}
            }
        },
        "open-webui": {
            "mcp_streamable_http_url": f"{http_url}/mcp",
            "openapi_tool_server_url": f"{http_url}/openapi.json",
            "start_command": f'egw -c "{resolved_cfg}" mcp --listen 127.0.0.1:8765',
        },
        "ollama": {
            "tools_endpoint": f"{http_url}/v1/tools",
            "call_endpoint": f"{http_url}/v1/tools/call",
            "start_command": f'egw -c "{resolved_cfg}" mcp --listen 127.0.0.1:8765',
        },
    }
