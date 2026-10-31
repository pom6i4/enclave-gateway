"""Model Context Protocol (MCP) JSON-RPC 2.0 Server over stdio."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from enclave_gateway import __version__
from enclave_gateway.engine import EnclaveEngine

MCP_PROTOCOL_VERSION = "2024-11-05"

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
        "description": "Execute a SQL statement inside a database container (mysql/postgres) on a TargetNode without shell-quoting hazards.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {"type": "string", "description": "TargetNode name."},
                "container": {"type": "string", "description": "Docker container name."},
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
            "required": ["node", "container", "engine", "query"],
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
]


class McpJsonRpcServer:
    """Handles MCP JSON-RPC 2.0 requests and dispatches tool calls to EnclaveEngine."""

    def __init__(self, engine: EnclaveEngine) -> None:
        self.engine = engine

    def handle_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method", "")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        if req_id is None:
            # Notification (e.g., notifications/initialized)
            return None

        try:
            if method == "initialize":
                return self._ok(
                    req_id,
                    {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {
                            "name": "enclave-gateway",
                            "version": __version__,
                        },
                    },
                )
            if method == "ping":
                return self._ok(req_id, {})
            if method == "tools/list":
                return self._ok(req_id, {"tools": TOOL_DEFINITIONS})
            if method == "tools/call":
                tool_name = str(params.get("name", ""))
                args = dict(params.get("arguments") or {})
                return self._dispatch_tool(req_id, tool_name, args)

            return self._error(req_id, -32601, f"Method not found: {method}")
        except Exception as exc:
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

    def _dispatch_tool(
        self, req_id: Any, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        if tool_name == "enclave_status":
            status_data = self.engine.status()
            return self._tool_result(req_id, json.dumps(status_data, indent=2))

        if tool_name == "enclave_doctor":
            diag_data = self.engine.doctor(
                fix=bool(args.get("fix", False)),
                probe_targets=bool(args.get("probe_targets", False)),
                actor="mcp",
            )
            return self._tool_result(
                req_id,
                json.dumps(diag_data, indent=2),
                is_error=not bool(diag_data.get("healthy", False)),
            )

        if tool_name == "enclave_heal":
            res = self.engine.heal(
                update_credentials=bool(args.get("update_credentials", False)),
                actor="mcp",
            )
            return self._exec_to_tool_result(req_id, res)

        if tool_name == "enclave_clean":
            clean_data = self.engine.clean_session(actor="mcp")
            return self._tool_result(req_id, json.dumps(clean_data, indent=2))

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
                actor="mcp",
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
                actor="mcp",
            )
            return self._tool_result(req_id, json.dumps(meta, indent=2))

        if tool_name == "node_sync":
            raw_excl = list(args.get("exclude") or [])
            meta = self.engine.sync_directory(
                str(args["direction"]),
                str(args["local_dir"]),
                str(args["node"]),
                str(args["remote_dir"]),
                as_root=bool(args.get("as_root", False)),
                exclude=[str(x) for x in raw_excl],
                actor="mcp",
            )
            return self._tool_result(req_id, json.dumps(meta, indent=2))

        if tool_name == "enclave_ssh_config":
            prefix = str(args.get("prefix", "enclave-"))
            return self._tool_result(
                req_id, self.engine.generate_ssh_config(prefix=prefix)
            )

        if tool_name == "node_db_query":
            res = self.engine.query_database(
                str(args["node"]),
                str(args["container"]),
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
            "stdout": res.stdout,
            "stderr": res.stderr,
        }
        return self._tool_result(
            req_id,
            json.dumps(payload, ensure_ascii=False, indent=2),
            is_error=(res.exit_code != 0),
        )

    @staticmethod
    def _tool_result(req_id: Any, text: str, *, is_error: bool = False) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": is_error,
            },
        }

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
        for raw_line in stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp = self.handle_message(msg)
            if resp is not None:
                stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout.flush()
