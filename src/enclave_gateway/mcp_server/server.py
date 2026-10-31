"""Model Context Protocol (MCP) JSON-RPC 2.0 Server over stdio and Streamable HTTP / OpenAPI."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
                return self._ok(req_id, {"tools": TOOL_DEFINITIONS})
            if method == "tools/call":
                tool_name = str(params.get("name", ""))
                args = dict(params.get("arguments") or {})
                return self._dispatch_tool(req_id, tool_name, args)
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
                            for k, v in self.engine.config.targets.items()
                        },
                        "forwards": {
                            k: {
                                "local_port": f.local_port,
                                "target_host": f.target_host,
                                "target_port": f.target_port,
                            }
                            for k, f in self.engine.config.forwards.items()
                        },
                    }
                    text = json.dumps(topo, indent=2)
                elif uri == "enclave://status":
                    text = json.dumps(self.engine.status(), indent=2)
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
                return self._ok(
                    req_id,
                    {
                        "description": "Diagnose and self-heal Enclave Gateway connectivity.",
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": "Call enclave_doctor with fix=true and probe_targets=true, then summarize the L1-L7 status.",
                                },
                            }
                        ],
                    },
                )

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
        """Serve MCP JSON-RPC 2.0 over stdio supporting both newline-JSON and Content-Length framing."""
        while True:
            raw_line = stdin.readline()
            if not raw_line:
                break
            line = raw_line.strip()
            if not line:
                continue

            use_content_length = False
            if line.lower().startswith("content-length:"):
                use_content_length = True
                try:
                    length = int(line.partition(":")[2].strip())
                except ValueError:
                    continue
                while True:
                    hdr = stdin.readline()
                    if not hdr or hdr in ("\r\n", "\n", ""):
                        break
                body = stdin.read(length)
                if not body:
                    break
                payload_str = body
            else:
                payload_str = line

            try:
                msg = json.loads(payload_str)
            except json.JSONDecodeError:
                continue

            resp = self.handle_message(msg)
            if resp is not None:
                out_json = json.dumps(resp, ensure_ascii=False)
                if use_content_length:
                    encoded = out_json.encode("utf-8")
                    stdout.write(f"Content-Length: {len(encoded)}\r\n\r\n{out_json}")
                else:
                    stdout.write(out_json + "\n")
                stdout.flush()


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
    ) -> None:
        self.rpc_server = rpc_server
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.bearer_token = bearer_token
        self._httpd: ThreadingHTTPServer | None = None

    def serve_forever(self) -> None:
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _check_auth(self) -> bool:
                if not parent.bearer_token:
                    return True
                auth = self.headers.get("Authorization", "")
                if auth == f"Bearer {parent.bearer_token}":
                    return True
                self._send_json(401, {"error": "Unauthorized"})
                return False

            def _send_json(self, status: int, data: Any) -> None:
                raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header(
                    "Access-Control-Allow-Headers", "Content-Type, Authorization"
                )
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()
                self.wfile.write(raw)

            def do_OPTIONS(self) -> None:
                self._send_json(200, {"ok": True})

            def do_GET(self) -> None:
                if not self._check_auth():
                    return
                path = self.path.split("?", 1)[0]
                if path == "/openapi.json":
                    url = f"http://{parent.bind_host}:{parent.bind_port}"
                    self._send_json(200, export_openapi_spec(url))
                    return
                if path == "/v1/tools":
                    self._send_json(200, {"tools": export_openai_tools()})
                    return
                if path == "/healthz":
                    self._send_json(200, {"status": "ok", "version": __version__})
                    return
                self._send_json(404, {"error": f"Unknown endpoint: {path}"})

            def do_POST(self) -> None:
                if not self._check_auth():
                    return
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
                try:
                    body = json.loads(raw_body) if raw_body.strip() else {}
                except json.JSONDecodeError:
                    self._send_json(400, {"error": "Invalid JSON body"})
                    return

                path = self.path.split("?", 1)[0]
                if path == "/mcp":
                    resp = parent.rpc_server.handle_message(body)
                    if resp is None:
                        self.send_response(202)
                        self.end_headers()
                    else:
                        self._send_json(200, resp)
                    return

                if path == "/v1/tools/call":
                    t_name = str(body.get("name", ""))
                    t_args = dict(body.get("arguments") or {})
                    rpc_resp = parent.rpc_server.handle_message(
                        {
                            "jsonrpc": "2.0",
                            "id": "http-tool-call",
                            "method": "tools/call",
                            "params": {"name": t_name, "arguments": t_args},
                        }
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
                        }
                    )
                    result = (rpc_resp or {}).get("result", {})
                    content = result.get("content") or []
                    text_out = content[0].get("text", "") if content else ""
                    try:
                        parsed = json.loads(text_out)
                    except Exception:
                        parsed = {"output": text_out}
                    self._send_json(200, parsed)
                    return

                self._send_json(404, {"error": f"Unknown endpoint: {path}"})

        httpd = ThreadingHTTPServer((self.bind_host, self.bind_port), _Handler)
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
    resolved_cfg = str(Path(config_path).expanduser().resolve())
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
            f'      - "{resolved_cfg}"\n'
            '      - "mcp"\n'
        ),
        "codex": (
            "[mcp_servers.enclave-gateway]\n"
            'command = "egw"\n'
            f'args = ["-c", "{resolved_cfg}", "mcp"]\n'
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
