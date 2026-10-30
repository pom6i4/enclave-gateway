"""Unit and integration test suite for enclave-gateway."""

from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.config import EnclaveConfig, parse_yaml_or_json
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.mcp_server.server import McpJsonRpcServer
from enclave_gateway.security.secrets import (
    DestructiveOperationError,
    SecretScrubber,
    SecretVault,
    verify_command_safety,
)
from enclave_gateway.transports.rdp_vfs import (
    compute_block_manifest,
    compute_file_sha256,
)
from enclave_gateway.transports.ssh_hop import build_remote_bash_invocation


class LoopbackControlChannel:
    """In-memory loopback simulator for Appliance + BastionWorker IPC."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.last_script: str = ""

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        self.last_script = script
        if "[Convert]::FromBase64String('" in script and "req_" in script:
            b64_part = script.split("[Convert]::FromBase64String('", 1)[1].split("')", 1)[0]
            env_json = json.loads(base64.b64decode(b64_part).decode("utf-8"))
            tx_id = env_json["tx_id"]
            inner_cmd = base64.b64decode(env_json["payload_b64"]).decode("utf-8")
            out_str = f"BASTION_EXEC_OK:{inner_cmd}"
            res_payload = {
                "tx_id": tx_id,
                "exit_code": 0,
                "stdout_b64": base64.b64encode(out_str.encode("utf-8")).decode("ascii"),
                "stderr_b64": "",
                "duration_ms": 12,
            }
            return ExecResult(
                exit_code=0,
                stdout=json.dumps(res_payload),
                stderr="",
                duration_ms=15,
            )

        if "ConvertTo-Json $out -Compress" in script:
            status_obj = {
                "tunnel_up": True,
                "source_ip": "10.0.6.228",
                "vpn_info": "Connection: Active",
                "worker": json.dumps({"pid": 4120, "uptime_sec": 3600}),
            }
            return ExecResult(
                exit_code=0,
                stdout=json.dumps(status_obj),
                stderr="",
                duration_ms=10,
            )

        return ExecResult(
            exit_code=0,
            stdout=f"APPLIANCE_EXEC_OK:{script.strip()}",
            stderr="",
            duration_ms=5,
        )

    def write_bytes(self, data: bytes, guest_path: str) -> None:
        self.files[guest_path] = data

    def read_bytes(self, guest_path: str) -> bytes:
        return self.files[guest_path]

    def write_file(self, local_path: Path, guest_path: str) -> None:
        self.files[guest_path] = local_path.read_bytes()

    def read_file(self, guest_path: str, local_path: Path) -> None:
        local_path.write_bytes(self.files[guest_path])


class EnclaveGatewayTests(unittest.TestCase):
    def test_yaml_parser_and_config_loader(self) -> None:
        sample = """
profile: staging
appliance:
  name: test-appliance
  cpus: 6
  mtu: 1350
targets:
  app01:
    host: 10.0.20.11
    port: 22
    user: deploy
    via: bastion
"""
        parsed = parse_yaml_or_json(sample)
        cfg = EnclaveConfig.from_dict(parsed)
        self.assertEqual(cfg.profile, "staging")
        self.assertEqual(cfg.appliance.name, "test-appliance")
        self.assertEqual(cfg.appliance.cpus, 6)
        self.assertEqual(cfg.appliance.mtu, 1350)
        self.assertIn("app01", cfg.targets)
        self.assertEqual(cfg.targets["app01"].host, "10.0.20.11")

    def test_secret_scrubber_and_crlf_normalization(self) -> None:
        with TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_bytes(b"ENCLAVE_BASTION_PASSWORD=SuperSecret#2026\r\n")
            vault = SecretVault(env_file=env_path)
            pw = vault.get("ENCLAVE_BASTION_PASSWORD")
            self.assertEqual(pw, "SuperSecret#2026")
            self.assertFalse(pw.endswith("\r"))

            scrubber = vault.scrubber
            raw_out = "Connecting with SuperSecret#2026 and SuperSecret%232026"
            scrubbed = scrubber.scrub(raw_out)
            self.assertNotIn("SuperSecret", scrubbed)
            self.assertEqual(scrubbed, "Connecting with [REDACTED] and [REDACTED]")

    def test_destructive_command_guardrails(self) -> None:
        verify_command_safety("SELECT id, email FROM users WHERE deleted = 0;")
        with self.assertRaises(DestructiveOperationError):
            verify_command_safety("DROP TABLE users;")
        with self.assertRaises(DestructiveOperationError):
            verify_command_safety("rm -rf /")
        verify_command_safety("DROP TABLE users;", confirm_destructive=True)

    def test_remote_bash_invocation_strips_cr(self) -> None:
        cmd = build_remote_bash_invocation("uname -a\r\nuptime", as_root=True)
        self.assertIn("sudo -S -p ''", cmd)
        self.assertIn("tr -d '\\r'", cmd)

    def test_block_manifest_and_sha256(self) -> None:
        with TemporaryDirectory() as tmp:
            f = Path(tmp) / "payload.bin"
            f.write_bytes(b"A" * 1024 + b"B" * 1024 + b"C" * 512)
            manifest = compute_block_manifest(f, block_size=1024)
            self.assertEqual(len(manifest), 3)
            self.assertEqual(manifest[0].size, 1024)
            self.assertEqual(manifest[2].size, 512)
            self.assertEqual(len(compute_file_sha256(f)), 64)

    def test_engine_and_mcp_server_dispatch(self) -> None:
        with TemporaryDirectory() as tmp:
            cfg = EnclaveConfig.from_dict(
                {
                    "profile": "test",
                    "targets": {
                        "app01": {
                            "host": "10.0.20.11",
                            "user": "deploy",
                            "via": "bastion",
                        }
                    },
                }
            )
            vault = SecretVault()
            vault.scrubber.register("HiddenToken999")
            recorder = FlightRecorder(log_path=Path(tmp) / "audit.jsonl")
            control = LoopbackControlChannel()
            engine = EnclaveEngine(
                config=cfg, vault=vault, recorder=recorder, control_override=control
            )
            mcp = McpJsonRpcServer(engine)

            init_resp = mcp.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            self.assertIsNotNone(init_resp)
            self.assertEqual(
                init_resp["result"]["serverInfo"]["name"], "enclave-gateway"  # type: ignore[index]
            )

            tools_resp = mcp.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tool_names = [t["name"] for t in tools_resp["result"]["tools"]]  # type: ignore[index]
            self.assertIn("enclave_status", tool_names)
            self.assertIn("node_exec", tool_names)

            exec_resp = mcp.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "node_exec",
                        "arguments": {
                            "node": "@bastion",
                            "script": "Write-Output 'Token is HiddenToken999'",
                        },
                    },
                }
            )
            text_out = exec_resp["result"]["content"][0]["text"]  # type: ignore[index]
            self.assertNotIn("HiddenToken999", text_out)
            self.assertIn("[REDACTED]", text_out)

            # Verify destructive command guardrail over MCP
            drop_resp = mcp.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "node_exec",
                        "arguments": {
                            "node": "app01",
                            "script": "rm -rf /",
                        },
                    },
                }
            )
            self.assertTrue(drop_resp["result"]["isError"])  # type: ignore[index]

            report_md = recorder.export_markdown_report()
            self.assertIn("Enclave Gateway Session Report", report_md)


if __name__ == "__main__":
    unittest.main()
