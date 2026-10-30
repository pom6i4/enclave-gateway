"""Unit and integration test suite for enclave-gateway."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import socket
import struct
import threading
import time
import unittest
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from tempfile import TemporaryDirectory

from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.config import EnclaveConfig, parse_yaml_or_json
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.mcp_server.server import McpJsonRpcServer
from enclave_gateway.provision.builder import (
    ApplianceProvisioner,
    ProvisionOptions,
    generate_autounattend_xml,
)
from enclave_gateway.security.secrets import (
    DestructiveOperationError,
    SecretVault,
    verify_command_safety,
)
from enclave_gateway.transports.rdp_vfs import (
    RdpVfsTunnelServer,
    build_parallel_striped_assemble_ps,
    build_parallel_striped_stage_ps,
    compute_block_manifest,
    compute_file_sha256,
)
from enclave_gateway.transports.socks5_mux import (
    SOCKS5_ATYP_DOMAIN,
    SOCKS5_AUTH_NONE,
    SOCKS5_CMD_CONNECT,
    SOCKS5_REP_SUCCEEDED,
    SOCKS5_VERSION,
    MultiPortForwardSupervisor,
    Socks5VfsServer,
    pump_stdio_mux,
)
from enclave_gateway.transports.ssh_hop import (
    build_powershell_ssh_hop_script,
    build_remote_bash_invocation,
)
from enclave_gateway.tui.dashboard import render_dashboard_text


class LoopbackControlChannel:
    """In-memory loopback simulator for Appliance + BastionWorker IPC, Striped I/O, and TCP Mux."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.bastion_files: dict[str, bytes] = {}
        self.mux_sessions: dict[str, dict[str, object]] = {}
        self.last_script: str = ""
        self._lock = threading.Lock()

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        with self._lock:
            self.last_script = script
            if "[Convert]::FromBase64String('" in script and "req_" in script:
                b64_part = script.split("[Convert]::FromBase64String('", 1)[1].split("')", 1)[0]
                env_json = json.loads(base64.b64decode(b64_part).decode("utf-8"))
                tx_id = env_json["tx_id"]
                inner_cmd = base64.b64decode(env_json["payload_b64"]).decode("utf-8")
                out_str = self._simulate_bastion_worker(inner_cmd)
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
                    "worker": json.dumps(
                        {
                            "pid": 4120,
                            "uptime_sec": 3600,
                            "parallel_streams": 4,
                            "active_mux_streams": len(self.mux_sessions),
                        }
                    ),
                }
                return ExecResult(
                    exit_code=0,
                    stdout=json.dumps(status_obj),
                    stderr="",
                    duration_ms=10,
                )

            if "DIAG_CLOCK:" in script:
                return ExecResult(
                    exit_code=0,
                    stdout=f"DIAG_CLOCK:{int(time.time())}:UDP:1",
                    stderr="",
                    duration_ms=5,
                )

            return ExecResult(
                exit_code=0,
                stdout=f"APPLIANCE_EXEC_OK:{script.strip()}",
                stderr="",
                duration_ms=5,
            )

    def _simulate_bastion_worker(self, inner_cmd: str) -> str:
        # 1. Multiplexed TCP open
        if "MUX_OPEN_OK:" in inner_cmd:
            m_id = re.search(r"MUX_OPEN_OK:(mux_[0-9a-f]+)", inner_cmd)
            m_target = re.search(r"Target\s*=\s*'([^']+)'", inner_cmd)
            conn_id = m_id.group(1) if m_id else "mux_0000"
            target = m_target.group(1) if m_target else "10.0.20.11:80"
            self.mux_sessions[conn_id] = {"target": target, "rx_queue": b""}
            return f"MUX_OPEN_OK:{conn_id}"

        # 2. Multiplexed TCP I/O
        if "MUX_DATA:" in inner_cmd and "MUX_EOF:" in inner_cmd:
            m_id = re.search(r"ContainsKey\('(mux_[0-9a-f]+)'\)", inner_cmd)
            conn_id = m_id.group(1) if m_id else ""
            if conn_id not in self.mux_sessions:
                return "MUX_EOF:"
            m_tx = re.search(r"if \('([^']*)' -ne ''\)", inner_cmd)
            tx_b64 = m_tx.group(1) if m_tx else ""
            tx_bytes = base64.b64decode(tx_b64) if tx_b64 else b""
            if not tx_bytes:
                return "MUX_DATA:"
            target = str(self.mux_sessions[conn_id]["target"])
            reply = f"MUX_ECHO[{target}]:".encode("utf-8") + tx_bytes
            rx_b64 = base64.b64encode(reply).decode("ascii")
            self.mux_sessions.pop(conn_id, None)
            return f"MUX_EOF:{rx_b64}"

        # 3. Multiplexed TCP close
        if "MUX_CLOSED" in inner_cmd:
            m_id = re.search(r"ContainsKey\('(mux_[0-9a-f]+)'\)", inner_cmd)
            if m_id:
                self.mux_sessions.pop(m_id.group(1), None)
            return "MUX_CLOSED"

        # 4. Pre-check in push_file
        if "Write-Output 'MISS'" in inner_cmd:
            m_dst = re.search(r"ExpandEnvironmentVariables\('([^']+)'\)", inner_cmd) or re.search(r"\$dst = '([^']+)'", inner_cmd)
            dst_path = m_dst.group(1) if m_dst else ""
            if dst_path in self.bastion_files:
                existing = self.bastion_files[dst_path]
                sha = hashlib.sha256(existing).hexdigest().lower()
                if f"if ($h -eq '{sha}')" in inner_cmd:
                    return "MATCH"
            return "MISS"

        # 5. Parallel striped assembly in push_file
        if "$stripeWorker =" in inner_cmd and "VERIFIED:" in inner_cmd:
            m_dst = re.search(r"ExpandEnvironmentVariables\('([^']+)'\)", inner_cmd) or re.search(r"\$dst = '([^']+)'", inner_cmd)
            m_tx = re.search(r"\$tmp = \"\$dst\.tmp_(tx_[^\"]+)\"", inner_cmd)
            m_changed = re.search(r"\$changed = @\(([0-9,]*)\)", inner_cmd)
            m_bsize = re.search(r"AddArgument\(\[int64\](\d+)\)", inner_cmd)
            m_fsize = re.search(r"\$truncFs\.SetLength\((\d+)\)", inner_cmd)
            m_comp = re.search(r"AddArgument\((\$(?:true|false))\)", inner_cmd)

            dst_path = m_dst.group(1) if m_dst else ""
            tx_id = m_tx.group(1) if m_tx else ""
            changed_str = m_changed.group(1) if m_changed else ""
            block_size = int(m_bsize.group(1)) if m_bsize else 1024
            file_size = int(m_fsize.group(1)) if m_fsize else 0
            is_compressed = (m_comp.group(1) == "$true") if m_comp else True

            buf = bytearray(self.bastion_files.get(dst_path, b"\x00" * file_size))
            if len(buf) < file_size:
                buf.extend(b"\x00" * (file_size - len(buf)))

            indices = [int(x) for x in changed_str.split(",") if x.strip()]
            for idx in indices:
                chunk_suffix = f"chunk_{tx_id}_{idx:05d}.bin"
                matching_keys = [k for k in self.files if k.endswith(chunk_suffix)]
                raw_bytes = self.files.pop(matching_keys[0])
                data = zlib.decompress(raw_bytes) if is_compressed else raw_bytes
                offset = idx * block_size
                buf[offset : offset + len(data)] = data

            final_bytes = bytes(buf[:file_size])
            self.bastion_files[dst_path] = final_bytes
            actual_sha = hashlib.sha256(final_bytes).hexdigest().lower()
            return f"VERIFIED:{actual_sha}"

        # 6. Parallel striped stage in pull_file
        if "$stageWorker =" in inner_cmd and "SHA256:" in inner_cmd:
            m_src = re.search(r"ExpandEnvironmentVariables\('([^']+)'\)", inner_cmd) or re.search(r"\$src = '([^']+)'", inner_cmd)
            m_bsize = re.search(r"\$blockSize = \[int64\](\d+)", inner_cmd)
            m_tx = re.search(r"pull_(tx_[0-9_a-f]+)\.bin", inner_cmd)
            src_path = m_src.group(1) if m_src else ""
            block_size = int(m_bsize.group(1)) if m_bsize else 1024
            tx_id = m_tx.group(1) if m_tx else ""

            src_bytes = self.bastion_files[src_path]
            sha = hashlib.sha256(src_bytes).hexdigest().lower()
            if len(src_bytes) <= block_size:
                self.files[f"C:\\EnclaveGateway\\spool\\pull_{tx_id}.bin"] = src_bytes
                return f"SHA256:{sha}:CHUNKS:0"
            num_chunks = (len(src_bytes) + block_size - 1) // block_size
            for idx in range(num_chunks):
                chunk = src_bytes[idx * block_size : (idx + 1) * block_size]
                self.files[f"C:\\EnclaveGateway\\spool\\pull_{tx_id}_{idx:05d}.bin"] = chunk
            return f"SHA256:{sha}:CHUNKS:{num_chunks}"

        # 7. SSH hop execution with base64-encoded bash script
        m_b64_sh = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d", inner_cmd)
        if m_b64_sh:
            decoded_sh = base64.b64decode(m_b64_sh.group(1)).decode("utf-8", errors="replace")
            m_ver = re.search(r"if \[ \"\$sha\" != '([0-9a-f]{64})' \]", decoded_sh)
            if m_ver:
                return f"VERIFIED:{m_ver.group(1)}"

        return f"BASTION_EXEC_OK:{inner_cmd}"

    def write_bytes(self, data: bytes, guest_path: str) -> None:
        with self._lock:
            self.files[guest_path] = data

    def read_bytes(self, guest_path: str) -> bytes:
        with self._lock:
            return self.files[guest_path]

    def write_file(self, local_path: Path, guest_path: str) -> None:
        with self._lock:
            self.files[guest_path] = local_path.read_bytes()

    def read_file(self, guest_path: str, local_path: Path) -> None:
        with self._lock:
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

    def test_ssh_askpass_and_doctor_diagnostics(self) -> None:
        cfg = EnclaveConfig.from_dict(
            {
                "appliance": {"hypervisor": "direct"},
                "targets": {
                    "app01": {
                        "host": "10.0.20.11",
                        "port": 2222,
                        "user": "deploy",
                        "via": "bastion",
                        "password_env": "ENCLAVE_APP01_SSH_PASSWORD",
                        "ssh_key_path": "~/.ssh/id_ed25519",
                    }
                },
            }
        )
        node_spec = cfg.targets["app01"]
        hop_ps = build_powershell_ssh_hop_script(
            node_spec,
            "id",
            as_root=True,
            ssh_password="SshPass#1",
            sudo_password="SudoPass#2",
        )
        self.assertIn("SSH_ASKPASS_REQUIRE = 'force'", hop_ps)
        self.assertIn("-o BatchMode=no", hop_ps)
        self.assertIn("-i ~/.ssh/id_ed25519", hop_ps)
        self.assertIn("-p 2222", hop_ps)

        with TemporaryDirectory() as tmp:
            control = LoopbackControlChannel()
            recorder = FlightRecorder(log_path=Path(tmp) / "audit.jsonl")
            engine = EnclaveEngine(
                config=cfg, recorder=recorder, control_override=control
            )
            diag = engine.doctor(fix=False)
            self.assertTrue(diag["healthy"])
            check_names = [c["check"] for c in diag["checks"]]
            self.assertIn("appliance_clock_sync", check_names)
            self.assertIn("rdp_udp_blackhole_guard", check_names)
            self.assertIn("bastion_rdp_vfs_ipc", check_names)

            key_res = engine.bootstrap_ssh_key("app01")
            self.assertEqual(key_res.exit_code, 0)

            clean_meta = engine.clean_session()
            self.assertTrue(clean_meta["appliance_cleaned"])
            self.assertTrue(clean_meta["bastion_cleaned"])

    def test_block_manifest_and_sha256(self) -> None:
        with TemporaryDirectory() as tmp:
            f = Path(tmp) / "payload.bin"
            f.write_bytes(b"A" * 1024 + b"B" * 1024 + b"C" * 512)
            manifest = compute_block_manifest(f, block_size=1024)
            self.assertEqual(len(manifest), 3)
            self.assertEqual(manifest[0].size, 1024)
            self.assertEqual(manifest[2].size, 512)
            self.assertEqual(len(compute_file_sha256(f)), 64)

    def test_provision_autounattend_and_bundle(self) -> None:
        cfg = EnclaveConfig()
        arm_xml = generate_autounattend_xml(cfg, ProvisionOptions(arch="arm64"))
        root_arm = ET.fromstring(arm_xml)
        self.assertIn("unattend", root_arm.tag)
        self.assertIn("ARM64\\w11", arm_xml)
        self.assertIn("qemu-ga-aarch64.msi", arm_xml)
        self.assertIn("BypassTPMCheck", arm_xml)

        x64_xml = generate_autounattend_xml(cfg, ProvisionOptions(arch="x86_64"))
        ET.fromstring(x64_xml)
        self.assertIn("amd64\\w11", x64_xml)
        self.assertIn("qemu-ga-x86_64.msi", x64_xml)

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "seed"
            provisioner = ApplianceProvisioner(cfg)
            manifest = provisioner.prepare_bundle(
                out_dir,
                ProvisionOptions(
                    arch="arm64",
                    win_iso_path="/tmp/win11_arm64.iso",
                    virtio_iso_path="/tmp/virtio-win.iso",
                ),
                create_disk=False,
            )
            self.assertTrue((out_dir / "Autounattend.xml").is_file())
            self.assertTrue((out_dir / "post_install.ps1").is_file())
            self.assertIn("bastion_worker.ps1", manifest["copied_agents"])
            qemu_cmd_str = " ".join(manifest["qemu_install_command"])
            self.assertIn("fat:rw:", qemu_cmd_str)
            self.assertIn("win11_arm64.iso", qemu_cmd_str)

    def test_parallel_striped_io_push_and_pull(self) -> None:
        assemble_ps = build_parallel_striped_assemble_ps(
            vfs_spool=r"\\tsclient\C\EnclaveGateway\spool",
            bastion_dest_path=r"C:\deploy\payload.bin",
            tx_id="tx_test_1",
            file_size=4096,
            block_size=1024,
            changed_indices=[0, 1, 2, 3],
            compress=True,
            use_delta=True,
            parallel_streams=4,
            expected_sha256="a" * 64,
        )
        self.assertIn("CreateRunspacePool(1, $maxStreams)", assemble_ps)
        self.assertIn("[IO.FileShare]::ReadWrite", assemble_ps)

        stage_ps = build_parallel_striped_stage_ps(
            bastion_src_path=r"C:\deploy\payload.bin",
            vfs_spool=r"\\tsclient\C\EnclaveGateway\spool",
            tx_id="tx_test_2",
            block_size=1024,
            parallel_streams=4,
        )
        self.assertIn("CreateRunspacePool(1, $maxStreams)", stage_ps)

        with TemporaryDirectory() as tmp:
            cfg = EnclaveConfig.from_dict(
                {
                    "bastion": {
                        "parallel_streams": 4,
                        "block_size_bytes": 1024,
                        "compress": True,
                    }
                }
            )
            control = LoopbackControlChannel()
            engine = EnclaveEngine(
                config=cfg,
                recorder=FlightRecorder(log_path=Path(tmp) / "audit.jsonl"),
                control_override=control,
            )

            src_file = Path(tmp) / "striped_src.bin"
            payload_data = (b"STRIPE_0_" * 120) + (b"STRIPE_1_" * 120) + (b"STRIPE_2_" * 80)
            src_file.write_bytes(payload_data)

            push_meta = engine.transfer_file(
                "push", src_file, "@bastion", r"C:\staging\striped.bin"
            )
            expected_sha = compute_file_sha256(src_file)
            self.assertEqual(push_meta["sha256"], expected_sha)
            self.assertEqual(
                control.bastion_files[r"C:\staging\striped.bin"], payload_data
            )

            pulled_file = Path(tmp) / "striped_pulled.bin"
            pull_meta = engine.transfer_file(
                "pull", pulled_file, "@bastion", r"C:\staging\striped.bin"
            )
            self.assertEqual(pull_meta["sha256"], expected_sha)
            self.assertEqual(pulled_file.read_bytes(), payload_data)

    def test_tui_dashboard_rendering(self) -> None:
        with TemporaryDirectory() as tmp:
            cfg = EnclaveConfig.from_dict(
                {
                    "profile": "enclave-prod",
                    "targets": {
                        "app01": {"host": "10.0.20.11", "user": "deploy", "via": "bastion"},
                        "auth01": {"host": "10.0.20.12", "user": "root", "via": "bastion"},
                    },
                }
            )
            recorder = FlightRecorder(log_path=Path(tmp) / "audit.jsonl")
            control = LoopbackControlChannel()
            engine = EnclaveEngine(
                config=cfg, recorder=recorder, control_override=control
            )
            engine.exec_node("@bastion", "Get-Date")

            snapshot = render_dashboard_text(engine)
            self.assertIn("ENCLAVE GATEWAY TUI MONITOR (egw top)", snapshot)
            self.assertIn("1. CRYPTOGRAPHIC APPLIANCE (@appliance)", snapshot)
            self.assertIn("2. VPN CRYPTO PROVIDER", snapshot)
            self.assertIn("3. BASTION RDP VFS RELAY (@bastion)", snapshot)
            self.assertIn("4. UPSTREAM TARGET NODES", snapshot)
            self.assertIn("5. FLIGHT RECORDER (RECENT OPERATIONS)", snapshot)
            self.assertIn("app01", snapshot)
            self.assertIn("auth01", snapshot)
            self.assertIn("Parallel Streams: 4", snapshot)

    def test_socks5_and_tcp_multiplexer_over_vfs(self) -> None:
        cfg = EnclaveConfig.from_dict(
            {
                "targets": {
                    "app01": {"host": "10.0.20.11", "port": 22, "via": "bastion"}
                }
            }
        )
        control = LoopbackControlChannel()
        engine = EnclaveEngine(config=cfg, control_override=control)

        socks_srv = Socks5VfsServer(
            engine.rdp_vfs,
            bind_host="127.0.0.1",
            bind_port=0,
            target_aliases={"app01": "10.0.20.11"},
        )
        t = threading.Thread(target=socks_srv.serve_forever, daemon=True)
        t.start()
        try:
            while socks_srv.bind_port == 0:
                pass
            with socket.create_connection(("127.0.0.1", socks_srv.bind_port), timeout=5.0) as cli:
                # 1. SOCKS5 Greeting
                cli.sendall(bytes([SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE]))
                greeting_resp = cli.recv(2)
                self.assertEqual(greeting_resp, bytes([SOCKS5_VERSION, SOCKS5_AUTH_NONE]))

                # 2. SOCKS5 CONNECT to target alias 'app01:8080'
                domain_bytes = b"app01"
                req = (
                    bytes([SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_DOMAIN, len(domain_bytes)])
                    + domain_bytes
                    + struct.pack("!H", 8080)
                )
                cli.sendall(req)
                conn_reply = cli.recv(10)
                self.assertEqual(conn_reply[0], SOCKS5_VERSION)
                self.assertEqual(conn_reply[1], SOCKS5_REP_SUCCEEDED)

                # 3. Send payload over the multiplexed stream and verify echoed response from Bastion
                cli.sendall(b"PING_ENCLAVE_MUX")
                data = cli.recv(4096)
                self.assertEqual(data, b"MUX_ECHO[10.0.20.11:8080]:PING_ENCLAVE_MUX")
        finally:
            socks_srv.stop()
            t.join(timeout=2.0)

        # Also verify RdpVfsTunnelServer in stateful multiplexed mode
        tun_srv = RdpVfsTunnelServer(
            engine.rdp_vfs, 0, "10.0.20.12", 443, multiplexed=True
        )
        t_tun = threading.Thread(target=tun_srv.serve_forever, daemon=True)
        t_tun.start()
        try:
            while tun_srv.local_port == 0:
                pass
            with socket.create_connection(("127.0.0.1", tun_srv.local_port), timeout=5.0) as cli:
                cli.sendall(b"HELLO_TUNNEL")
                resp = cli.recv(4096)
                self.assertEqual(resp, b"MUX_ECHO[10.0.20.12:443]:HELLO_TUNNEL")
        finally:
            tun_srv.stop()
            t_tun.join(timeout=2.0)

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

    def test_stdio_proxy_ssh_config_forwards_watchdog_and_zero_disk_transit(self) -> None:
        with TemporaryDirectory() as tmp:
            cfg = EnclaveConfig.from_dict(
                {
                    "profile": "dev-enclave",
                    "appliance": {"hypervisor": "direct"},
                    "targets": {
                        "app01": {
                            "host": "10.0.20.11",
                            "port": 22,
                            "user": "deploy",
                            "via": "bastion",
                            "ssh_key_path": "~/.ssh/id_ed25519",
                        }
                    },
                    "forwards": {
                        "pg_app": "0:app01:5432",
                        "kc_https": {
                            "local_port": 0,
                            "target_host": "10.0.20.12",
                            "target_port": 8443,
                        },
                    },
                }
            )
            self.assertEqual(cfg.forwards["pg_app"].target_host, "10.0.20.11")
            self.assertEqual(cfg.forwards["pg_app"].target_port, 5432)
            self.assertEqual(cfg.forwards["kc_https"].target_port, 8443)

            control = LoopbackControlChannel()
            recorder = FlightRecorder(log_path=Path(tmp) / "audit.jsonl")
            engine = EnclaveEngine(
                config=cfg, recorder=recorder, control_override=control
            )

            # 1. Verify OpenSSH ProxyCommand config generator
            ssh_cfg = engine.generate_ssh_config(prefix="enclave-")
            self.assertIn("Host enclave-app01", ssh_cfg)
            self.assertIn("ProxyCommand egw stdio-proxy %h %p", ssh_cfg)
            self.assertIn("IdentityFile ~/.ssh/id_ed25519", ssh_cfg)

            # 2. Verify pump_stdio_mux over RdpVfsTransport
            in_buf = io.BytesIO(b"SSH-2.0-OpenSSH_Client\r\n")
            out_buf = io.BytesIO()
            rc = pump_stdio_mux(engine.rdp_vfs, "10.0.20.11", 22, in_buf, out_buf)
            self.assertEqual(rc, 0)
            self.assertEqual(
                out_buf.getvalue(),
                b"MUX_ECHO[10.0.20.11:22]:SSH-2.0-OpenSSH_Client\r\n",
            )

            # 3. Verify Zero-Disk VFS Transit (\\tsclient\C\EnclaveGateway\spool) + SSH stream fallback
            local_payload = Path(tmp) / "release.tar.gz"
            local_payload.write_bytes(b"ZERO_DISK_TRANSIT_PAYLOAD")
            push_meta = engine.transfer_file(
                "push",
                local_payload,
                "app01",
                "/opt/app/release.tar.gz",
                as_root=True,
            )
            self.assertEqual(push_meta["sha256"], compute_file_sha256(local_payload))
            self.assertEqual(len(control.bastion_files), 0)
            self.assertTrue(
                any("egw_stage_" in k for k in control.files),
                "Expected payload to stage directly in Appliance spool without writing to Bastion local disk",
            )

            # 4. Verify MultiPortForwardSupervisor
            sup = MultiPortForwardSupervisor(
                engine.rdp_vfs,
                cfg.forwards,
                socks5_port=0,
                target_aliases={"app01": "10.0.20.11"},
            )
            sup.start()
            try:
                pg_srv = sup.tunnel_servers["pg_app"]
                while pg_srv.local_port == 0:
                    time.sleep(0.01)
                with socket.create_connection(("127.0.0.1", pg_srv.local_port), timeout=5.0) as cli:
                    cli.sendall(b"PG_PING")
                    data = cli.recv(4096)
                    self.assertEqual(data, b"MUX_ECHO[10.0.20.11:5432]:PG_PING")
            finally:
                sup.stop()

            # 5. Verify autonomous self-healing watchdog (bounded run)
            watch_hist = engine.watch(interval_sec=0.05, max_iterations=1)
            self.assertEqual(len(watch_hist), 1)
            self.assertTrue(watch_hist[0]["healthy"])

            # 6. Verify Copy-on-Write (CoW) profile creation
            provisioner = ApplianceProvisioner(cfg)
            prof_manifest = provisioner.create_cow_profile(
                "enclave-b",
                base_disk=Path(tmp) / "base.qcow2",
                output_dir=Path(tmp) / "profiles" / "enclave-b",
                create_disk=False,
            )
            self.assertEqual(prof_manifest["profile"], "enclave-b")
            self.assertTrue(Path(prof_manifest["profile_config"]).is_file())


if __name__ == "__main__":
    unittest.main()
