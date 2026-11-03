"""Unit and integration test suite for enclave-gateway."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shutil
import socket
import struct
import threading
import time
import unittest
import xml.etree.ElementTree as ET
import zlib
import os
import subprocess
import tarfile
import contextlib
from unittest.mock import patch, Mock
from concurrent.futures import ThreadPoolExecutor
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

    def __init__(self, *, direct_spool_ipc: bool = False) -> None:
        self.supports_direct_spool_ipc = direct_spool_ipc
        self.files: dict[str, bytes] = {}
        self.bastion_files: dict[str, bytes] = {}
        self.mux_sessions: dict[str, dict[str, object]] = {}
        self.last_script: str = ""
        self.powershell_calls: int = 0
        self._lock = threading.Lock()

    def exec_powershell(self, script: str, timeout_sec: float = 120.0) -> ExecResult:
        with self._lock:
            self.powershell_calls += 1
            self.last_script = script
            if 'EGW_WORKER_READINESS' in script:
                return ExecResult(0,json.dumps({'running':True,'age_sec':0}),'',1)
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
        output=self._simulate_bastion_command(inner_cmd)
        if "schema='egw.ssh-result.v1'" in inner_cmd:
            return json.dumps({'schema':'egw.ssh-result.v1','exit_code':0,
                               'stdout_b64':base64.b64encode(output.encode()).decode(),'stderr_b64':''})
        return output

    def _simulate_bastion_command(self, inner_cmd: str) -> str:
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
        decoded_sh = None
        for encoded in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", inner_cmd):
            try:
                candidate = base64.b64decode(encoded, validate=True).decode("utf-8")
            except (ValueError, UnicodeError):
                continue
            if candidate.startswith("unset HISTFILE;") or "unset HISTFILE\n" in candidate:
                decoded_sh = candidate[candidate.index('unset HISTFILE'): ]
                break
        if decoded_sh is not None:
            m_ver = re.search(r"if \[ \"\$sha\" != '([0-9a-f]{64})' \]", decoded_sh)
            if m_ver:
                return f"VERIFIED:{m_ver.group(1)}"
            if "SYNC_EXTRACT_OK" in decoded_sh:
                return "SYNC_EXTRACT_OK"
            return f"TARGET_DECODED:{decoded_sh}"

        return f"BASTION_EXEC_OK:{inner_cmd}"

    def write_bytes(self, data: bytes, guest_path: str) -> None:
        with self._lock:
            self.files[guest_path] = data
            if self.supports_direct_spool_ipc and "\\req_" in guest_path and guest_path.endswith(".json"):
                env_json = json.loads(data.decode("utf-8"))
                tx_id = env_json["tx_id"]
                inner_cmd = base64.b64decode(env_json["payload_b64"]).decode("utf-8")
                out_str = self._simulate_bastion_worker(inner_cmd)
                res_payload = {
                    "tx_id": tx_id,
                    "exit_code": 0,
                    "stdout_b64": base64.b64encode(out_str.encode("utf-8")).decode("ascii"),
                    "stderr_b64": "",
                    "duration_ms": 4,
                }
                res_guest = guest_path.replace(f"\\req_{tx_id}.json", f"\\res_{tx_id}.json")
                self.files.pop(guest_path, None)
                self.files[res_guest] = json.dumps(res_payload).encode("utf-8")

    def publish_bytes(self, data: bytes, guest_path: str) -> None:
        self.write_bytes(data, guest_path)

    def consume_file(self, guest_path: str) -> None:
        with self._lock:
            self.files.pop(guest_path, None)

    def compare_replace_file(self, stage: str, path: str, expected_sha: str) -> None:
        with self._lock:
            if hashlib.sha256(self.files[path]).hexdigest() != expected_sha:
                raise RuntimeError("Patch conflict")
            self.files[path] = self.files.pop(stage)

    def read_bytes(self, guest_path: str) -> bytes:
        with self._lock:
            return self.files[guest_path]

    def try_read_bytes(
        self, guest_path: str, *, truncate_after_read: bool = False
    ) -> bytes | None:
        if guest_path.endswith('worker_state.json'):
            return json.dumps({'status':'running','last_heartbeat_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}).encode()
        with self._lock:
            raw = self.files.get(guest_path)
            if not raw:
                return None
            if truncate_after_read:
                self.files.pop(guest_path, None)
            return raw

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
        self.assertIn("tr -d", cmd)

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
        self.assertIn("BatchMode=no", hop_ps)
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
        self.assertIn('machine_prepare.ps1',arm_xml)
        self.assertNotIn('AutoLogon',arm_xml)
        self.assertNotIn('BypassTPMCheck',arm_xml)
        self.assertNotIn('BypassSecureBootCheck',arm_xml)

        x64_xml = generate_autounattend_xml(cfg, ProvisionOptions(arch="x86_64"))
        ET.fromstring(x64_xml)
        self.assertIn("amd64\\w11", x64_xml)
        self.assertIn("-Architecture 'x86_64'", x64_xml)
        # Windows Setup rejects longer commands before it starts PowerShell.
        for document in (root_arm, ET.fromstring(x64_xml)):
            command = document.find('.//{*}RunSynchronousCommand/{*}Path')
            self.assertIsNotNone(command)
            self.assertLessEqual(len(command.text), 259)

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "seed"
            provisioner = ApplianceProvisioner(cfg)
            manifest = provisioner.prepare_bundle(
                out_dir,
                ProvisionOptions(
                    arch="arm64",
                    guest_agent_sha256='A'*64,
                    win_iso_path="/tmp/win11_arm64.iso",
                    virtio_iso_path="/tmp/virtio-win.iso",
                ),
                create_disk=False,
            )
            self.assertTrue((out_dir / "Autounattend.xml").is_file())
            self.assertTrue((out_dir / "post_install.ps1").is_file())
            self.assertEqual(json.loads((out_dir/'provision-media.json').read_text())['guest_agent_sha256'],'a'*64)
            with self.assertRaises(ValueError):ProvisionOptions(guest_agent_sha256='unapproved')
            self.assertIn("bastion_worker.ps1", manifest["copied_agents"])
            original_seed=(out_dir/'Autounattend.xml').read_bytes()
            with patch.object(provisioner.hypervisor,'is_running',return_value=(True,123)):
                with self.assertRaisesRegex(RuntimeError,'Stop the appliance'):
                    provisioner.prepare_bundle(out_dir,ProvisionOptions(admin_password='changed-fixture-password'),create_disk=True)
            self.assertEqual((out_dir/'Autounattend.xml').read_bytes(),original_seed)
            qemu_cmd_str = " ".join(manifest["qemu_install_command"])
            self.assertIn("file=fat:", qemu_cmd_str)
            self.assertNotIn("fat:rw:", qemu_cmd_str)
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
            socks_srv.wait_ready()
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
            tun_srv.wait_ready()
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

            init_resp = mcp.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
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
            self.assertEqual(drop_resp["error"]["data"]["code"], "operation_failed")
            self.assertFalse(drop_resp["error"]["data"]["indeterminate"])

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
            self.assertIn('IdentityFile "~/.ssh/id_ed25519"', ssh_cfg)

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
                pg_srv.wait_ready()
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

    def test_env_injection_directory_sync_and_ssh_launcher(self) -> None:
        with TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("ENCLAVE_REGISTRY_TOKEN=RegToken#Secret2026\n", encoding="utf-8")
            vault = SecretVault(env_file=env_file)
            cfg = EnclaveConfig.from_dict(
                {
                    "appliance": {"hypervisor": "direct"},
                    "targets": {
                        "app01": {
                            "host": "10.0.20.11",
                            "port": 2222,
                            "user": "deploy",
                            "via": "bastion",
                            "ssh_key_path": "~/.ssh/id_ed25519",
                        }
                    },
                }
            )
            control = LoopbackControlChannel()
            recorder = FlightRecorder(log_path=Path(tmp) / "audit.jsonl")
            engine = EnclaveEngine(
                config=cfg, vault=vault, recorder=recorder, control_override=control
            )

            # 1. Verify in-memory env and secret_env injection + automatic secret scrubbing
            res = engine.exec_node(
                "app01",
                "echo $DEPLOY_ENV $REG_TOKEN",
                env={"DEPLOY_ENV": "production"},
                secret_env={"REG_TOKEN": "ENCLAVE_REGISTRY_TOKEN"},
            )
            self.assertEqual(res.exit_code, 0)
            self.assertIn("export DEPLOY_ENV=", res.stdout)
            self.assertIn("export REG_TOKEN=", res.stdout)
            self.assertNotIn("RegToken#Secret2026", res.stdout)

            # 2. Verify batch directory sync (`egw sync`) with automatic exclude filtering
            src_dir = Path(tmp) / "chart"
            (src_dir / "templates").mkdir(parents=True)
            (src_dir / ".git").mkdir(parents=True)
            (src_dir / "Chart.yaml").write_text("name: enclave-app\n", encoding="utf-8")
            (src_dir / "templates" / "deployment.yaml").write_text("kind: Deployment\n", encoding="utf-8")
            (src_dir / ".git" / "config").write_text("ignored\n", encoding="utf-8")

            sync_meta = engine.sync_directory(
                "push",
                src_dir,
                "app01",
                "/opt/charts/enclave-app",
                as_root=True,
            )
            self.assertEqual(sync_meta["files_synced"], 2)
            self.assertGreater(sync_meta["archive_bytes"], 0)

            # 3. Verify one-liner interactive SSH launcher command builder (`egw ssh`)
            ssh_cmd = engine.build_ssh_command(
                "app01", extra_args=["-L", "5432:127.0.0.1:5432"]
            )
            self.assertIn("ProxyCommand=egw stdio-proxy %h %p", " ".join(ssh_cmd))
            self.assertIn("-p 2222", " ".join(ssh_cmd))
            self.assertIn("deploy@10.0.20.11", ssh_cmd)
            self.assertEqual(ssh_cmd[-3:-1], ["-L", "5432:127.0.0.1:5432"])

    def test_zero_disk_stealth_direct_spool_ipc_polyglot_and_heuristic_scrubber(self) -> None:
        with TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text(
                "ENCLAVE_BASTION_USER=operator\nENCLAVE_BASTION_PASSWORD=BastionPass#2026\n",
                encoding="utf-8",
            )
            vault = SecretVault(env_file=env_file)
            scrubber = vault.scrubber

            # 1. Verify heuristic SecretScrubber (PEM private keys, JWTs, URI passwords)
            jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRldk9wcyJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            pem_sample = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----"
            uri_sample = "postgresql://admin:MyDbSecret!99@10.0.20.11:5432/enclave"
            scrubbed_text = scrubber.scrub(f"Token={jwt_sample}\n{pem_sample}\nDSN={uri_sample}")
            self.assertIn("[REDACTED_JWT]", scrubbed_text)
            self.assertIn("[REDACTED_PRIVATE_KEY]", scrubbed_text)
            self.assertIn("postgresql://admin:[REDACTED]@10.0.20.11:5432/enclave", scrubbed_text)
            self.assertNotIn("MyDbSecret!99", scrubbed_text)

            # 2. Verify POSIX shell polyglot + zero history + UserKnownHostsFile=NUL + VFS askpass staging
            inv = build_remote_bash_invocation("id", as_root=False)
            self.assertIn("command -v bash >/dev/null 2>&1 && exec bash || exec sh", inv)
            m_b64 = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d", inv)
            self.assertIsNotNone(m_b64)
            decoded_inv = base64.b64decode(m_b64.group(1)).decode("utf-8")  # type: ignore[union-attr]
            self.assertIn("unset HISTFILE; export HISTFILE=/dev/null;", decoded_inv)

            cfg = EnclaveConfig.from_dict(
                {
                    "appliance": {"hypervisor": "direct"},
                    "bastion": {"user_env": "ENCLAVE_BASTION_USER"},
                    "targets": {
                        "app01": {
                            "host": "10.0.20.11",
                            "port": 22,
                            "user": "deploy",
                            "via": "bastion",
                        }
                    },
                }
            )
            hop_ps = build_powershell_ssh_hop_script(
                cfg.targets["app01"],
                "id",
                ssh_password="SshSecretPassword",
                stage_dir=r"\\tsclient\C\EnclaveGateway\spool",
            )
            self.assertIn("StrictHostKeyChecking=yes", hop_ps)
            self.assertNotIn("UserKnownHostsFile=NUL", hop_ps)
            self.assertIn("egw-askpass.exe", hop_ps)

            # 3. Verify Direct Spool File IPC (zero powershell.exe process creation on Appliance)
            control = LoopbackControlChannel(direct_spool_ipc=True)
            recorder = FlightRecorder(log_path=Path(tmp) / "audit.jsonl")
            engine = EnclaveEngine(
                config=cfg, vault=vault, recorder=recorder, control_override=control
            )
            res = engine.exec_node("@bastion", "Get-Date")
            self.assertEqual(res.exit_code, 0)
            self.assertEqual(
                control.powershell_calls,
                0,
                "Expected Direct Spool File IPC to exchange envelopes without spawning powershell.exe on Appliance",
            )

            # 4. Verify Zero-CLI-Password (-RdpPasswordB64) in heal(update_credentials=True)
            engine.heal(update_credentials=True)
            self.assertIn("-RdpPasswordB64", control.last_script)
            self.assertNotIn("BastionPass#2026", control.last_script)

            # 5. Verify query_database with container="" (host-direct) and env-based password (PGPASSWORD / MYSQL_PWD)
            db_res = engine.query_database(
                "app01",
                "",
                "postgres",
                "SELECT 1;",
                database="enclave_db",
                db_user="postgres",
                db_password_env="ENCLAVE_BASTION_PASSWORD",
            )
            self.assertEqual(db_res.exit_code, 0)
            self.assertIn("PGPASSWORD=", db_res.stdout)
            self.assertNotIn("BastionPass#2026", db_res.stdout)

            # 6. Verify structured mux_action over Direct Spool File IPC
            cid = engine.rdp_vfs.mux_open("10.0.20.11", 5432)
            rx, eof = engine.rdp_vfs.mux_io(cid, b"FAST_MUX")
            self.assertTrue(eof)
            self.assertEqual(rx, b"MUX_ECHO[10.0.20.11:5432]:FAST_MUX")

            # 7. Verify zero-cmd.exe, zero-disk-file sudo password piping & BSD/OpenSSL base64 cascade
            sudo_hop_ps = build_powershell_ssh_hop_script(
                cfg.targets["app01"],
                "id -u",
                as_root=True,
                sudo_password="SudoRootPassword#1",
                stage_dir=r"\\tsclient\C\EnclaveGateway\spool",
            )
            self.assertNotIn("cmd.exe", sudo_hop_ps)
            self.assertNotIn("s_", sudo_hop_ps)
            self.assertIn('RedirectStandardInput=$true', sudo_hop_ps)
            self.assertNotIn('SudoRootPassword#1', sudo_hop_ps)

            # 8. Verify N-hop cascading Multi-Hop SSH (dmz01 -> app01 -> db01) & Windows TargetNode (os: windows)
            multi_cfg = EnclaveConfig.from_dict(
                {
                    "appliance": {"hypervisor": "direct"},
                    "targets": {
                        "dmz01": {"host": "10.0.10.5", "port": 22, "user": "jump", "via": "bastion"},
                        "app01": {"host": "10.0.20.11", "port": 22, "user": "deploy", "via": "dmz01"},
                        "db01": {"host": "10.0.30.50", "port": 2222, "user": "postgres", "via": "app01"},
                        "ad01": {"host": "10.0.40.10", "port": 22, "user": "Admin", "via": "bastion", "os": "windows"},
                    },
                }
            )
            multi_engine = EnclaveEngine(
                config=multi_cfg, vault=vault, recorder=recorder, control_override=control
            )
            ssh_cfg_text = multi_engine.generate_ssh_config(prefix="enclave-")
            self.assertIn("ProxyJump enclave-app01", ssh_cfg_text)
            db_ssh_cmd = multi_engine.build_ssh_command("db01")
            self.assertIn("-W", " ".join(db_ssh_cmd))
            self.assertIn("jump@10.0.10.5", " ".join(db_ssh_cmd))
            self.assertIn("deploy@10.0.20.11", " ".join(db_ssh_cmd))

            win_hop_ps = build_powershell_ssh_hop_script(
                multi_cfg.targets["ad01"],
                "Get-Service NTDS",
            )
            self.assertIn("-EncodedCommand", win_hop_ps)

            # 9. Verify Podman/nerdctl/Docker container runtime resolver & curl/wget/python3 HTTP polyglot
            ctr_res = multi_engine.query_database(
                "app01",
                "pg-ctr",
                "postgres",
                "SELECT 1;",
            )
            self.assertIn("command -v podman", ctr_res.stdout)
            http_res = multi_engine.http_request("app01", "http://127.0.0.1:8080/healthz")
            self.assertIn("urllib.request", http_res.stdout)

            # 10. Verify FlightRecorder cryptographic SHA-256 hash chain integrity
            chain_ok, verified_count = recorder.verify_integrity()
            self.assertTrue(chain_ok)
            self.assertGreaterEqual(verified_count, 3)

            # 11. Verify Universal Proxy Polyglot (HTTP CONNECT + SOCKS4a) & CLM file assembly fallback
            from enclave_gateway.hypervisor.driver import resolve_efi_code_path
            from enclave_gateway.transports.rdp_vfs import build_parallel_striped_assemble_ps

            clm_assemble = build_parallel_striped_assemble_ps(
                vfs_spool=r"\\tsclient\C\EnclaveGateway\spool",
                bastion_dest_path=r"C:\Temp\artifact.bin",
                tx_id="txclm1",
                file_size=1024,
                block_size=512,
                changed_indices=[0, 1],
                compress=False,
                use_delta=False,
                parallel_streams=2,
                expected_sha256="0" * 64,
            )
            self.assertIn("LanguageMode -ne 'FullLanguage'", clm_assemble)
            self.assertIn("requires a policy-approved FullLanguage worker", clm_assemble)

            fake_efi = Path(tmp) / "custom_efi.fd"
            fake_efi.write_bytes(b"EFI")
            self.assertEqual(resolve_efi_code_path("arm64", str(fake_efi)), str(fake_efi))

            poly_proxy = Socks5VfsServer(
                engine.rdp_vfs,
                bind_port=0,
                target_aliases={"app01": "10.0.20.11"},
            )
            poly_thread = threading.Thread(target=poly_proxy.serve_forever, daemon=True)
            poly_thread.start()
            deadline = time.time() + 3.0
            while poly_proxy.bind_port == 0 and time.time() < deadline:
                time.sleep(0.01)
            try:
                # Test HTTP CONNECT proxy on the same port
                with socket.create_connection(("127.0.0.1", poly_proxy.bind_port), timeout=3.0) as s_http:
                    s_http.sendall(b"CONNECT app01:8443 HTTP/1.1\r\nHost: app01:8443\r\n\r\nTLS_CLIENT_HELLO")
                    resp_buf = b""
                    while b"MUX_ECHO" not in resp_buf:
                        chunk = s_http.recv(4096)
                        if not chunk:
                            break
                        resp_buf += chunk
                    self.assertIn(b"HTTP/1.1 200 Connection Established\r\n\r\n", resp_buf)
                    self.assertIn(b"MUX_ECHO[10.0.20.11:8443]:TLS_CLIENT_HELLO", resp_buf)

                # Test SOCKS4a proxy on the same port
                with socket.create_connection(("127.0.0.1", poly_proxy.bind_port), timeout=3.0) as s_s4:
                    s4a_req = b"\x04\x01" + struct.pack("!H", 5432) + b"\x00\x00\x00\x01user\x00app01\x00PG_HELLO"
                    s_s4.sendall(s4a_req)
                    s4_resp = b""
                    while b"MUX_ECHO" not in s4_resp:
                        chunk = s_s4.recv(4096)
                        if not chunk:
                            break
                        s4_resp += chunk
                    self.assertTrue(s4_resp.startswith(b"\x00\x5a"))
                    self.assertIn(b"MUX_ECHO[10.0.20.11:5432]:PG_HELLO", s4_resp)
            finally:
                poly_proxy.stop()
                poly_thread.join(timeout=2.0)

            # 12. Verify Multi-IDE MCP configs, Content-Length framing, resources/read, and HTTP OpenAPI/Ollama bridge
            from enclave_gateway.mcp_server.server import (
                McpHttpServer,
                export_openai_tools,
                export_openapi_spec,
                generate_client_configs,
            )
            import urllib.request

            client_cfgs = generate_client_configs(config_path="./enclave.yaml")
            self.assertIn("vscode", client_cfgs)
            self.assertIn("zed", client_cfgs)
            self.assertIn("continue", client_cfgs)
            self.assertIn("open-webui", client_cfgs)
            self.assertGreaterEqual(len(export_openai_tools()), 10)
            self.assertIn("/tools/node_exec", export_openapi_spec()["paths"])

            mcp_srv = McpJsonRpcServer(multi_engine)
            res_list = mcp_srv.handle_message({"jsonrpc": "2.0", "id": 50, "method": "resources/list"})
            self.assertEqual(len(res_list["result"]["resources"]), 2)
            topo_read = mcp_srv.handle_message(
                {"jsonrpc": "2.0", "id": 51, "method": "resources/read", "params": {"uri": "enclave://topology"}}
            )
            self.assertIn("db01", topo_read["result"]["contents"][0]["text"])

            lsp_req = json.dumps({"jsonrpc": "2.0", "id": 52, "method": "ping"})
            lsp_in = io.StringIO(f"Content-Length: {len(lsp_req)}\r\n\r\n{lsp_req}")
            lsp_out = io.StringIO()
            mcp_srv.serve_stdio(stdin=lsp_in, stdout=lsp_out)
            self.assertTrue(lsp_out.getvalue().startswith("Content-Length:"))

            http_mcp = McpHttpServer(mcp_srv, bind_host="127.0.0.1", bind_port=0)
            http_thread = threading.Thread(target=http_mcp.serve_forever, daemon=True)
            http_thread.start()
            deadline = time.time() + 3.0
            while http_mcp.bind_port == 0 and time.time() < deadline:
                time.sleep(0.01)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{http_mcp.bind_port}/v1/tools", timeout=3.0) as r_tools:
                    tools_payload = json.loads(r_tools.read().decode("utf-8"))
                    self.assertIn("tools", tools_payload)
            finally:
                http_mcp.stop()
                http_thread.join(timeout=2.0)

            # 13. Verify node_read_file, node_patch_file, enclave_tunnel, enclave_audit, read_only mode, & context truncation
            from enclave_gateway.mcp_server.server import truncate_for_context

            remote_cfg_path = r"C:\App\service.conf"
            control.files[remote_cfg_path] = b"line1\nport=8080\nsecret=BastionPass#2026\nline4\n"

            read_resp = mcp_srv.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 60,
                    "method": "tools/call",
                    "params": {
                        "name": "node_read_file",
                        "arguments": {"node": "@appliance", "remote_path": remote_cfg_path, "start_line": 2, "end_line": 3},
                    },
                }
            )
            read_data = json.loads(read_resp["result"]["content"][0]["text"])
            self.assertEqual(read_data["total_lines"], 4)
            self.assertIn("port=8080", read_data["content"])
            self.assertNotIn("BastionPass#2026", read_data["content"])

            patch_resp = mcp_srv.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 61,
                    "method": "tools/call",
                    "params": {
                        "name": "node_patch_file",
                        "arguments": {
                            "node": "@appliance",
                            "remote_path": remote_cfg_path,
                            "target": "port=8080",
                            "replacement": "port=9090",
                            "expected_sha256": read_data["sha256"],
                        },
                    },
                }
            )
            patch_data = json.loads(patch_resp["result"]["content"][0]["text"])
            self.assertEqual(patch_data["replacements"], 1)
            self.assertIn(b"port=9090", control.files[remote_cfg_path])

            tun_start = mcp_srv.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 62,
                    "method": "tools/call",
                    "params": {
                        "name": "enclave_tunnel",
                        "arguments": {"action": "start", "mode": "tcp", "target_host": "app01", "target_port": 5432},
                    },
                }
            )
            tun_info = json.loads(tun_start["result"]["content"][0]["text"])
            self.assertGreater(tun_info["local_port"], 0)
            self.assertEqual(tun_info["resolved_host"], "10.0.20.11")
            mcp_srv.stop_all_tunnels()

            audit_resp = mcp_srv.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 63,
                    "method": "tools/call",
                    "params": {"name": "enclave_audit", "arguments": {"limit": 5}},
                }
            )
            audit_data = json.loads(audit_resp["result"]["content"][0]["text"])
            self.assertTrue(audit_data["integrity_verified"])

            ro_mcp = McpJsonRpcServer(multi_engine, read_only=True, max_output_chars=120)
            ro_block = ro_mcp.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 64,
                    "method": "tools/call",
                    "params": {
                        "name": "node_exec",
                        "arguments": {"node": "app01", "script": "rm -rf /tmp/cache"},
                    },
                }
            )
            self.assertTrue(ro_block["result"]["isError"])
            self.assertIn("--read-only", ro_block["result"]["content"][0]["text"])

            long_str = "HEAD_MARKER_" + ("A\n" * 200) + "_TAIL_MARKER"
            truncated = truncate_for_context(long_str, max_chars=80)
            self.assertIn("HEAD_MARKER_", truncated)
            self.assertIn("_TAIL_MARKER", truncated)
            self.assertIn("TRUNCATED", truncated)

class AuditRegressionTests(unittest.TestCase):
    def make_engine(self, root, control=None):
        return EnclaveEngine(
            EnclaveConfig.from_dict({"appliance": {"hypervisor": "direct"},
                                     "targets": {"app01": {"host": "10.0.20.11", "user": "deploy"}}}),
            vault=SecretVault(env_file=Path(root) / "absent.env"),
            recorder=FlightRecorder(Path(root) / "audit.jsonl"),
            control_override=control or LoopbackControlChannel(),
        )

    @contextlib.contextmanager
    def wire_peer(self, handler):
        left, right = socket.socketpair()
        right.settimeout(2.0)
        failures = []
        class Endpoint:
            def connect(self, _path): pass
            def __enter__(self): return self
            def __exit__(self, *_args): left.close()
            def __getattr__(self, name): return getattr(left, name)
        def run():
            try:
                with right, right.makefile("rb") as stream:
                    handler(right, stream)
            except Exception as exc:
                failures.append(exc)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            # Wire tests use socketpair; CPython on Windows omits AF_UNIX.
            with patch.object(socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), create=True):
                yield Endpoint()
        finally:
            left.close()
            thread.join(3.0)
            self.assertFalse(thread.is_alive(), "Wire peer leaked a thread")
            if failures:
                raise failures[0]

    def qga_sync(self, connection, stream):
        line = stream.readline()
        self.assertEqual(line[:1], b"\xff")
        request = json.loads(line[1:])
        self.assertEqual(request["execute"], "guest-sync-delimited")
        # Dirty UTF-8 and a compact JSON response, fragmented across the marker.
        connection.sendall(b'old\xfe{"return":12')
        for fragment in (b'\xff', b'{"return":', str(request["arguments"]["id"]).encode(), b'}\n'):
            connection.sendall(fragment)

    def test_qga_delimited_sync_short_writes_flush_and_close(self):
        from enclave_gateway.control.qga_client import QgaClient
        captured = bytearray()
        commands = []
        def peer(conn, stream):
            self.qga_sync(conn, stream)
            while True:
                request = json.loads(stream.readline())
                command = request["execute"]
                commands.append(command)
                if command == "guest-file-open": result = 7
                elif command == "guest-file-write":
                    data = base64.b64decode(request["arguments"]["buf-b64"])
                    count = min(2, len(data))
                    captured.extend(data[:count])
                    result = {"count": count, "eof": False}
                else: result = {}
                conn.sendall(json.dumps({"return": result}).encode() + b"\n")
                if command == "guest-file-close": break
        with TemporaryDirectory() as tmp, self.wire_peer(peer) as endpoint:
            client = QgaClient(Path(tmp) / "qga.sock")
            with patch("enclave_gateway.control.local_socket.connect_local", return_value=endpoint):
                client.write_bytes(b"\0\xffabc", r"C:\папка с пробелом\file.bin")
        self.assertEqual(captured, b"\0\xffabc")
        self.assertEqual(commands[-2:], ["guest-file-flush", "guest-file-close"])

    def test_qga_write_no_progress_and_read_error_close_guest_handles(self):
        from enclave_gateway.control.qga_client import QgaClient
        for operation in ("write", "read"):
            with self.subTest(operation=operation):
                commands = []
                def peer(conn, stream):
                    self.qga_sync(conn, stream)
                    for _ in range(3):
                        request = json.loads(stream.readline())
                        command = request["execute"]
                        commands.append(command)
                        result = ({"return": 5} if command == "guest-file-open" else
                                  {"return": {"count": 0}} if command == "guest-file-write" else
                                  {"error": {"desc": "read failed"}} if command == "guest-file-read" else {"return": {}})
                        conn.sendall(json.dumps(result).encode() + b"\n")
                with TemporaryDirectory() as tmp, self.wire_peer(peer) as endpoint:
                    client = QgaClient(Path(tmp) / "qga.sock")
                    with patch("enclave_gateway.control.local_socket.connect_local", return_value=endpoint):
                        with self.assertRaises((OSError, RuntimeError)):
                            client.write_bytes(b"abc", "file") if operation == "write" else client.read_bytes("file")
                self.assertEqual(commands[-1], "guest-file-close")

    def test_qga_clock_uses_utc_nanoseconds(self):
        from enclave_gateway.control.qga_client import QgaClient
        expected = 1700000000123456789
        def peer(conn, stream):
            self.qga_sync(conn, stream)
            request = json.loads(stream.readline())
            self.assertEqual(request, {"execute": "guest-set-time", "arguments": {"time": expected}})
            conn.sendall(b'{"return":{}}\n')
        with TemporaryDirectory() as tmp, self.wire_peer(peer) as endpoint:
            with patch("enclave_gateway.control.local_socket.connect_local", return_value=endpoint):
                self.assertTrue(QgaClient(Path(tmp) / "qga.sock").sync_guest_clock(expected))

    def test_qga_exec_signal_and_clixml_errors_are_preserved(self):
        from enclave_gateway.control.qga_client import QgaClient
        client = QgaClient("unused")
        @contextlib.contextmanager
        def connected(*_args, **_kwargs): yield None, None
        client._connect_synced = connected
        client._request = Mock(side_effect=[{"pid": 9}, {"exited": True, "signal": 9,
            "out-data": base64.b64encode(b" padded \n").decode(),
            "err-data": base64.b64encode(b"#< CLIXML\nerror details").decode()}])
        result = client.exec_powershell("exit 1", 1)
        self.assertEqual(result.exit_code, 137)
        self.assertEqual(result.stdout, " padded \n")
        self.assertIn("error details", result.stderr)

    def test_qmp_events_do_not_acknowledge_commands(self):
        from enclave_gateway.control.qmp_client import QmpClient
        def peer(conn, stream):
            conn.sendall(b'{"QMP":{"version":{}}}\n')
            capabilities = json.loads(stream.readline())
            conn.sendall(b'{"event":"STOP"}\n')
            conn.sendall(json.dumps({"return": {}, "id": capabilities["id"]}).encode() + b"\n")
            request = json.loads(stream.readline())
            conn.sendall(b'{"event":"RESUME"}\n{"return":{},"id":"other"}\n')
            conn.sendall(json.dumps({"return": {"status": "running"}, "id": request["id"]}).encode() + b"\n")
        with self.wire_peer(peer) as endpoint:
            with patch("enclave_gateway.control.qmp_client.connect_local", return_value=endpoint):
                result = QmpClient("unused").execute("query-status")
        self.assertEqual(result["return"]["status"], "running")

    def test_qmp_powerdown_failure_is_not_success(self):
        from enclave_gateway.control.qmp_client import QmpClient
        client = QmpClient("unused")
        client.execute = Mock(return_value={"error": {"desc": "unsupported"}})
        self.assertFalse(client.system_powerdown())
        client.execute = Mock(side_effect=ConnectionError("EOF"))
        self.assertFalse(client.system_powerdown())

    def test_windows_file_lock_locks_and_unlocks_same_byte(self):
        from enclave_gateway.control.qga_client import _file_lock
        backend = Mock(LK_NBLCK=1, LK_UNLCK=2)
        with TemporaryDirectory() as tmp:
            with patch("enclave_gateway.control.qga_client.fcntl", None), patch("enclave_gateway.control.qga_client.msvcrt", backend):
                with _file_lock(Path(tmp) / "lock"):
                    self.assertEqual(backend.locking.call_args.args[1:], (1, 1))
            self.assertEqual(backend.locking.call_args.args[1:], (2, 1))

    def test_control_deadline_is_not_reset_by_trickle_input(self):
        from enclave_gateway.control.wire import SocketLineReader
        fake = Mock()
        fake.recv.return_value = b"x"
        clock = iter([0.01, 0.02, 0.2])
        with patch("enclave_gateway.control.wire.time.monotonic", side_effect=lambda: next(clock)):
            with self.assertRaises(TimeoutError): SocketLineReader(fake, 0.1).readline()
        self.assertEqual(fake.recv.call_count, 2)

    def test_flight_recorder_concurrent_instances_have_one_hash_chain(self):
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            def write(index):
                FlightRecorder(log).record(tx_id=str(index), actor="test", operation="read", node="app01",
                                          summary="parallel", exit_code=0, duration_ms=1)
            with ThreadPoolExecutor(max_workers=12) as pool:
                list(pool.map(write, range(120)))
            self.assertEqual(FlightRecorder(log).verify_integrity(), (True, 120))
            self.assertEqual(len(FlightRecorder(log).read_recent(3)), 3)
            self.assertEqual(FlightRecorder(log).read_recent(0), [])
            log.write_text("[]\n")
            self.assertEqual(FlightRecorder(log).verify_integrity(), (False, 0))

    def test_independent_processes_initialize_and_append_one_audit_chain(self):
        import sys
        with TemporaryDirectory() as tmp:
            root=Path(tmp);log=root/'audit.jsonl';gate=root/'start';children=[]
            program='''
import os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[2])
from enclave_gateway.audit.flight_recorder import FlightRecorder
root=Path(sys.argv[1]);deadline=time.monotonic()+15
while not (root/'start').exists():
 if time.monotonic()>deadline:raise TimeoutError('Fixture start deadline')
 time.sleep(.005)
for index in range(20):
 FlightRecorder(root/'audit.jsonl').record(tx_id='p'+str(os.getpid())+'_'+str(index),actor='fixture',operation='read',node='app01',summary='concurrent fixture',exit_code=0,duration_ms=1)
'''
            try:
                for _ in range(2):children.append(subprocess.Popen([sys.executable,'-c',program,str(root),str(Path(__file__).resolve().parents[1]/'src')],stdout=subprocess.PIPE,stderr=subprocess.PIPE))
                gate.touch()
                for child in children:
                    output,error=child.communicate(timeout=60)
                    self.assertEqual(child.returncode,0,error.decode(errors='replace'))
                self.assertEqual(FlightRecorder(log).verify_integrity(),(True,40))
            finally:
                for child in children:
                    if child.poll() is None:child.kill();child.communicate(timeout=5)

    def test_secret_scrubber_nested_short_tokens_and_partial_private_key(self):
        from enclave_gateway.security.secrets import SecretScrubber
        scrubber = SecretScrubber(["abc", "Quote\\Secret\"2026"])
        result = scrubber.scrub({"items": ["abc", {"value": "Quote\\Secret\"2026"}], "number": 4})
        self.assertEqual(result["items"], ["[REDACTED]", {"value": "[REDACTED]"}])
        self.assertEqual(result["number"], 4)
        scrubber.register("LongBoundaryPassword2026")
        self.assertNotIn("LongBoundaryPass", scrubber.scrub("output: LongBoundaryPass"))
        self.assertNotIn("sensitive", scrubber.scrub("-----BEGIN PRIVATE KEY-----\nsensitive"))

    def test_scrub_before_mcp_json_encoding_and_context_truncation(self):
        with TemporaryDirectory() as tmp:
            engine = self.make_engine(tmp)
            secret = 'abc"\\xyz'
            engine.vault.scrubber.register(secret)
            server = McpJsonRpcServer(engine, max_output_chars=64)
            response = server._exec_to_tool_result(1, ExecResult(0, "H" * 35 + secret + "T" * 100, secret, 0))
            self.assertNotIn(secret, json.dumps(response))
            self.assertNotIn("abc", response["result"]["content"][0]["text"])

    def test_mcp_jsonrpc_errors_batch_notifications_and_version_negotiation(self):
        with TemporaryDirectory() as tmp:
            server = McpJsonRpcServer(self.make_engine(tmp))
            for bad in (None, 1, "text", {}, {"jsonrpc": "1.0", "id": 1, "method": "ping"}):
                self.assertEqual(server.handle_message(bad)["error"]["code"], -32600)
            self.assertEqual(server.handle_message([])["error"]["code"], -32600)
            request = {"jsonrpc": "2.0", "id": 0, "method": "ping"}
            self.assertEqual(server.handle_message([request, {"jsonrpc": "2.0", "method": "notifications/initialized"}]),
                             [{"jsonrpc": "2.0", "id": 0, "result": {}}])
            request["id"] = None
            self.assertEqual(server.handle_message(request)["id"], None)
            for version in ("2024-11-05", "2025-03-26"):
                result = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
                self.assertEqual(result["result"]["protocolVersion"], version)

    def test_mcp_validates_schema_before_engine_dispatch(self):
        with TemporaryDirectory() as tmp:
            engine = self.make_engine(tmp)
            engine.exec_node = Mock()
            server = McpJsonRpcServer(engine)
            cases = [{"node": "app01"}, {"node": "app01", "script": "id", "as_root": "false"},
                     {"node": "app01", "script": "id", "timeout_sec": -1},
                     {"node": "app01", "script": "id", "env": {"A": []}},
                     {"node": "app01", "script": "id", "unknown": True}]
            for arguments in cases:
                result = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "node_exec", "arguments": arguments}})
                self.assertEqual(result["error"]["code"], -32602)
            engine.exec_node.assert_not_called()

    def test_read_only_rejects_shell_sql_http_tunnel_and_host_writes(self):
        with TemporaryDirectory() as tmp:
            server = McpJsonRpcServer(self.make_engine(tmp), read_only=True)
            cases = [("node_exec", {"script": "python3 -c 'print(1)'"}),
                     ("node_exec", {"script": "r'm' -f /tmp/cache"}),
                     ("node_db_query", {"query": "WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x"}),
                     ("node_http_request", {"method": "GET"}),
                     ("node_transfer", {"direction": "pull"}), ("node_sync", {"direction": "pull"}),
                     ("enclave_tunnel", {"action": "start"}), ("enclave_tunnel", {"action": "stop"}),
                     ("enclave_doctor", {"fix": True})]
            for name, arguments in cases:
                with self.subTest(tool=name): self.assertIsNotNone(server._check_read_only_violation(name, arguments))
            self.assertIsNone(server._check_read_only_violation("enclave_status", {}))
            self.assertIsNone(server._check_read_only_violation("enclave_tunnel", {"action": "list"}))

    def test_stdio_utf8_content_length_and_parse_errors(self):
        with TemporaryDirectory() as tmp:
            server = McpJsonRpcServer(self.make_engine(tmp))
            request = json.dumps({"jsonrpc": "2.0", "id": "проверка", "method": "ping"}, ensure_ascii=False)
            framed = f"Content-Length: {len(request.encode())}\r\n\r\n{request}"
            for source in (io.StringIO(framed), io.BytesIO(framed.encode())):
                out = io.BytesIO()
                server.serve_stdio(source, out)
                headers, body = out.getvalue().split(b"\r\n\r\n", 1)
                self.assertEqual(int(headers.split(b":")[1]), len(body))
                self.assertEqual(json.loads(body)["id"], "проверка")
            out = io.StringIO()
            server.serve_stdio(io.StringIO("not json\n" + request + "\n"), out)
            responses = list(map(json.loads, out.getvalue().splitlines()))
            self.assertEqual(responses[0]["error"]["code"], -32700)
            self.assertEqual(responses[1]["id"], "проверка")

    def test_http_origin_host_auth_limits_and_stateless_mcp(self):
        from enclave_gateway.mcp_server.server import McpHttpServer
        import http.client
        with TemporaryDirectory() as tmp:
            server = McpHttpServer(McpJsonRpcServer(self.make_engine(tmp)), bind_port=0, bearer_token="TestBearer#2026", allowed_origins=("http://app01.enclave.internal",))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            deadline = time.monotonic() + 3
            while server.bind_port == 0 and time.monotonic() < deadline: time.sleep(0.01)
            self.assertGreater(server.bind_port, 0)
            def request(method, path, body=None, headers=None):
                connection = http.client.HTTPConnection("127.0.0.1", server.bind_port, timeout=3)
                try:
                    connection.request(method, path, body, headers or {})
                    response = connection.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                finally: connection.close()
            auth = {"Authorization": "Bearer TestBearer#2026", "Content-Type": "application/json"}
            try:
                self.assertEqual(request("GET", "/healthz")[0], 401)
                preflight = request("OPTIONS", "/mcp", headers={"Origin": "http://app01.enclave.internal"})
                self.assertEqual(preflight[0], 200)
                self.assertEqual(preflight[1].get("Access-Control-Allow-Origin"), "http://app01.enclave.internal")
                self.assertEqual(request("GET", "/healthz", headers={**auth, "Origin": "http://untrusted.enclave.internal"})[0], 403)
                self.assertEqual(request("GET", "/healthz", headers={**auth, "Host": "untrusted.enclave.internal"})[0], 403)
                self.assertEqual(request("GET", "/mcp", headers=auth)[0], 405)
                self.assertEqual(request("POST", "/mcp", b"{}", {**auth, "Content-Length": "-1"})[0], 413)
                self.assertEqual(request("POST", "/mcp", b"{}", {**auth, "Content-Length": "x"})[0], 400)
                self.assertEqual(request("POST", "/mcp", b"x" * 32768, {**auth, "Content-Type": "text/plain"})[0], 415)
                payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
                status, headers, body = request("POST", "/mcp", payload, auth)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["result"], {})
                self.assertNotIn("Access-Control-Allow-Origin", headers)
                notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
                self.assertEqual(request("POST", "/mcp", notification, auth)[0], 202)
                self.assertEqual(request("POST", "/tools/node_exec", b"{}", auth)[0], 400)
                self.assertEqual(request("POST", "/tools/node_exec", json.dumps({"node": "app01", "script": "rm -rf /"}), auth)[0], 422)
            finally:
                server.stop()
                thread.join(3)
            self.assertFalse(thread.is_alive())

    def test_direct_control_rejects_path_and_symlink_escape(self):
        from enclave_gateway.control.qga_client import DirectHostControlChannel
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            control = DirectHostControlChannel(root)
            with self.assertRaises(ValueError): control.write_bytes(b"x", "../../outside")
            if os.name != "nt":
                (root / "escape").symlink_to(Path(tmp), target_is_directory=True)
                with self.assertRaises(ValueError): control.write_bytes(b"x", "escape/outside")
            control.publish_bytes(b"atomic", "C:/safe/file")
            self.assertEqual(control.read_bytes("C:/safe/file"), b"atomic")

    def test_tar_rejects_prefix_traversal_links_devices_and_existing_symlinks(self):
        from enclave_gateway.engine import safe_extract_tar
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            for name, kind, link in [("../root-outside/file", tarfile.REGTYPE, ""),
                                     ("/absolute", tarfile.REGTYPE, ""), ("C:/outside", tarfile.REGTYPE, ""),
                                     ("link", tarfile.SYMTYPE, "../outside"), ("hard", tarfile.LNKTYPE, "../outside"),
                                     ("fifo", tarfile.FIFOTYPE, "")]:
                with self.subTest(name=name):
                    buffer = io.BytesIO()
                    with tarfile.open(fileobj=buffer, mode="w") as archive:
                        item = tarfile.TarInfo(name)
                        item.type, item.linkname = kind, link
                        archive.addfile(item)
                    buffer.seek(0)
                    with tarfile.open(fileobj=buffer, mode="r") as archive:
                        with self.assertRaises(ValueError): safe_extract_tar(archive, root)
            self.assertFalse((Path(tmp) / "root-outside").exists())

    def test_vfs_zero_exact_block_unicode_and_binary_files(self):
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        with TemporaryDirectory() as tmp:
            control = LoopbackControlChannel(direct_spool_ipc=True)
            config = EnclaveConfig.from_dict({"bastion": {"block_size_bytes": 1024, "parallel_streams": 3}})
            transport = RdpVfsTransport(control, config.bastion)
            for size in (0, 1024, 2048, 2049):
                with self.subTest(size=size):
                    data = (bytes(range(256)) * 9)[:size]
                    source = Path(tmp) / "исходный файл.bin"
                    output = Path(tmp) / "полученный файл.bin"
                    source.write_bytes(data)
                    path = r"C:\папка с пробелом\файл.bin"
                    expected = hashlib.sha256(data).hexdigest()
                    self.assertEqual(transport.push_file(source, path), expected)
                    self.assertEqual(transport.pull_file(path, output), expected)
                    self.assertEqual(output.read_bytes(), data)
            with self.assertRaises(ValueError): compute_block_manifest(source, 0)
            with self.assertRaises(ValueError): compute_block_manifest(source, -1)

    def test_vfs_preserves_destination_when_download_hash_fails(self):
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        with TemporaryDirectory() as tmp:
            control = LoopbackControlChannel()
            path = r"C:\source.bin"
            control.bastion_files[path] = b"correct"
            transport = RdpVfsTransport(control, EnclaveConfig().bastion)
            control.read_file = lambda _source, target: target.write_bytes(b"corrupt")
            destination = Path(tmp) / "important.bin"
            destination.write_bytes(b"original")
            with self.assertRaises(RuntimeError): transport.pull_file(path, destination)
            self.assertEqual(destination.read_bytes(), b"original")

    def test_vfs_rejects_response_mismatch_invalid_schema_and_ambiguous_replay(self):
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        response = {"tx_id": "other", "exit_code": 0, "stdout_b64": "", "stderr_b64": ""}
        self.assertEqual(RdpVfsTransport._parse_envelope_response(json.dumps(response), 0, "expected").exit_code, 1)
        for bad in ("[]", "null", "{}"):
            self.assertEqual(RdpVfsTransport._parse_envelope_response(bad, 0).exit_code, 1)
        control = LoopbackControlChannel(direct_spool_ipc=True)
        control.publish_bytes = Mock(side_effect=OSError("ambiguous rename"))
        transport = RdpVfsTransport(control, EnclaveConfig().bastion)
        with self.assertRaises(OSError): transport.exec_bastion("Write-Output 1")
        self.assertEqual(control.powershell_calls, 0)
        with self.assertRaises(ValueError): transport.exec_bastion("x", extra_fields={"tx_id": "bad"})
        with self.assertRaises(ValueError): transport.mux_open("host'; exit 1; '", 80)

    def test_proxy_fragmented_socks5_ipv6_and_auth_rejection(self):
        from enclave_gateway.transports.socks5_mux import negotiate_proxy_destination
        class Fragmented:
            def __init__(self, data): self.data = bytearray(data); self.output = bytearray()
            def recv(self, count):
                chunk = bytes(self.data[:min(count, 1)]); del self.data[:len(chunk)]; return chunk
            def sendall(self, data): self.output.extend(data)
        request = b"\x05\x01\x00\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("!H", 443)
        peer = Fragmented(request)
        self.assertEqual(negotiate_proxy_destination(peer)[:2], ("::1", 443))
        self.assertEqual(peer.output, b"\x05\x00")
        peer = Fragmented(b"\x05\x01\x02")
        with self.assertRaises(PermissionError): negotiate_proxy_destination(peer)
        self.assertEqual(peer.output, b"\x05\xff")
        peer = Fragmented(b"\x05\x01\x00\x05\x01\x01\x01")
        with self.assertRaises(ValueError): negotiate_proxy_destination(peer)

    def test_proxy_http_connect_authority_and_origin_rewrite(self):
        from enclave_gateway.transports.socks5_mux import negotiate_proxy_destination, _read_cstring
        class Peer:
            def __init__(self, data): self.stream = io.BytesIO(data)
            def recv(self, count): return self.stream.read(min(count, 2))
            def sendall(self, data): pass
        host, port, proto, payload = negotiate_proxy_destination(Peer(b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"))
        self.assertEqual((host, port, proto), ("::1", 443, "http_connect"))
        for target in (b"app01", b"app01:", b"app01:0", b"user@app01:443", b"app01:443/path"):
            with self.assertRaises(ValueError): negotiate_proxy_destination(Peer(b"CONNECT " + target + b" HTTP/1.1\r\n\r\n"))
        request = b"GET http://app01.enclave.internal/a?q=1 HTTP/1.1\r\nHost: wrong.enclave.internal\r\nProxy-Authorization: private\r\nConnection: X-Private\r\nX-Private: private\r\n\r\n"
        _, _, _, rewritten = negotiate_proxy_destination(Peer(request))
        self.assertTrue(rewritten.startswith(b"GET /a?q=1 HTTP/1.1\r\n"))
        self.assertIn(b"Host: app01.enclave.internal", rewritten)
        self.assertNotIn(b"private", rewritten.lower())
        self.assertIn(b"Connection: close", rewritten)
        with self.assertRaises(ValueError): _read_cstring(Peer(b"a" * 300))

    def test_mux_half_close_delivers_late_remote_response(self):
        from enclave_gateway.transports.rdp_vfs import pump_mux_connection
        class Transport:
            def __init__(self): self.shutdown = False; self.calls = 0; self.closed = False
            def mux_io(self, _id, data, **_kwargs):
                self.calls += 1
                return (b"late response", True) if self.shutdown and self.calls >= 4 else (b"", False)
            def mux_shutdown_write(self, _id): self.shutdown = True
            def mux_close(self, _id): self.closed = True
        transport = Transport()
        client, peer = socket.socketpair()
        thread = threading.Thread(target=pump_mux_connection, args=(transport, peer, "mux_test"), daemon=True)
        thread.start()
        client.settimeout(3)
        try:
            client.sendall(b"request")
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(1024), b"late response")
            self.assertEqual(client.recv(1), b"")
        finally:
            client.close(); peer.close(); thread.join(3)
        self.assertTrue(transport.closed)
        self.assertFalse(thread.is_alive())

    def test_stdio_eof_does_not_drop_delayed_remote_output(self):
        class Transport:
            def __init__(self): self.shutdown = False; self.calls = 0; self.closed = False
            def mux_open(self, *_args): return "mux_test"
            def mux_io(self, *_args, **_kwargs):
                self.calls += 1
                return (b"result", True) if self.shutdown and self.calls >= 4 else (b"", False)
            def mux_shutdown_write(self, _id): self.shutdown = True
            def mux_close(self, _id): self.closed = True
        transport = Transport()
        out = io.BytesIO()
        self.assertEqual(pump_stdio_mux(transport, "app01", 22, io.BytesIO(b"request"), out), 0)
        self.assertEqual(out.getvalue(), b"result")
        self.assertTrue(transport.closed)

    def test_listener_bind_failure_is_observable_and_forward_bind_is_respected(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0)); occupied.listen()
            server = Socks5VfsServer(Mock(), bind_port=occupied.getsockname()[1])
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            with self.assertRaises(OSError): server.wait_ready()
            thread.join(2)
        from enclave_gateway.config import PortForwardSpec
        spec = PortForwardSpec("x", 0, "10.0.20.11", 80, "127.0.0.2")
        supervisor = MultiPortForwardSupervisor(Mock(), {"x": spec})
        self.assertEqual(supervisor.tunnel_servers["x"].bind_host, "127.0.0.2")

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell runtime required")
    def test_ssh_posix_payload_executes_and_sudo_quoting_is_valid(self):
        marker = "literal ' quote $HOME ; Ж"
        invocation = build_remote_bash_invocation("printf '%s' " + __import__('shlex').quote(marker))
        result = subprocess.run(["sh", "-c", invocation], capture_output=True, encoding="utf-8", timeout=3)
        self.assertEqual((result.returncode, result.stdout), (0, marker))
        with TemporaryDirectory() as tmp:
            sudo = Path(tmp) / "sudo"
            sudo.write_text('#!/bin/sh\nif [ "$1" = "-n" ]; then exit 1; fi\nread password\n[ "$password" = "test-pass" ] || exit 1\nshift 3\nexec "$@"\n')
            sudo.chmod(0o700)
            command = build_remote_bash_invocation("printf 'root-ok'", as_root=True, sudo_password="test-pass")
            result = subprocess.run(["sh", "-c", command], env={**os.environ, "PATH": tmp + os.pathsep + os.environ["PATH"]}, capture_output=True, text=True, timeout=3)
            self.assertEqual((result.returncode, result.stdout), (0, "root-ok"))

    def test_ssh_askpass_helper_contains_no_password_and_literal_paths_are_quoted(self):
        from enclave_gateway.transports.ssh_hop import _wrap_with_askpass_ps
        secret = "p&%!!'quoted2026"
        script = _wrap_with_askpass_ps("Write-Output done", secret, "test", stage_dir=r"C:\папка ' с пробелом")
        self.assertNotIn(secret, script)
        self.assertNotIn("WriteAllBytes", script)
        self.assertNotIn(".cmd", script)
        self.assertIn("EGW_ASKPASS_B64", script)
        self.assertIn("ReleaseMutex", script)
        self.assertIn("Get-AuthenticodeSignature", script)
        script = _wrap_with_askpass_ps("Write-Output done", secret, "test", helper_path=r"C:\папка ' с пробелом\helper.exe")
        self.assertIn("папка '' с пробелом", script)
        with self.assertRaises(ValueError):
            EnclaveConfig.from_dict({"targets": {"app01": {"host": "app01; exit 1"}}})

    def test_config_lists_without_yaml_missing_explicit_config_and_bad_geometry(self):
        with patch.dict("sys.modules", {"yaml": None}):
            config = EnclaveConfig.from_dict(parse_yaml_or_json("provider:\n  routes:\n    - 10.0.20.0/24\n    - 10.0.30.0/24\n  dns_servers:\n    - 10.0.1.53\n"))
        self.assertEqual(config.provider.routes, ["10.0.20.0/24", "10.0.30.0/24"])
        self.assertEqual(config.provider.dns_servers, ["10.0.1.53"])
        with TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError): EnclaveConfig.load(Path(tmp) / "absent.yaml")
        for value in (0, -1, 4*1024*1024+1, 48*1024*1024):
            with self.assertRaises(ValueError): EnclaveConfig.from_dict({"bastion": {"block_size_bytes": value}})

    def test_hypervisor_uefi_arch_options_and_stop_timeout_preserve_state(self):
        from enclave_gateway.config import ApplianceSpec
        from enclave_gateway.hypervisor.driver import ApplianceHypervisor, resolve_efi_code_path
        for arch in ("arm64", "x86_64"):
            spec = ApplianceSpec(arch=arch, hypervisor="tcg", disk_path="/tmp/a,b.qcow2")
            command = ApplianceHypervisor(spec).build_qemu_command()
            self.assertIn("if=pflash,format=raw,readonly=on,file=", " ".join(command))
            self.assertIn("a,,b.qcow2", " ".join(command))
        with TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError): resolve_efi_code_path("arm64", str(Path(tmp) / "missing.fd"))
            spec = ApplianceSpec(runtime_dir=tmp,disk_path=str(Path(tmp)/"disk.qcow2"),efi_vars_path=str(Path(tmp)/"vars.fd"))
            spec.pid_file.write_text("123")
            hypervisor = ApplianceHypervisor(spec)
            hypervisor.is_running = Mock(return_value=(True, 123))
            hypervisor.qmp.system_powerdown = Mock(return_value=True)
            with self.assertRaises(TimeoutError): hypervisor.stop(timeout_sec=0)
            self.assertTrue(spec.pid_file.exists())
            with self.assertRaises(RuntimeError): hypervisor.create_snapshot()

    def test_provision_profile_retains_topology_and_uses_independent_nvram(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            nvram = root / "base-vars.fd"; nvram.write_bytes(b"vars")
            config = EnclaveConfig.from_dict({"appliance": {"efi_vars_path": str(nvram)}, "provider": {"type": "custom", "dns_servers": ["10.0.1.53"]}, "targets": {"app01": {"host": "10.0.20.11"}}})
            provisioner = ApplianceProvisioner(config)
            result = provisioner.create_cow_profile("test", base_disk=root / "base.qcow2", output_dir=root / "profile")
            clone = EnclaveConfig.load(result["profile_config"])
            self.assertIn("app01", clone.targets)
            self.assertEqual(clone.provider.dns_servers, ["10.0.1.53"])
            self.assertNotEqual(clone.appliance.efi_vars_path, str(nvram))
            self.assertEqual(clone.appliance.resolved_efi_vars_path.read_bytes(), b"vars")
            with self.assertRaises(ValueError): provisioner.create_cow_profile("../escape")
            self.assertNotEqual(ProvisionOptions().admin_password, ProvisionOptions().admin_password)

    def test_doctor_missing_measurements_fail_closed(self):
        with TemporaryDirectory() as tmp:
            control = LoopbackControlChannel()
            original = control.exec_powershell
            control.exec_powershell = lambda script, timeout_sec=120: ExecResult(1, "", "unavailable", 0) if "DIAG_CLOCK:" in script else original(script, timeout_sec)
            result = self.make_engine(tmp, control).doctor()
            checks = {row["check"]: row for row in result["checks"]}
            self.assertFalse(checks["appliance_clock_sync"]["ok"])
            self.assertFalse(checks["rdp_udp_blackhole_guard"]["ok"])
            self.assertFalse(result["healthy"])

    def test_destructive_guard_common_obfuscation_and_reverse_flags(self):
        for command in ("DROP/**/TABLE users", "d'rop' database enclave", "rm -fr /", "rm -r -f /", "rm --force --recursive /", "Stop-Computer"):
            with self.subTest(command=command):
                with self.assertRaises(DestructiveOperationError): verify_command_safety(command)
        verify_command_safety("SELECT 1")

    def test_patch_checks_current_hash_and_preserves_destination_on_conflict(self):
        from enclave_gateway.control.qga_client import DirectHostControlChannel
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = DirectHostControlChannel(root)
            control.write_bytes(b"before", "C:/config")
            control.write_bytes(b"updated", "C:/stage")
            expected = hashlib.sha256(b"before").hexdigest()
            control.write_bytes(b"concurrent", "C:/config")
            with self.assertRaises(RuntimeError): control.compare_replace_file("C:/stage", "C:/config", expected)
            self.assertEqual(control.read_bytes("C:/config"), b"concurrent")

    def test_read_file_redacts_multiline_secret_before_slicing(self):
        with TemporaryDirectory() as tmp:
            control = LoopbackControlChannel()
            control.files["file"] = b"-----BEGIN PRIVATE KEY-----\nsensitive-body\n-----END PRIVATE KEY-----\n"
            result = self.make_engine(tmp, control).read_remote_file("@appliance", "file", start_line=2, end_line=2)
            self.assertNotIn("sensitive-body", result["content"])

    def test_windows_http_values_are_literals_and_unknown_hops_fail(self):
        with TemporaryDirectory() as tmp:
            engine = self.make_engine(tmp)
            engine.exec_node = Mock(return_value=ExecResult(0, "", "", 0))
            engine.http_request("@appliance", "http://app01.enclave.internal/a'b", headers={"X-One": "a'b", "X-Two": "ok"})
            script = engine.exec_node.call_args.args[1]
            self.assertIn("a''b", script)
            self.assertIn("; 'X-Two'", script)
            with self.assertRaises(ValueError): engine.http_request("app01", "file:///etc/passwd")
            engine.config.targets["app01"].via = "missing"
            with self.assertRaises(ValueError): engine._resolve_hop_and_jump(engine.config.targets["app01"])

    def test_qga_sync_discards_a_second_stale_marker(self):
        from enclave_gateway.control.qga_client import QgaClient
        def peer(conn, stream):
            request = json.loads(stream.readline()[1:])
            conn.sendall(b'\xffstale partial\xff' + json.dumps({"return": request["arguments"]["id"]}).encode() + b'\n')
            command = json.loads(stream.readline())
            self.assertEqual(command["execute"], "guest-set-time")
            conn.sendall(b'{"return":{}}\n')
        with TemporaryDirectory() as tmp, self.wire_peer(peer) as endpoint:
            with patch("enclave_gateway.control.local_socket.connect_local", return_value=endpoint):
                self.assertTrue(QgaClient(Path(tmp) / "socket").sync_guest_clock(1))

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell runtime required")
    def test_environment_decode_is_command_substitution_not_arithmetic(self):
        with TemporaryDirectory() as tmp:
            engine = self.make_engine(tmp)
            script = engine._inject_env_into_script("printf '%s' \"$VALUE\"", is_powershell=False, env={"VALUE": "value with ' quotes"})
            result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=3)
            self.assertEqual((result.returncode, result.stdout), (0, "value with ' quotes"))

    def test_mcp_scrubs_escaped_secrets_in_audit_records_and_rejects_nested_batch(self):
        with TemporaryDirectory() as tmp:
            engine = self.make_engine(tmp)
            secret = 'quoted"\\token'
            engine.vault.scrubber.register(secret)
            engine.recorder.record(tx_id="tx1", actor="test", operation="test", node="app01", summary=secret, exit_code=0, duration_ms=0)
            self.assertNotIn(secret, engine.recorder.read_recent()[0]["summary"])
            server = McpJsonRpcServer(engine)
            response = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "enclave_audit", "arguments": {}}})
            self.assertNotIn("quoted", response["result"]["content"][0]["text"])
            response = server.handle_message([[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]])
            self.assertEqual(response[0]["error"]["code"], -32600)
            malformed = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            self.assertEqual(malformed["error"]["code"], -32602)

    def test_empty_environment_override_does_not_load_an_old_secret(self):
        with TemporaryDirectory() as tmp:
            file = Path(tmp) / "values.env"
            file.write_text("TEST_ENCLAVE_PASSWORD=old-secret\n")
            vault = SecretVault(file)
            with patch.dict(os.environ, {"TEST_ENCLAVE_PASSWORD": ""}):
                self.assertEqual(vault.get("TEST_ENCLAVE_PASSWORD"), "")
            vault._get_from_keychain = Mock(side_effect=FileNotFoundError())
            self.assertEqual(vault.get("MISSING_ENCLAVE_VALUE", "fallback"), "fallback")

    def test_vfs_transfer_templates_bound_jobs_and_escape_apostrophes(self):
        script = build_parallel_striped_assemble_ps(vfs_spool=r"\\tsclient\C\spool", bastion_dest_path=r"C:\папка ' с пробелом\файл.bin", tx_id="tx1", file_size=1, block_size=1,
                                                   changed_indices=[0], compress=True, use_delta=False, parallel_streams=2, expected_sha256="a" * 64)
        self.assertIn("папка '' с пробелом", script)
        self.assertIn("$jobs.Count -ge $maxStreams", script)
        self.assertIn("$jobs.RemoveAt(0)", script)
        self.assertIn("Decompressed block exceeds block size", script)
        self.assertIn("Remove-Item -LiteralPath $tmp", script)

    def test_windows_target_file_delivery_uses_powershell_not_posix_commands(self):
        from enclave_gateway.transports.ssh_hop import SshHopExecutor
        from enclave_gateway.config import TargetNodeSpec
        scripts = []
        digest = hashlib.sha256(b"payload").hexdigest()
        def execute(script, timeout):
            scripts.append(script)
            # Return the verification marker without executing Windows code.
            output="VERIFIED:"+digest
            if "schema='egw.ssh-result.v1'" in script:
                output=json.dumps({'schema':'egw.ssh-result.v1','exit_code':0,'stdout_b64':base64.b64encode(output.encode()).decode(),'stderr_b64':''})
            return ExecResult(0,output,"",0)
        node = TargetNodeSpec("app01", "10.0.20.11", os="windows", user="Admin")
        executor = SshHopExecutor(execute, lambda *_args: digest, Mock())
        with TemporaryDirectory() as tmp:
            file = Path(tmp) / "локальный файл.bin"; file.write_bytes(b"payload")
            self.assertEqual(executor.push_file_to_node(node, file, r"C:\папка ' с пробелом\файл.bin"), digest)
        for script in scripts:
            self.assertNotIn("cat >", script)
            self.assertNotIn("mkdir -p", script)
        self.assertTrue(any("CopyToAsync" in script for script in scripts))
        self.assertTrue(any("-EncodedCommand" in script for script in scripts))

    def test_real_qmp_monitor_when_qemu_is_available(self):
        import shutil
        from enclave_gateway.control.qmp_client import QmpClient
        binary = shutil.which("qemu-system-aarch64") or shutil.which("qemu-system-x86_64")
        if not binary or os.name == "nt": self.skipTest("Optional local QEMU UNIX monitor smoke")
        with TemporaryDirectory(prefix="egw-qmp-", dir="/tmp") as tmp:
            path = Path(tmp) / "monitor.sock"
            process = subprocess.Popen([binary, "-machine", "none", "-display", "none", "-nodefaults", "-S", "-qmp", f"unix:{path},server=on,wait=off"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not path.exists() and process.poll() is None and time.monotonic() < deadline: time.sleep(0.02)
                if process.poll() is not None: self.fail(process.stderr.read().decode(errors="replace"))
                monitor = QmpClient(path)
                self.assertIn("status", monitor.execute("query-status")["return"])
                self.assertIn("return", monitor.execute("quit"))
                process.wait(3)
                self.assertEqual(process.returncode, 0)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(3)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(3)
                process.stderr.close()

    def test_proxy_handshake_has_a_total_deadline(self):
        from enclave_gateway.transports.socks5_mux import negotiate_proxy_destination
        class Trickle:
            def recv(self, count): return b"G"
            def sendall(self, data): pass
        with patch("enclave_gateway.transports.socks5_mux.time.monotonic", side_effect=[0, 1, 11]):
            with self.assertRaises(TimeoutError): negotiate_proxy_destination(Trickle())

    def test_windows_qemu_command_does_not_request_daemonize(self):
        from enclave_gateway.hypervisor.driver import ApplianceHypervisor
        config = EnclaveConfig()
        config.appliance.hypervisor = "tcg"
        with patch("enclave_gateway.hypervisor.driver.platform.system", return_value="Windows"):
            self.assertNotIn("-daemonize", ApplianceHypervisor(config.appliance).build_qemu_command())

    def test_audit_corrupt_tail_is_not_silently_extended(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            path.write_text("invalid\n")
            with self.assertRaises(RuntimeError):
                FlightRecorder(path).record(tx_id="tx", actor="test", operation="read", node="app01", summary="", exit_code=0, duration_ms=0)
            self.assertEqual(path.read_text(), "invalid\n")


if __name__ == "__main__":
    unittest.main()
