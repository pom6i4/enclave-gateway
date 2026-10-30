"""Command-line interface (egw / enclave-gateway)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from enclave_gateway import __version__
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.mcp_server.server import McpJsonRpcServer
from enclave_gateway.provision.builder import ApplianceProvisioner, ProvisionOptions
from enclave_gateway.transports.rdp_vfs import RdpVfsTunnelServer
from enclave_gateway.transports.socks5_mux import Socks5VfsServer
from enclave_gateway.tui.dashboard import run_interactive_top


def _parse_copy_spec(spec: str) -> tuple[str | None, str]:
    if ":" in spec and not (len(spec) >= 2 and spec[1] == ":" and spec[2:3] in ("\\", "/")):
        node, _, path = spec.partition(":")
        if node and path:
            return node, path
    return None, spec


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="egw",
        description="Enclave Gateway: Cryptographic Appliance, RDP VFS Relay, Multi-Hop SSH Router & MCP Server.",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help="Path to enclave.yaml topology configuration file.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"enclave-gateway {__version__}"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser(
        "init",
        help="Generate Autounattend.xml, provisioning scripts, and optional qcow2 disk for the Appliance VM.",
    )
    p_init.add_argument(
        "--output-dir",
        default="./build/provision",
        help="Directory where Autounattend.xml and seed scripts will be written.",
    )
    p_init.add_argument(
        "--arch",
        choices=["auto", "arm64", "x86_64"],
        default="auto",
        help="Target guest architecture.",
    )
    p_init.add_argument(
        "--disk-size-gb",
        type=int,
        default=64,
        help="Size of the qcow2 disk in GiB when --create-disk is used.",
    )
    p_init.add_argument(
        "--win-iso",
        default="",
        help="Optional path to Windows 11 installation ISO.",
    )
    p_init.add_argument(
        "--virtio-iso",
        default="",
        help="Optional path to virtio-win drivers ISO.",
    )
    p_init.add_argument(
        "--create-disk",
        action="store_true",
        help="Create disk.qcow2 (and efi_vars.fd on ARM64) if not already present.",
    )
    p_init.add_argument(
        "--force-disk",
        action="store_true",
        help="Overwrite existing disk.qcow2 when used with --create-disk.",
    )
    p_init.add_argument(
        "--launch-installer",
        action="store_true",
        help="Immediately launch QEMU with the unattended seed and ISO drives attached.",
    )

    sub.add_parser("up", help="Start the Appliance VM and verify tunnel readiness.")
    sub.add_parser("down", help="Gracefully stop the Appliance VM via ACPI powerdown.")
    sub.add_parser("status", help="Display health telemetry across Appliance, VPN, Bastion, and Targets.")

    p_top = sub.add_parser(
        "top",
        help="Interactive TUI dashboard monitoring Host -> Appliance -> Bastion -> TargetNodes.",
    )
    p_top.add_argument(
        "--once",
        action="store_true",
        help="Render a single TUI snapshot to stdout and exit.",
    )
    p_top.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Refresh interval in seconds (default: 2.0).",
    )

    p_heal = sub.add_parser(
        "heal",
        help="Enforce MTU=1350, disable RDP-over-UDP, and reconnect Bastion RDP session.",
    )
    p_heal.add_argument(
        "--update-credentials",
        action="store_true",
        help="Re-inject Bastion domain credentials into the interactive session.",
    )

    p_reset = sub.add_parser(
        "reset", help="Restore the Appliance disk to its golden qcow2 snapshot."
    )
    p_reset.add_argument("--snapshot", default=None, help="Snapshot name to restore.")

    p_snap = sub.add_parser(
        "snapshot", help="Create a golden qcow2 snapshot of the current Appliance state."
    )
    p_snap.add_argument("--name", default=None, help="Snapshot name to save.")

    p_exec = sub.add_parser(
        "exec",
        help="Execute a command/script on @appliance, @bastion, or a TargetNode.",
    )
    p_exec.add_argument("node", help="Target node (@appliance, @bastion, or target name).")
    p_exec.add_argument("script", help="Command or script to execute.")
    p_exec.add_argument(
        "--sudo", action="store_true", help="Execute with sudo on Linux TargetNode."
    )
    p_exec.add_argument(
        "--confirm-destructive",
        action="store_true",
        help="Confirm execution of destructive commands.",
    )
    p_exec.add_argument("--timeout", type=float, default=120.0)

    p_cp = sub.add_parser(
        "cp",
        help="Verified file transfer with block delta sync (<local> <node>:<remote> or <node>:<remote> <local>).",
    )
    p_cp.add_argument("source", help="Source path or <node>:<remote_path>.")
    p_cp.add_argument("destination", help="Destination path or <node>:<remote_path>.")
    p_cp.add_argument(
        "--no-delta",
        action="store_true",
        help="Disable 4 MB block-level SHA-256 delta synchronization.",
    )

    p_tun = sub.add_parser(
        "tunnel",
        help="Tunnel a local TCP port to an internal host:port over RdpVfsTransport (e.g. 8443:10.0.20.12:443).",
    )
    p_tun.add_argument(
        "spec",
        help="Tunnel specification in format <local_port>:<target_host_or_node>:<target_port>.",
    )
    p_tun.add_argument(
        "--single-exchange",
        action="store_true",
        help="Use stateless single request/response exchange instead of stateful TCP multiplexing.",
    )

    p_socks = sub.add_parser(
        "socks5",
        help="Start a bidirectional RFC 1928 SOCKS5 multiplexer over RdpVfsTransport.",
    )
    p_socks.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Local address to bind the SOCKS5 server (default: 127.0.0.1).",
    )
    p_socks.add_argument(
        "--port",
        type=int,
        default=None,
        help="Local TCP port for SOCKS5 proxy (defaults to appliance.socks5_port).",
    )

    p_sec = sub.add_parser(
        "secret", help="Store or inspect credentials in the native OS Keychain."
    )
    p_sec.add_argument("action", choices=["set", "get"])
    p_sec.add_argument("key", help="Environment variable / secret identifier.")
    p_sec.add_argument("value", nargs="?", default="", help="Secret value (for 'set').")

    p_rep = sub.add_parser(
        "report", help="Export Markdown session audit report from the Flight Recorder."
    )
    p_rep.add_argument("--limit", type=int, default=50)

    p_ui = sub.add_parser("ui", help="Open VNC console to Appliance or native RDP client.")
    p_ui.add_argument("--view", choices=["vnc", "rdp"], default="vnc")

    sub.add_parser(
        "mcp", help="Run the Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio."
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = EnclaveConfig.load(args.config)
    engine = EnclaveEngine(config=cfg)

    if args.command == "mcp":
        server = McpJsonRpcServer(engine)
        server.serve_stdio()
        return 0

    if args.command == "init":
        admin_pw = (
            engine.vault.get("ENCLAVE_APPLIANCE_PASSWORD") or "Enclave#Appliance2026"
        )
        opts = ProvisionOptions(
            arch=args.arch,
            admin_password=admin_pw,
            computer_name=cfg.appliance.name[:15],
            disk_size_gb=args.disk_size_gb,
            win_iso_path=args.win_iso,
            virtio_iso_path=args.virtio_iso,
        )
        provisioner = ApplianceProvisioner(cfg)
        manifest = provisioner.prepare_bundle(
            Path(args.output_dir),
            opts,
            create_disk=args.create_disk,
            force_disk=args.force_disk,
        )
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        if args.launch_installer:
            subprocess.run(manifest["qemu_install_command"], check=True)
        return 0

    if args.command == "up":
        pid = engine.hypervisor.start()
        print(f"Appliance '{cfg.appliance.name}' is running (PID {pid}).")
        return 0

    if args.command == "down":
        engine.hypervisor.stop()
        print(f"Appliance '{cfg.appliance.name}' stopped.")
        return 0

    if args.command == "status":
        st = engine.status()
        print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0

    if args.command == "top":
        return run_interactive_top(
            engine, interval_sec=args.interval, once=args.once
        )

    if args.command == "heal":
        res = engine.heal(update_credentials=args.update_credentials, actor="cli")
        if res.stdout:
            print(res.stdout)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        return res.exit_code

    if args.command == "reset":
        engine.hypervisor.restore_snapshot(args.snapshot)
        print("Appliance disk restored to golden snapshot.")
        return 0

    if args.command == "snapshot":
        engine.hypervisor.create_snapshot(args.name)
        print("Appliance snapshot created.")
        return 0

    if args.command == "exec":
        res = engine.exec_node(
            args.node,
            args.script,
            as_root=args.sudo,
            confirm_destructive=args.confirm_destructive,
            timeout_sec=args.timeout,
            actor="cli",
        )
        if res.stdout:
            print(res.stdout)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        return res.exit_code

    if args.command == "cp":
        src_node, src_path = _parse_copy_spec(args.source)
        dst_node, dst_path = _parse_copy_spec(args.destination)
        if src_node is None and dst_node is not None:
            meta = engine.transfer_file(
                "push",
                src_path,
                dst_node,
                dst_path,
                use_delta=not args.no_delta,
                actor="cli",
            )
        elif src_node is not None and dst_node is None:
            meta = engine.transfer_file(
                "pull",
                dst_path,
                src_node,
                src_path,
                use_delta=not args.no_delta,
                actor="cli",
            )
        else:
            print(
                "Error: specify exactly one remote endpoint (<local> <node>:<remote> or <node>:<remote> <local>).",
                file=sys.stderr,
            )
            return 1
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        return 0

    if args.command == "tunnel":
        parts = args.spec.split(":")
        if len(parts) != 3:
            print(
                "Error: tunnel spec must be <local_port>:<target_host_or_node>:<target_port>",
                file=sys.stderr,
            )
            return 1
        local_port = int(parts[0])
        target_host = (
            cfg.targets[parts[1]].host if parts[1] in cfg.targets else parts[1]
        )
        target_port = int(parts[2])
        mode_str = "single-exchange" if args.single_exchange else "multiplexed"
        print(
            f"Listening on 127.0.0.1:{local_port} -> relaying ({mode_str}) via RdpVfsTransport to {target_host}:{target_port}..."
        )
        server = RdpVfsTunnelServer(
            engine.rdp_vfs,
            local_port,
            target_host,
            target_port,
            multiplexed=not args.single_exchange,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.stop()
        return 0

    if args.command == "socks5":
        port = args.port if args.port is not None else cfg.appliance.socks5_port
        aliases = {name: spec.host for name, spec in cfg.targets.items()}
        print(
            f"SOCKS5 multiplexer listening on {args.bind}:{port} -> routing via RdpVfsTransport..."
        )
        socks_srv = Socks5VfsServer(
            engine.rdp_vfs,
            bind_host=args.bind,
            bind_port=port,
            target_aliases=aliases,
        )
        try:
            socks_srv.serve_forever()
        except KeyboardInterrupt:
            socks_srv.stop()
        return 0

    if args.command == "secret":
        if args.action == "set":
            ok = engine.vault.set_in_keychain(args.key, args.value)
            if not ok:
                print("Failed to store secret in OS Keychain.", file=sys.stderr)
                return 1
            print(f"Secret '{args.key}' stored in OS Keychain.")
            return 0
        val = engine.vault.get(args.key)
        print(f"{args.key}: {'[SET]' if val else '[NOT SET]'}")
        return 0

    if args.command == "report":
        print(engine.recorder.export_markdown_report(limit=args.limit))
        return 0

    if args.command == "ui":
        if args.view == "vnc":
            vnc_port = 5900 + cfg.appliance.vnc_display
            subprocess.run(["open", f"vnc://127.0.0.1:{vnc_port}"], check=False)
        else:
            print(f"Connect RDP client to 127.0.0.1:{cfg.appliance.rdp_forward_port}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
