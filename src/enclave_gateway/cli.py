"""Command-line interface (egw / enclave-gateway)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from enclave_gateway import __version__
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.security.policy import AccessPolicy
from enclave_gateway.operations.context import OperationError


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
    parser.add_argument('--state-dir',type=Path,help='Private audit/journal/environment directory for this invocation.')
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
    config=sub.add_parser('config',help='Create or validate a configuration without opening a connection.')
    config_actions=config.add_subparsers(dest='config_action',required=True)
    create=config_actions.add_parser('init',help='Write a starter configuration; never overwrite a file.')
    create.add_argument('--mode',choices=['standard','enterprise'],default='standard')
    create.add_argument('--route',choices=['ssh','rdp_vfs'],default='rdp_vfs',help='Explicit approved route; ssh disables the RDP worker and starts SSH on Appliance.')
    destination=create.add_mutually_exclusive_group()
    destination.add_argument('--output',type=Path)
    destination.add_argument('--global',dest='global_config',action='store_true',help='Create the private XDG user configuration.')
    config_actions.add_parser('check',help='Validate configuration and show effective security settings.')
    agents=sub.add_parser('agents',help='Stage an immutable worker bundle or print its Bastion startup command.')
    agents.add_argument('agents_action',choices=['stage','command','prune','stop','unregister-autostart-command'])
    agents.add_argument('--execution-policy',choices=['RemoteSigned'],default='',help='Explicit process-only Standard startup option; never weakens AllSigned or Group Policy.')
    agents.add_argument('--policy-source', type=Path, help='Stage the independently approved operator policy from this Host file.')
    agents.add_argument('--persist-autostart',action='store_true',help='Opt-in HKCU Run persistence; requires endpoint policy approval and may be blocked by EDR.')
    agents.add_argument('--unregister-autostart',action='store_true',help='Remove the current worker user HKCU startup value before acknowledged stop.')
    agents.add_argument('--migrate-legacy-state',action='store_true',help='Approve one-time journal migration after stopping the old worker.')
    agents.add_argument('--timeout',type=float,default=45,help='Stop request budget in seconds.')
    agents.add_argument('--apply',action='store_true',help='Apply explicit reviewed --remove IDs; requires stopped lease-aware workers.')
    agents.add_argument('--remove',action='append',default=[],help='Exact bundle SHA-256 to remove; repeat as needed.')
    agents.add_argument('--keep',action='append',default=[],help='Additional bundle SHA-256 to retain.')
    agents.add_argument('--min-age-hours',type=int,default=168,help='Minimum age for pruning; default seven days.')
    diagnostics=sub.add_parser('diagnostics',help='Preview or save an allow-listed offline support snapshot.')
    diagnostics.add_argument('diagnostics_action',choices=['preview','save'])
    diagnostics.add_argument('--output',type=Path)
    diagnostics.add_argument('--sha256',default='',help='Exact digest from the reviewed preview; required to save.')

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
    p_init.add_argument('--seed-iso',default='',help='Read-only seed ISO prepared from the generated bundle.')
    p_init.add_argument('--guest-agent-sha256',default='',help='Explicitly approve these QGA MSI bytes; unsigned media otherwise requires Authenticode.')
    p_init.add_argument('--completion-mode',choices=['StartupTask','SetupComplete'],default='StartupTask',help='SYSTEM preparation trigger after Windows Setup.')
    p_init.add_argument('--recover-machine-preparation',action='store_true',help='Finish a matching prepared generation through QGA without running MSI.')
    p_init.add_argument('--admin-user',default='Admin',help='New disposable/appliance local administrator name.')
    p_init.add_argument('--detach-installer',action='store_true',help='Detach a requested installer and verify its QMP identity.')
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
    sub.add_parser("down", help="Gracefully stop the Appliance VM via guest agent or ACPI.")
    sub.add_parser("status", help="Display health telemetry across Appliance, VPN, Bastion, and Targets.")

    p_doc = sub.add_parser(
        "doctor",
        help="Run end-to-end L1-L7 diagnostics (clock skew, MTU/UDP policy, VPN tunnel, Bastion VFS RTT, SSH).",
    )
    p_doc.add_argument(
        "--fix",
        action="store_true",
        help="Automatically self-heal clock skew, MTU/UDP policy, or stale Bastion RDP session.",
    )
    p_doc.add_argument(
        "--probe-targets",
        action="store_true",
        help="Also test SSH connectivity to all configured TargetNodes.",
    )
    p_doc.add_argument('--preflight',action='store_true',help='Check Host prerequisites only; no connections, journal or changes.')

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
        help="Repair Appliance settings and reconnect the managed Bastion RDP session when applicable.",
    )
    p_heal.add_argument(
        "--update-credentials",
        action="store_true",
        help="Re-inject Bastion domain credentials into the interactive session.",
    )
    p_heal.add_argument('--execution-policy', choices=['RemoteSigned'], default='',
                        help='Explicit process-only option for the printed Standard worker command.')
    p_heal.add_argument('--policy-source', type=Path,
                        help='Explicitly stage an approved local operator policy alongside the worker.')

    sub.add_parser(
        "clean",
        help="Purge transient spool chunks, staging files, and open multiplexed sockets across tiers.",
    )

    p_reset = sub.add_parser(
        "reset", help="Restore a verified offline disk, firmware variables and optional TPM bundle."
    )
    p_reset.add_argument("--snapshot", default=None, help="Snapshot name to restore.")

    p_snap = sub.add_parser(
        "snapshot", help="Create a consistent offline Appliance state bundle."
    )
    p_snap.add_argument("--name", default=None, help="State bundle name to save.")
    p_snap.add_argument("--recover",action="store_true",help="Recover an interrupted offline restore without creating a bundle.")

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
    p_exec.add_argument(
        "--env",
        action="append",
        default=[],
        help="Inject environment variable KEY=VALUE in-memory before running the script.",
    )
    p_exec.add_argument(
        "--secret-env",
        action="append",
        default=[],
        help="Inject secret from OS Keychain/.env as KEY or KEY=VAULT_KEY and scrub from output.",
    )
    p_exec.add_argument("--timeout", type=float, default=120.0)

    p_cp = sub.add_parser(
        "cp",
        help="Verified file transfer with block delta sync (<local> <node>:<remote> or <node>:<remote> <local>).",
    )
    p_cp.add_argument("source", help="Source path or <node>:<remote_path>.")
    p_cp.add_argument("destination", help="Destination path or <node>:<remote_path>.")
    p_cp.add_argument("--timeout", type=float, default=900.0, help="Total file transfer budget in seconds.")
    p_cp.add_argument("--chunked", action="store_true",
                      help="Use bounded chunks for files up to 512 MiB via the structured operator backend.")
    p_cp.add_argument(
        "--sudo",
        action="store_true",
        help="Use sudo staging on Linux TargetNode for root-owned paths.",
    )
    p_cp.add_argument(
        "--no-delta",
        action="store_true",
        help="Disable 4 MB block-level SHA-256 delta synchronization.",
    )

    p_sync = sub.add_parser(
        "sync",
        help="Batch-synchronize a directory via streaming tar.gz (<local_dir> <node>:<remote_dir> or <node>:<remote_dir> <local_dir>).",
    )
    p_sync.add_argument("source", help="Source directory or <node>:<remote_dir>.")
    p_sync.add_argument(
        "destination", help="Destination directory or <node>:<remote_dir>."
    )
    p_sync.add_argument(
        "--sudo",
        action="store_true",
        help="Extract or pack with sudo privileges on a Linux TargetNode.",
    )
    p_sync.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Additional glob pattern to exclude (can be passed multiple times).",
    )

    p_ssh = sub.add_parser(
        "ssh",
        help="Launch interactive OpenSSH on the configured Direct SSH or RDP TCP mux route.",
    )
    p_ssh.add_argument("node", help="TargetNode name from enclave.yaml.")
    p_ssh.add_argument(
        "--print-cmd",
        action="store_true",
        help="Print the constructed ssh command line instead of executing it.",
    )
    p_ssh.add_argument(
        "ssh_args",
        nargs=argparse.REMAINDER,
        help="Optional extra arguments passed to the host ssh client.",
    )

    p_key = sub.add_parser(
        "ssh-copy-id",
        help="Generate hop SSH keypair if missing and install public key onto a TargetNode.",
    )
    p_key.add_argument("node", help="TargetNode name from enclave.yaml.")

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

    p_fwd = sub.add_parser(
        "forward",
        help="Concurrently run all declarative port forwards from enclave.yaml (and optional SOCKS5 proxy).",
    )
    p_fwd.add_argument(
        "--with-socks5",
        action="store_true",
        help="Also start the SOCKS5 multiplexer in the same supervisor process.",
    )
    p_fwd.add_argument(
        "--socks5-port",
        type=int,
        default=None,
        help="Override local TCP port for SOCKS5 when --with-socks5 is used.",
    )

    p_stdio = sub.add_parser(
        "stdio-proxy",
        help="OpenSSH ProxyCommand stdio bridge over RdpVfsTransport (`egw stdio-proxy <host> <port>`).",
    )
    p_stdio.add_argument("host", help="Target host IP, FQDN, or TargetNode alias.")
    p_stdio.add_argument("port", type=int, help="Target TCP port.")

    p_sshcfg = sub.add_parser(
        "ssh-config",
        help="Generate an OpenSSH ~/.ssh/config block using `egw stdio-proxy %%h %%p`.",
    )
    p_sshcfg.add_argument(
        "--prefix",
        default="enclave-",
        help="Host alias prefix for generated SSH config entries (default: enclave-).",
    )

    p_watch = sub.add_parser(
        "watch",
        help="Autonomous self-healing watchdog that monitors health and heals drift automatically.",
    )
    p_watch.add_argument(
        "--interval",
        type=float,
        default=15.0,
        help="Seconds between health checks (default: 15.0).",
    )
    p_watch.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Optional maximum number of check cycles before exiting.",
    )
    p_watch.add_argument(
        "--probe-targets",
        action="store_true",
        help="Also probe TargetNodes over SSH during each watchdog cycle.",
    )

    p_prof = sub.add_parser(
        "profile",
        help="Create Copy-on-Write (CoW) qcow2 overlay profiles for multi-enclave isolation.",
    )
    p_prof_sub = p_prof.add_subparsers(dest="profile_action", required=True)
    p_prof_create = p_prof_sub.add_parser(
        "create",
        help="Create a new Copy-on-Write qcow2 overlay profile backed by the base Appliance image.",
    )
    p_prof_create.add_argument("name", help="Profile name (e.g. prod-enclave).")
    p_prof_create.add_argument(
        "--base-disk",
        default=None,
        help="Optional path to the read-only backing qcow2 image.",
    )
    p_prof_create.add_argument(
        "--output-dir",
        default=None,
        help="Optional directory for the overlay disk and profile YAML.",
    )
    p_prof_create.add_argument(
        "--create-disk",
        action="store_true",
        help="Invoke qemu-img to create the qcow2 CoW overlay disk immediately.",
    )

    p_sec = sub.add_parser(
        "secret", help="Store or inspect credentials in the native OS Keychain."
    )
    p_sec.add_argument("action", choices=["set", "get"])
    p_sec.add_argument("key", help="Environment variable / secret identifier.")
    p_sec.add_argument("value", nargs="?", default=None, help="Legacy argv value; omit to use a hidden prompt.")
    p_sec.add_argument('--stdin',action='store_true',help='Read a secret from stdin instead of command arguments/history.')

    p_rep = sub.add_parser(
        "report", help="Export Markdown session audit report from the Flight Recorder."
    )
    p_rep.add_argument("--limit", type=int, default=50)

    p_ui = sub.add_parser("ui", help="Open VNC console to Appliance or native RDP client.")
    p_ui.add_argument("--view", choices=["vnc", "rdp"], default="vnc")

    p_mcp = sub.add_parser(
        "mcp",
        help="Run the MCP JSON-RPC 2.0 server over stdio or HTTP (/mcp, /v1/tools, /openapi.json).",
    )
    p_mcp.add_argument("--isolation-map",type=Path,help="Trusted map of principals to separate OS-account backend profiles.")
    p_mcp.add_argument("--worker-state-dir",type=Path,help=argparse.SUPPRESS)
    p_mcp.add_argument("--worker-identity-handshake",action="store_true",help=argparse.SUPPRESS)
    p_mcp.add_argument("--policy", type=Path, help="JSON principal/tool/node/path/network policy.")
    p_mcp.add_argument("--principal", default="local", help="Trusted launcher identity for stdio or the legacy HTTP bearer token.")
    p_mcp.add_argument(
        "--listen",
        default="",
        help="Optional HTTP bind address (e.g. 127.0.0.1:8765) for Streamable HTTP MCP, Open WebUI, and Ollama.",
    )
    p_mcp.add_argument(
        "--token",
        default="",
        help="Optional Bearer token for HTTP endpoints.",
    )
    p_mcp.add_argument(
        "--token-env", default="ENCLAVE_MCP_TOKEN",
        help="Vault/environment key for the HTTP bearer token when --token is omitted.",
    )
    p_mcp.add_argument(
        "--allowed-origin", action="append", default=[],
        help="Explicit browser origin allowed to access HTTP endpoints; repeat for multiple origins.",
    )
    p_mcp.add_argument(
        "--export-openai-tools",
        action="store_true",
        help="Print OpenAI / Ollama / vLLM / llama.cpp function-calling schema JSON and exit.",
    )
    p_mcp.add_argument(
        "--export-openapi",
        action="store_true",
        help="Print OpenAPI 3.1.0 tool server specification JSON (for Open WebUI) and exit.",
    )
    p_mcp.add_argument(
        "--read-only",
        action="store_true",
        help="Expose structured reads only; block arbitrary commands, SQL/HTTP calls, transfers, sync, tunnels, and escalation.",
    )
    p_mcp.add_argument(
        "--max-output-chars",
        type=int,
        default=32000,
        help="Maximum characters per tool response before head+tail context truncation (default: 32000).",
    )

    p_mcp_cfg = sub.add_parser(
        "mcp-config",
        help="Generate MCP / Tool configurations for IDEs (VS Code, Cursor, Zed, Continue, Codex, Claude Code) and local LLMs (Ollama, LM Studio, Open WebUI).",
    )
    p_mcp_cfg.add_argument(
        "--client",
        choices=[
            "all",
            "cursor",
            "vscode",
            "zed",
            "continue",
            "codex",
            "claude-code",
            "lm-studio",
            "open-webui",
            "ollama",
        ],
        default="all",
        help="Target IDE or local LLM client (default: all).",
    )

    p_provider=sub.add_parser('provider',help='Plan/apply an approved version-pinned provider lifecycle recipe.')
    p_provider.add_argument('action',choices=['install','connect','disconnect','import_key'])
    p_provider.add_argument('--apply',action='store_true')
    p_provider.add_argument('--approval-digest',default='')
    p_provider.add_argument('--tx-id',default=None)
    p_verify = sub.add_parser('agent-verify',help='Verify fresh evidence from the running Bastion worker.')
    p_verify.add_argument('--wait-ready',type=float,default=None,metavar='SECONDS',
                          help='Wait for startup before beginning the independent attestation (up to 120 seconds).')
    sub.add_parser("capabilities", help="Report local capabilities without contacting a live enclave.")
    p_tx = sub.add_parser("transactions", help="Retrieve durable results and request cancellation without replaying work.")
    p_tx.add_argument("action", choices=["get", "list", "cancel", "reconcile", "maintain"])
    p_tx.add_argument("tx_id", nargs="?")
    p_tx.add_argument("--limit", type=int, default=25)
    for transactional_parser in (p_exec, p_cp, p_sync):
        transactional_parser.add_argument("--tx-id", default=None, help="Stable idempotency key; reuse retrieves the original operation.")

    return parser


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command=='mcp-config':
        from enclave_gateway.mcp_server.server import generate_client_configs

        configs=generate_client_configs(config_path=args.config)
        value=configs if args.client=='all' else configs[args.client]
        print(value if isinstance(value,str) else json.dumps(value,indent=2,ensure_ascii=False));return 0
    if args.command=='mcp' and (args.export_openai_tools or args.export_openapi):
        from enclave_gateway.mcp_server.server import export_openai_tools, export_openapi_spec

        print(json.dumps(export_openai_tools() if args.export_openai_tools else export_openapi_spec(),indent=2));return 0
    if args.command=='secret':
        from enclave_gateway.security.secrets import SecretVault
        from enclave_gateway.config import state_directory,configuration_path
        source=configuration_path(args.config) if args.state_dir is None and not os.environ.get('ENCLAVE_STATE_DIR') else None
        args.state_dir=state_directory(explicit=args.state_dir,source_path=source)
        if args.state_dir:
            from enclave_gateway.operations.retention import private_directory
            private_directory(args.state_dir)
        vault=SecretVault(env_file=args.state_dir/'.env' if args.state_dir else None)
        if args.action=='get':
            if args.stdin or args.value is not None:parser.error('secret get accepts no value')
            print(f"{args.key}: {'[SET]' if vault.get(args.key) else '[NOT SET]'}");return 0
        if args.stdin and args.value is not None:parser.error('Select --stdin or an argv value')
        if args.stdin:
            value=sys.stdin.read(65537)
            if len(value)>65536:raise ValueError('Secret input exceeds 64 KiB')
            if value.endswith('\n'):value=value[:-1].removesuffix('\r')
        elif args.value is None:
            if not sys.stdin.isatty():raise ValueError('Use secret set NAME --stdin for noninteractive input')
            import getpass
            value=getpass.getpass('Secret value: ')
        else:value=args.value
        if not value:raise ValueError('Secret value must not be empty')
        if not vault.set_in_keychain(args.key,value):raise OSError('Failed to store secret in the OS credential store')
        print(f"Secret '{args.key}' stored in OS credential store.");return 0

    if args.command=='config' and args.config_action=='init':
        from enclave_gateway.onboarding import starter_yaml
        from enclave_gateway.config import global_config_path
        if args.global_config or (args.output is not None and args.output.expanduser().absolute()==global_config_path().absolute()):
            from enclave_gateway.operations.retention import private_directory
            args.output=global_config_path();private_directory(args.output.parent)
        else:args.output=(args.output or Path('enclave.yaml')).expanduser()
        data=starter_yaml(args.mode,args.route).encode()
        descriptor=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(descriptor,'wb') as output:output.write(data)
        print(json.dumps({'created':str(args.output),'mode':args.mode,'route':args.route,'next_step':'Edit topology, then run egw config check. Enterprise placeholders must be replaced with approved release pins.'}))
        return 0

    if args.command=='agents' and args.agents_action=='unregister-autostart-command':
        if args.execution_policy or args.policy_source or args.persist_autostart or args.unregister_autostart or args.migrate_legacy_state or args.apply or args.remove or args.keep or args.min_age_hours!=168 or args.timeout!=45:
            parser.error('Offline autostart removal command accepts no deployment, stop or pruning options')
        from enclave_gateway.onboarding import unregister_autostart_command
        print(unregister_autostart_command());return 0

    if args.command=='agents' and args.persist_autostart:
        print('USER_AUTOSTART_POLICY: HKCU Run persistence and ACL provisioning require endpoint administrator approval; EDR compatibility is not implied.',file=sys.stderr)

    try:cfg = EnclaveConfig.load(args.config)
    except TypeError as error:raise ValueError('Invalid configuration value type; run egw config check and see docs/GUIDE.md.') from error
    if args.command=='config':
        from enclave_gateway.onboarding import configuration_summary
        print(json.dumps(configuration_summary(cfg),indent=2));return 0
    if args.command=='diagnostics':
        from enclave_gateway.diagnostics import support_preview,save_support
        if args.diagnostics_action=='preview':
            if args.output or args.sha256:parser.error('preview accepts neither --output nor --sha256')
            result=support_preview(cfg)[0]
        else:
            if not args.output or not args.sha256:parser.error('save requires --output and the reviewed --sha256')
            result=save_support(cfg,args.output,args.sha256)
        print(json.dumps(result,indent=2));return 0
    if args.command=='doctor' and args.preflight:
        if args.fix or args.probe_targets:parser.error('--preflight cannot be combined with --fix or --probe-targets')
        from enclave_gateway.diagnostics import preflight
        result=preflight(cfg);print(json.dumps(result,indent=2));return 0 if result['healthy'] else 1
    if args.command=='agents' and args.agents_action!='prune' and (args.apply or args.remove or args.keep or args.min_age_hours!=168):
        parser.error('Maintenance flags require agents prune')
    if args.command=='agents' and args.policy_source and args.agents_action!='stage':
        parser.error('--policy-source requires agents stage')
    if args.command=='agents' and args.agents_action not in ('stage','command') and (args.execution_policy or args.migrate_legacy_state or args.persist_autostart):
        parser.error('Startup options require agents stage or command')
    if args.command=='agents' and args.agents_action!='stop' and args.unregister_autostart:
        parser.error('--unregister-autostart requires agents stop')
    if args.command=='agents' and args.agents_action!='stop' and args.timeout!=45:
        parser.error('--timeout requires agents stop')
    if args.command=='agents' and args.agents_action=='command':
        from enclave_gateway.onboarding import agent_bundle
        print(agent_bundle(cfg,execution_policy=args.execution_policy,migrate_legacy_state=args.migrate_legacy_state,persist_autostart=args.persist_autostart)[3]);return 0
    if args.command=='mcp' and cfg.security.mode=='enterprise':
        if not args.policy or (not args.read_only and not args.isolation_map and not args.worker_identity_handshake):
            raise ValueError('Enterprise MCP requires --policy and, for mutable service, --isolation-map. See docs/SECURITY.md.')
    if args.command=='mcp' and args.worker_identity_handshake:
        from enclave_gateway.security.secrets import SecretVault
        from enclave_gateway.operations.retention import private_directory
        from enclave_gateway.audit.flight_recorder import FlightRecorder
        if not args.worker_state_dir: raise ValueError('Worker state directory is required')
        private_directory(args.worker_state_dir)
        engine=EnclaveEngine(config=cfg,vault=SecretVault(env_file=(cfg.source_path or Path(args.config)).parent/'.env'),recorder=FlightRecorder(args.worker_state_dir/'audit.jsonl'))
    else:
        engine=EnclaveEngine(config=cfg,state_dir=args.state_dir)

    if args.command == "mcp":
        from enclave_gateway.mcp_server.server import McpHttpServer, McpJsonRpcServer

        policy = AccessPolicy.load(args.policy) if args.policy else None
        router=None
        if args.isolation_map:
            if not policy: raise ValueError('Isolation requires an explicit principal policy')
            from enclave_gateway.security.isolation import PrincipalRouter
            router=PrincipalRouter(args.isolation_map,vault=engine.vault,policy=policy)
        if args.worker_identity_handshake:
            if os.name!='nt':
                import signal
                def terminate_worker(_signal,_frame): raise KeyboardInterrupt()
                signal.signal(signal.SIGTERM,terminate_worker)
            from enclave_gateway.security.isolation import process_identity,process_privileged
            print(json.dumps({'egw_worker_identity':process_identity(),'privileged':process_privileged(),'principal':args.principal,'config':str(Path(args.config).resolve())}),flush=True)
        server = McpJsonRpcServer(
            engine,router=router,
            policy=policy, principal=args.principal,
            read_only=bool(args.read_only),
            max_output_chars=int(args.max_output_chars),
        )
        try:
            if args.listen:
                host_part, _, port_part = args.listen.rpartition(":")
                bind_host = host_part or "127.0.0.1"
                bind_port = int(port_part or "8765")
                principal_tokens = {}
                if policy:
                    for name, grant in policy.grants.items():
                        if grant.token_env:
                            token = engine.vault.get(grant.token_env)
                            if len(token) < 16:
                                raise ValueError("Each HTTP principal needs a credential of at least 16 characters")
                            if token in principal_tokens:
                                raise ValueError("A credential cannot be shared by different principals")
                            principal_tokens[token] = name
                http_srv = McpHttpServer(
                    server,
                    bind_host=bind_host,
                    bind_port=bind_port,
                    bearer_token=args.token or engine.vault.get(args.token_env),
                    allowed_origins=tuple(args.allowed_origin),
                    principal_tokens=principal_tokens,
                )
                print(
                    f"Enclave Gateway HTTP MCP & Tool Server listening on http://{bind_host}:{bind_port} "
                    "(/mcp, /v1/tools, /v1/tools/call, /openapi.json)",
                    file=sys.stderr,
                )
                try:
                    http_srv.serve_forever()
                except KeyboardInterrupt:
                    http_srv.stop()
                return 0
            server.serve_stdio()
            return 0
        finally:
            server.stop_all_tunnels()
            if router: router.close()

    if args.command=='provider':
        result=engine.provider_manage(args.action,apply=args.apply,approval_digest=args.approval_digest,tx_id=args.tx_id)
        print(json.dumps(result,indent=2))
        return 1 if result.get('cleanup_pending') else 0
    if args.command=='agent-verify':
        evidence = engine.attest_worker() if args.wait_ready is None else engine.attest_when_ready(args.wait_ready)
        print(json.dumps(evidence,indent=2))
        return 0
    if args.command == "capabilities":
        print(json.dumps(engine.capabilities(), indent=2))
        return 0

    if args.command == "transactions":
        if args.action in ("get", "cancel") and not args.tx_id:
            parser.error("transactions get/cancel requires a tx_id")
        if args.action=='maintain':
            value=engine.journal.maintain(force=True)
        elif args.action == "cancel":
            value = engine.cancel_transaction(args.tx_id)
        elif args.action == "reconcile":
            from enclave_gateway.operations.context import principal
            value = {"indeterminate": engine.journal.reconcile_expired(principal())}
        else:
            value = engine.transaction_status(args.tx_id if args.action == "get" else None, limit=args.limit)
        print(json.dumps(value, indent=2, ensure_ascii=False))
        return 0

    if args.command == "init":
        from enclave_gateway.provision.builder import ApplianceProvisioner, ProvisionOptions

        if args.recover_machine_preparation:
            if args.create_disk or args.force_disk or args.launch_installer or args.detach_installer:
                parser.error('Machine recovery cannot create a disk or launch an installer')
            from enclave_gateway.provision.recovery import recover_machine
            from enclave_gateway.control.qga_client import QgaClient
            from enclave_gateway.hypervisor.driver import detect_host_arch
            architecture=cfg.appliance.arch if args.arch=='auto' else args.arch
            print(json.dumps(recover_machine(QgaClient(cfg.appliance.qga_socket),detect_host_arch(architecture)),indent=2))
            return 0
        if args.detach_installer and not args.launch_installer:parser.error('--detach-installer requires --launch-installer')
        with engine.hypervisor.state_store().locked():
            if args.launch_installer:engine.hypervisor._assert_offline()
            admin_pw = (
                engine.vault.get("ENCLAVE_APPLIANCE_PASSWORD") or ProvisionOptions().admin_password
            )
            opts = ProvisionOptions(
                arch=args.arch,
                admin_password=admin_pw,
                admin_user=args.admin_user,
                seed_iso_path=args.seed_iso,
                guest_agent_sha256=args.guest_agent_sha256,
                completion_mode=args.completion_mode,
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
                from enclave_gateway.hypervisor.state import private_dir
                private_dir(Path(cfg.appliance.runtime_dir))
                engine.hypervisor._assert_offline()
                engine.hypervisor._start_tpm()
                command=manifest['qemu_install_command']
                try:
                    if args.detach_installer:
                        if os.name=='nt':
                            subprocess.Popen(command,cwd=cfg.appliance.runtime_dir,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                             creationflags=getattr(subprocess,'DETACHED_PROCESS',0)|getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0))
                        else:subprocess.run([*command,'-daemonize'],check=True)
                        import time
                        deadline=time.monotonic()+30
                        while not engine.hypervisor.is_running()[0]:
                            if time.monotonic()>=deadline:raise TimeoutError('Installer did not expose its expected QMP identity')
                            time.sleep(.1)
                        print(json.dumps({'installer_started':True,'pid':engine.hypervisor.is_running()[1]}))
                    else:
                        subprocess.run(command,cwd=cfg.appliance.runtime_dir,check=True)
                        engine.hypervisor._assert_offline()
                except BaseException:
                    if not cfg.appliance.pid_file.exists():engine.hypervisor._assert_offline()
                    raise
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

    if args.command=='agents':
        if args.agents_action=='prune':
            print(json.dumps(engine.prune_agents(remove=args.remove,keep=args.keep,min_age_hours=args.min_age_hours,apply=args.apply),indent=2))
        elif args.agents_action=='stop':
            result=engine.stop_worker(timeout_sec=args.timeout,unregister_autostart=args.unregister_autostart)
            print(json.dumps({'exit_code':result.exit_code,'stdout':result.stdout,'stderr':result.stderr,'tx_id':result.tx_id}))
            return result.exit_code
        else:print(json.dumps(engine.stage_agents(execution_policy=args.execution_policy,migrate_legacy_state=args.migrate_legacy_state,persist_autostart=args.persist_autostart,policy_source=args.policy_source),indent=2))
        return 0

    if args.command == "doctor":
        diag = engine.doctor(
            fix=args.fix, probe_targets=args.probe_targets, actor="cli"
        )
        print(json.dumps(diag, indent=2, ensure_ascii=False))
        return 0 if diag["healthy"] else 1

    if args.command == "top":
        from enclave_gateway.tui.dashboard import run_interactive_top

        return run_interactive_top(
            engine, interval_sec=args.interval, once=args.once
        )

    if args.command == "heal":
        res = engine.heal(update_credentials=args.update_credentials, execution_policy=args.execution_policy,
                          policy_source=args.policy_source, actor="cli")
        if res.stdout:
            print(res.stdout)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        if res.exit_code:
            from enclave_gateway.diagnostics import remediation
            print(remediation(res.stderr or res.stdout),file=sys.stderr)
        return res.exit_code

    if args.command == "clean":
        summary = engine.clean_session(actor="cli")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0 if summary['ok'] else 1

    if args.command == "reset":
        engine.hypervisor.restore_snapshot(args.snapshot)
        print("Appliance offline state restored from verified bundle.")
        return 0

    if args.command == "snapshot":
        if args.recover:
            if args.name:parser.error('--recover cannot be combined with --name')
            print(json.dumps({'recovered':engine.hypervisor.recover_snapshot_restore()}))
        else:
            engine.hypervisor.create_snapshot(args.name)
            print("Appliance offline state bundle created.")
        return 0

    if args.command == "exec":
        env_map: dict[str, str] = {}
        for item in args.env or []:
            k, sep, v = str(item).partition("=")
            if not sep or not k:
                print(
                    f"Error: invalid --env '{item}' (expected KEY=VALUE).",
                    file=sys.stderr,
                )
                return 1
            env_map[k] = v

        secret_env_map: dict[str, str] = {}
        for item in args.secret_env or []:
            raw_item = str(item)
            if "=" in raw_item:
                ek, _, vk = raw_item.partition("=")
                secret_env_map[ek] = vk
            else:
                secret_env_map[raw_item] = raw_item

        res = engine.exec_node(
            args.node,
            args.script,
            as_root=args.sudo,
            confirm_destructive=args.confirm_destructive,
            env=env_map,
            secret_env=secret_env_map,
            timeout_sec=args.timeout,
            actor="cli", tx_id=args.tx_id,
        )
        from enclave_gateway.diagnostics import diagnostic_code,remediation
        metadata={"tx_id":res.tx_id,"timings_ms":res.timings_ms,"exit_code":res.exit_code}
        if res.exit_code:metadata['diagnostic_code']=diagnostic_code(res.stderr,res.exit_code)
        print(json.dumps(metadata),file=sys.stderr)
        if res.stdout:
            sys.stdout.write(res.stdout)
        if res.stderr:
            sys.stderr.write(res.stderr)
        if res.exit_code==255:
            if res.stderr and not res.stderr.endswith('\n'):print(file=sys.stderr)
            print(remediation(res.stderr or res.stdout),file=sys.stderr)
        return res.exit_code

    if args.command == "cp":
        src_node, src_path = _parse_copy_spec(args.source)
        dst_node, dst_path = _parse_copy_spec(args.destination)
        transfer = engine.transfer_file_chunked if args.chunked else engine.transfer_file
        delta_options = {} if args.chunked else {"use_delta": not args.no_delta}
        if src_node is None and dst_node is not None:
            meta = transfer(
                "push",
                src_path,
                dst_node,
                dst_path,
                as_root=args.sudo,
                **delta_options,
                timeout_sec=args.timeout,
                actor="cli", tx_id=args.tx_id,
            )
        elif src_node is not None and dst_node is None:
            meta = transfer(
                "pull",
                dst_path,
                src_node,
                src_path,
                as_root=args.sudo,
                **delta_options,
                timeout_sec=args.timeout,
                actor="cli", tx_id=args.tx_id,
            )
        else:
            print(
                "Error: specify exactly one remote endpoint (<local> <node>:<remote> or <node>:<remote> <local>).",
                file=sys.stderr,
            )
            return 1
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        return 0

    if args.command == "sync":
        src_node, src_path = _parse_copy_spec(args.source)
        dst_node, dst_path = _parse_copy_spec(args.destination)
        if src_node is None and dst_node is not None:
            meta = engine.sync_directory(
                "push",
                src_path,
                dst_node,
                dst_path,
                as_root=args.sudo,
                exclude=args.exclude,
                actor="cli", tx_id=args.tx_id,
            )
        elif src_node is not None and dst_node is None:
            meta = engine.sync_directory(
                "pull",
                dst_path,
                src_node,
                src_path,
                as_root=args.sudo,
                exclude=args.exclude,
                actor="cli", tx_id=args.tx_id,
            )
        else:
            print(
                "Error: specify exactly one remote endpoint (<local_dir> <node>:<remote_dir> or <node>:<remote_dir> <local_dir>).",
                file=sys.stderr,
            )
            return 1
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        return 0

    if args.command == "ssh":
        extra = list(args.ssh_args or [])
        if extra and extra[0] == "--":
            extra = extra[1:]
        ssh_cmd = engine.build_ssh_command(
            args.node, extra_args=extra, config_path=args.config
        )
        if args.print_cmd:
            print(" ".join(ssh_cmd))
            return 0
        proc = subprocess.run(ssh_cmd, check=False)
        return proc.returncode

    if args.command == "ssh-copy-id":
        res = engine.bootstrap_ssh_key(args.node, actor="cli")
        if res.stdout:
            print(res.stdout)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        return res.exit_code

    if args.command == "tunnel":
        engine.rdp_vfs.require_tcp_mux()
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
        from enclave_gateway.transports.rdp_vfs import RdpVfsTunnelServer

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
        engine.rdp_vfs.require_tcp_mux()
        from enclave_gateway.transports.socks5_mux import Socks5VfsServer

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

    if args.command == "forward":
        engine.rdp_vfs.require_tcp_mux()
        from enclave_gateway.transports.socks5_mux import MultiPortForwardSupervisor

        if not cfg.forwards and not args.with_socks5:
            print(
                "Error: no 'forwards:' configured in enclave.yaml (and --with-socks5 not specified).",
                file=sys.stderr,
            )
            return 1
        socks_port: int | None = None
        if args.with_socks5:
            socks_port = (
                args.socks5_port
                if args.socks5_port is not None
                else cfg.appliance.socks5_port
            )
        aliases = {name: spec.host for name, spec in cfg.targets.items()}
        for f_name, f_spec in cfg.forwards.items():
            print(
                f"Forward [{f_name}] listening on {f_spec.bind_host}:{f_spec.local_port} -> {f_spec.target_host}:{f_spec.target_port}"
            )
        if socks_port is not None:
            print(
                f"SOCKS5 multiplexer listening on 127.0.0.1:{socks_port} -> routing via RdpVfsTransport"
            )
        sup = MultiPortForwardSupervisor(
            engine.rdp_vfs,
            cfg.forwards,
            socks5_port=socks_port,
            target_aliases=aliases,
        )
        try:
            sup.serve_forever()
        except KeyboardInterrupt:
            sup.stop()
        return 0

    if args.command == "stdio-proxy":
        engine.rdp_vfs.require_tcp_mux()
        from enclave_gateway.transports.socks5_mux import pump_stdio_mux

        resolved_host = (
            cfg.targets[args.host].host if args.host in cfg.targets else args.host
        )
        return pump_stdio_mux(
            engine.rdp_vfs,
            resolved_host,
            args.port,
            sys.stdin.buffer,
            sys.stdout.buffer,
        )

    if args.command == "ssh-config":
        sys.stdout.write(
            engine.generate_ssh_config(config_path=args.config, prefix=args.prefix)
        )
        return 0

    if args.command == "watch":
        try:
            history = engine.watch(
                interval_sec=args.interval,
                max_iterations=args.max_iterations,
                probe_targets=args.probe_targets,
            )
            if args.max_iterations is not None:
                print(json.dumps(history, indent=2, ensure_ascii=False))
        except KeyboardInterrupt:
            pass
        return 0

    if args.command == "profile":
        if args.profile_action == "create":
            from enclave_gateway.provision.builder import ApplianceProvisioner

            provisioner = ApplianceProvisioner(cfg)
            base_disk = Path(args.base_disk) if args.base_disk else None
            out_dir = Path(args.output_dir) if args.output_dir else None
            manifest = provisioner.create_cow_profile(
                args.name,
                base_disk=base_disk,
                output_dir=out_dir,
                create_disk=args.create_disk,
            )
            print(json.dumps(manifest, indent=2, ensure_ascii=False))
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


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except Exception as exc:
        error = exc if isinstance(exc, OperationError) else getattr(exc, "operation_error", None)
        if error is None:
            if isinstance(exc,(ValueError,OSError)):
                from enclave_gateway.diagnostics import remediation,diagnostic_code
                detail=str(exc)
                print(json.dumps({'error':{'code':'setup_error','diagnostic_code':diagnostic_code(detail),'message':detail,'remediation':remediation(detail)}},ensure_ascii=False),file=sys.stderr)
                return 1
            raise
        from enclave_gateway.diagnostics import remediation,diagnostic_code
        data=error.as_dict();data['remediation']=remediation(str(error));data['diagnostic_code']=diagnostic_code(str(error))
        print(json.dumps({"error": data}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
