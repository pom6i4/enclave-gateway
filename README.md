# Enclave Gateway (`egw`)

**Cross-Platform Cryptographic Appliance Orchestrator, RDP Virtual-Channel (`[MS-RDPEFS]`) Relay, Multi-Hop SSH Router, and Model Context Protocol (MCP) Server for Isolated Network Enclaves.**

---

## Overview

Connecting modern developer workstations (**macOS on Apple Silicon `M1–M5`**, **modern Linux kernels `6.8+`**, or clean **Windows** hosts) to isolated corporate and government network enclaves protected by proprietary VPN clients (**InfoTeCS ViPNet Client 4/5**, etc.) and locked-down **RDP Jump Hosts (Bastions)** normally requires manual GUI workflows, dedicated laptops, or fragile nested quoting across multiple shells.

**Enclave Gateway (`egw`)** replaces manual GUI clicking with an automated, cross-platform L3–L7 gateway and RPC pipeline:

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Host Environment (macOS HVF / Linux KVM / Windows WHPX or Direct)                 │
│   CLI: egw (init | up | down | status | top | heal | exec | cp | tunnel | socks5) │
│   MCP Server: JSON-RPC 2.0 over stdio (enclave_status, node_exec, node_transfer…) │
│   Security: OS Keychain Vault + Blind Secret Injection + Output Secret Scrubber   │
└───────────────────┬───────────────────────────────────────────┬───────────────────┘
                    │ virtio-serial (QEMU Guest Agent / QMP)    │ TCP 127.0.0.1
                    ▼                                           ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Cryptographic Appliance VM (Isolated Guest OS + Golden qcow2 Snapshot)            │
│   VPN Provider: InfoTeCS ViPNet Client 5 (WINTUN-ARM64.SYS / x64) or Custom VPN   │
│   Network Tuning: Persistent MTU=1350 (PMTUD blackhole fix) + fClientDisableUDP=1 │
│   SessionSupervisor: Interactive Session Credential Injector + mstsc Watchdog     │
└───────────────────────────────────────┬───────────────────────────────────────────┘
                                        │ RDP (TCP 3389, [MS-RDPEFS] rdpdr channel)
                                        ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Bastion (Locked-Down Terminal Server / Jump Host — Only TCP 3389 Open)            │
│   RdpVfsTransport Spool: \\tsclient\C\EnclaveGateway\spool                        │
│   BastionWorker: Resident In-Process PowerShell Runspace Agent (~250ms latency)   │
│     • Transactional JSON Envelopes: req_<tx_id>.json <-> res_<tx_id>.json         │
│     • Block-Level SHA-256 Delta Sync + zlib Stream Compression                    │
│     • TCP-over-RDP-VFS Socket Relay & Multi-Hop OpenSSH Client                    │
└───────────────────┬───────────────────────────────────────────┬───────────────────┘
                    │ OpenSSH / SCP (Base64 + CR-stripped)      │ TCP Relay
                    ▼                                           ▼
┌───────────────────────────────────────┐   ┌───────────────────────────────────────┐
│ Upstream TargetNode (app01)           │   │ Upstream TargetNode (auth01)          │
│ 10.0.20.11 (Linux / Docker / DB)      │   │ 10.0.20.12 (Internal Web / IAM / API) │
└───────────────────────────────────────┘   └───────────────────────────────────────┘
```

---

## Key Engineering Capabilities

1. **Hardware-Accelerated Cross-Platform Appliance (`HVF` / `KVM` / `WHPX`)**
   * Runs `ViPNet Client 5` natively on **Apple Silicon (`ARM64`)** via `WINTUN-ARM64.SYS` inside an isolated QEMU appliance accelerated by Apple `Hypervisor.framework` (`-accel hvf -cpu host`).
   * Keeps **Linux** (`6.8+` kernels where proprietary out-of-tree modules fail to build) and **Windows** host network stacks completely clean of third-party NDIS filter drivers.
   * Supports instant **1-second rollback (`egw reset`)** via `qcow2` golden snapshots and lightweight **Copy-on-Write profile overlays** (~300 MB per customer enclave).

2. **Transactional RDP Virtual File System IPC (`RdpVfsTransport` over `[MS-RDPEFS]`)**
   * When an enterprise firewall blocks `SSH (22)`, `SMB (445)`, and `WinRM (5985/5986)` on the Jump Host—leaving only `RDP (3389/TCP)` open—`egw` mounts a shared spool directory over the RDP File System Virtual Channel (`\\tsclient\C\EnclaveGateway\spool`).
   * **In-Process `BastionWorker`**: executes payloads inside a warm PowerShell runspace (`& ([scriptblock]::Create(...))`) in `~200–350 ms` without spawning child `powershell.exe` processes (avoiding `AMSI` startup overhead and false-positive behavioral alerts from endpoint security suites).
   * **Concurrency-Safe Envelopes**: pairs `req_<tx_id>.json` and `res_<tx_id>.json` with separated Base64-encoded `stdout` and `stderr` streams.

3. **Accelerated File Delivery (`Block-Level Delta Sync` + `Parallel Striped I/O`)**
   * Standard `[MS-RDPEFS]` single-stream file transfers are bottlenecked by RDP flow control (~140 KB/s).
   * `egw cp` computes a **4 MB block-level `SHA-256` manifest** on both ends, compresses changed blocks with `zlib`, and reads/writes stripes in parallel via a warm PowerShell `RunspacePool` on `BastionWorker` (`Parallel Striped I/O`), verifying full-file `SHA-256` integrity before atomic rename.

4. **Bidirectional `SOCKS5` & `TCP-over-RDP-VFS` Multiplexer (`egw socks5` / `egw tunnel`)**
   * Exposes internal enclave web interfaces, APIs, and databases directly on the Host (`127.0.0.1:<port>`) or through a standards-compliant **RFC 1928 `SOCKS5` proxy** (`egw socks5`) with automatic `TargetNode` alias resolution even when only `TCP 3389` is reachable on the Bastion.

5. **Automated Unattended Appliance Provisioning (`egw init`) & Interactive TUI (`egw top`)**
   * `egw init` generates architecture-aware (`arm64` / `x86_64`) `Autounattend.xml` and post-install provisioning media with `VirtIO` drivers, `QEMU Guest Agent`, `MTU=1350`, and silent `ViPNet Client` installation.
   * `egw top` renders a live terminal dashboard tracking `Host -> Appliance -> VPN -> Bastion -> TargetNodes` and recent `FlightRecorder` operations.

6. **Zero-Escaping Multi-Hop SSH & Ephemeral `sudo` Injection**
   * Payloads destined for upstream Linux `TargetNodes` are Base64-encoded end-to-end and stripped of `CR` (`\r`) characters (`tr -d '\r'`), eliminating multi-shell quote escaping bugs and Windows PowerShell `CRLF` pipeline corruption.
   * Elevated `--sudo` operations inject credentials from the OS Keychain via ephemeral files deleted in a `finally` block—passwords never appear in command-line arguments or process tables.

7. **Built-In Model Context Protocol (MCP) Server (`egw mcp`)**
   * Standards-compliant JSON-RPC 2.0 MCP server over `stdio` with zero external runtime dependencies.
   * Includes **Output Secret Scrubbing** (`[REDACTED]`) and **Destructive Command Guardrails** (`DROP`, `TRUNCATE`, `rm -rf /`, `shutdown` require explicit `confirm_destructive=True`).

---

## Real-World Pitfalls Solved Out of the Box

| Problem | Root Cause | How `enclave-gateway` Solves It |
|---|---|---|
| **RDP drops every ~60 seconds over ViPNet** (`Event 1026, Reason=267`) | Virtual `Infotecs` (`WinTun`) adapter defaults to `NlMtu = 65535`, while the tunnel silently drops `DF=1` packets >1420 bytes without ICMP fragmentation notices (PMTUD blackhole), and RDP-over-UDP sends unnegotiated 1500-byte datagrams. | `appliance_init.ps1` sets persistent `mtu=1350` on `Infotecs` and `Ethernet` interfaces and sets `fClientDisableUDP = 1` in registry policy. |
| **`cmdkey` updates via QGA fail NLA login (`LogonUI.exe`)** | QEMU Guest Agent runs as `NT AUTHORITY\SYSTEM` (Session 0), whereas `mstsc.exe` runs in the interactive desktop user session. Windows Credential Manager vaults are strictly isolated per session. | `session_supervisor.ps1` injects `cmdkey` credentials directly into the interactive user session via an ephemeral `/it` scheduled task (`UpdateEnclaveRDPCred`). |
| **Spurious `invalid_grant` / auth failures in bash scripts called from PowerShell** | Windows PowerShell 5.1 pipelines append `\r\n` to every piped line; Linux `read -r` retains the trailing `\r` as part of the password string. | `SecretVault` and `SshHopExecutor` strip `\r` on both ingress and egress (`tr -d '\r'`). |

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/pom6i4/enclave-gateway.git
cd enclave-gateway
pip install -e .
```

### 2. Configuration

Copy the example topology and environment templates:

```bash
cp config/enclave.example.yaml enclave.yaml
cp config/.env.example .env
```

Or store credentials directly in your operating system's native Keychain (macOS Keychain / Linux Secret Service):

```bash
egw secret set ENCLAVE_BASTION_PASSWORD "your-secret-password"
egw secret set ENCLAVE_APP01_SUDO_PASSWORD "your-sudo-password"
```

### 3. CLI Usage

```bash
# Generate unattended Windows 11 Appliance provisioning bundle (Autounattend.xml + VirtIO + QGA)
egw init --output-dir ./build/provision --create-disk

# Start Appliance VM and verify tunnel status
egw up
egw status

# Launch live interactive TUI topology monitor (or --once for snapshot)
egw top

# Self-heal MTU=1350, UDP policy, interactive credentials, and Bastion RDP session
egw heal --update-credentials

# Execute commands across any tier of the topology
egw exec @appliance "vipnetclient.exe info"
egw exec @bastion   "Get-NetTCPConnection -State Established"
egw exec app01      "docker ps --format 'table {{.Names}}\t{{.Status}}'"
egw exec app01 --sudo "systemctl status docker"

# Transfer files with 4 MB block-level SHA-256 delta sync, Parallel Striped I/O, and verification
egw cp ./release.tar.gz app01:/tmp/release.tar.gz
egw cp app01:/var/log/syslog ./syslog.txt

# Tunnel local port 8443 to internal service 10.0.20.12:443 over multiplexed RdpVfsTransport
egw tunnel 8443:auth01:443

# Start bidirectional RFC 1928 SOCKS5 multiplexer on 127.0.0.1:1080 over RdpVfsTransport
egw socks5 --port 1080

# Export Markdown audit report of session operations
egw report
```

### 4. MCP Server Configuration (Cursor / VS Code / Claude Desktop)

Add the following entry to your MCP client configuration (`mcp.json`):

```json
{
  "mcpServers": {
    "enclave-gateway": {
      "command": "egw",
      "args": ["-c", "/path/to/enclave.yaml", "mcp"]
    }
  }
}
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
