# Enclave Gateway (`egw`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](pyproject.toml)
[![Zero mandatory third-party Python dependencies](https://img.shields.io/badge/Python_dependencies-0_required-green.svg)](pyproject.toml)
[![MCP server](https://img.shields.io/badge/MCP-server-green.svg)](docs/SECURITY.md)

Run commands, transfer files and forward TCP connections from a macOS (Apple
Silicon arm64 or Intel x86_64), Linux or Windows Host through an isolated Windows
VPN Appliance and an RDP Bastion (TCP 3389), even when inbound SSH to Bastion is
closed. The Appliance uses QEMU HVF / KVM / WHPX with matching Host/guest
architectures; Windows Direct mode uses the existing Host instead of an isolated
VM. Use the organization's approved Windows VPN client: ViPNet Client,
АПКШ Континент, Cisco AnyConnect / Secure Client, OpenVPN, WireGuard or a custom
provider. `egw` connects a local CLI or MCP client to the enclave's TargetNodes.

```text
Host → QGA → Windows Appliance → RDP redirected drive → Bastion worker → SSH → TargetNode
```

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/architecture-light.svg">
    <img alt="Enclave Gateway architecture from host through Windows appliance and RDP Bastion to SSH and TCP targets" src="docs/assets/architecture-light.svg" width="100%">
  </picture>
</p>

**Beta software.** Standard mode is for a trusted operator and RDP session.
Enterprise adds signed native isolation and verified identities. Neither mode
replaces the organization's endpoint policy, VPN entitlement or host-key approval.

## Key capabilities

- **QEMU Appliance & 6 VPN Provider Adapters** — `vipnet`, `kontinent`,
  `anyconnect`, `openvpn`, `wireguard`, `custom`. Installed-binary probes inspect
  PE architecture (`arm64` / `x86_64` / `x86`), Authenticode and exact configured
  versions/publisher. Matching configuration does not qualify a driver or VPN
  session. Optional `egw provider install|connect|disconnect|import_key` plans use
  a hash-pinned lifecycle manifest; apply requires its reviewed approval digest.
  No proprietary command line or key-import procedure is inferred.
- **Transactional RDP VFS Transport** — `[MS-RDPEFS]` / `\\tsclient` redirected
  files, without custom virtual-channel `.dll` installation. Parallel Striped I/O
  and block deltas use SHA-256, default 4 MiB blocks and optional zlib compression.
  Standard executes commands in warm PowerShell runspaces; transfer scripts use
  a RunspacePool. No C# compiler or additional worker `.exe` is required.
- **Multi-Hop SSH, SOCKS5 & Port Forwarding** — `egw exec`, `cp` and `sync`;
  bidirectional TCP multiplexing and RFC 1928 SOCKS5 (`egw socks5`); OpenSSH
  ProxyCommand (`egw ssh`, `stdio-proxy`, `ssh-config`); supervised forwards
  (`egw forward`), terminal monitoring (`egw top`) and layered L1–L7 diagnostics
  (`egw doctor`, `heal`). SSH requires verified host keys and credentials on the
  executing hop; transport compatibility and latency need deployment validation.
- **Governed MCP Server (stdio & HTTP)** — connect AI agents and IDEs with
  `egw mcp`, role/tool/node/path policies and `PrincipalRouter` backends.
  `DestructiveCommandGuard` checks commands, `SecretScrubber` filters registered
  and recognized secret patterns, `FlightRecorder` provides hash-linked audit,
  and `egw transactions` retains operation identities/outcomes. These controls
  supplement explicit authorization and Enterprise OS isolation; command checks
  and scrubbing cannot recognize every possible shell effect or secret.

## Start with an existing environment

You need Python 3.10+, an existing Windows Appliance with its QGA channel exposed
to the Host, a working approved VPN/RDP route, PowerShell FullLanguage and an
OpenSSH client on the Bastion. New VM provisioning is a separate installation
step. Proprietary VPN installers, licenses, credentials and images are not bundled.

```sh
git clone https://github.com/pom6i4/enclave-gateway.git
cd enclave-gateway
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/egw config init
# Or: cp config/enclave.example.yaml enclave.yaml
# Edit the VM paths, Bastion and TargetNode.
.venv/bin/egw config check
.venv/bin/egw doctor --preflight
.venv/bin/egw agents stage
```

On Windows use `.venv\Scripts\python.exe` and `.venv\Scripts\egw.exe`;
see [installation](docs/GUIDE.md#installation).

For a global installation, use `egw config init --global`. The CLI can then run
from any directory; the global configuration and private state are selected
without a shell wrapper. See [configuration discovery](docs/GUIDE.md#configuration-discovery-and-private-state)
for precedence and environment overrides.

Connect the Appliance's approved RDP session to the Bastion with drive redirection.
**Run the command printed by `agents stage` inside that Bastion session.**
It copies the verified scripts locally on Bastion and starts a foreground
in-process worker in Standard mode: no C# compiler,
additional `.exe` or code-signing certificate is needed. The existing execution
policy must permit the scripts; WDAC/AppLocker/ConstrainedLanguage are respected.

Provision verified SSH host keys and a login key **on the hop that executes SSH**
([instructions](docs/GUIDE.md#ssh-trust)), then:

```sh
.venv/bin/egw doctor --probe-targets
.venv/bin/egw exec app01 'id'
echo hello > hello.txt
.venv/bin/egw cp hello.txt app01:/tmp/hello.txt
```

`egw heal` also stages the agents in named modes, repairs Appliance settings and
reconnects its managed RDP session. Until the worker is started on Bastion it can
return `SESSION_PENDING_WORKER`; staging alone does not start a remote process.

For high-latency redirected drives, evaluate the explicit
[`bastion.spool_protocol: stream` option](docs/GUIDE.md#short-command-latency-over-redirected-drives).
The compatible file protocol remains the default; switching requires restarting
the worker with the same configuration.
For measured Stream performance and the cold-start acceptance boundary, see
the [source baseline](docs/RELEASING.md#source-baseline).

## Choose a trust model

| | Standard | Enterprise |
| --- | --- | --- |
| Intended use | Trusted operator/session | Governed deployment and isolated service principals |
| Worker commands | In-process PowerShell runspaces | Native owned process jobs |
| Additional binaries | None for key-based SSH | Approved `egw-runtime.exe`, and askpass for passwords |
| Code trust | Reviewed source under endpoint policy | Authenticode, approved release/CMS verification and pinned hashes |
| Worker identity | Session trust; heartbeat is liveness | Fresh release/runtime/SID attestation |
| Multiuser MCP | No hostile-principal isolation claim | Explicit policy plus per-principal OS backends |

Enterprise is configured with [its template](config/enclave.enterprise.example.yaml)
and [security/deployment guide](docs/SECURITY.md). Missing requirements fail closed;
there is no automatic downgrade. Configurations without `security.mode` retain
their existing **Custom** defaults. A new CLI-generated config explicitly selects
Standard; migrating an existing deployment is an operator decision.

## Documentation

- [Engineer and administrator guide](docs/GUIDE.md): installation, first connection,
  keys, CLI recipes, existing VM prerequisites and troubleshooting.
- [Security architecture and Enterprise deployment](docs/SECURITY.md): trust
  boundaries, signing, attestation, roles and operational limits.
- [Contributing](CONTRIBUTING.md): code layout, tests and extension points.
- [Release preparation and component compatibility](docs/RELEASING.md), with
  [unreleased changes](CHANGELOG.md): source-bound unsigned candidates and checks.
- [Maintainer qualification](contrib/qualification/README.md): disposable lab
  tooling and historical evidence, separate from product configuration.

The CLI includes `exec`, `cp`, `sync`, `ssh`, `ssh-config`, `tunnel`, `socks5`,
`forward`, `status`, `doctor`, `top` and `mcp`. Run `egw --help` for the full list.

License: [MIT](LICENSE).
