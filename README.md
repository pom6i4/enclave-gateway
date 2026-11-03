# Enclave Gateway (`egw`)

Run commands, transfer files and forward TCP connections into an enclave through
an approved Windows VPN Appliance and an RDP Bastion. `egw` connects a local CLI
or MCP client to TargetNodes without requiring an inbound SSH port on the Bastion.

```text
Host → QGA → Windows Appliance → RDP redirected drive → Bastion worker → SSH → TargetNode
```

**Beta software.** Standard mode is for a trusted operator and RDP session.
Enterprise adds signed native isolation and verified identities. Neither mode
replaces the organization's endpoint policy, VPN entitlement or host-key approval.

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
- [Maintainer qualification](contrib/qualification/README.md): disposable lab
  tooling and historical evidence, separate from product configuration.

The CLI includes `exec`, `cp`, `sync`, `ssh`, `ssh-config`, `tunnel`, `socks5`,
`forward`, `status`, `doctor`, `top` and `mcp`. Run `egw --help` for the full list.

License: [MIT](LICENSE).
