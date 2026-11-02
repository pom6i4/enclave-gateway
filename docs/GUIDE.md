# Engineer and administrator guide

## Installation

The Python CLI requires Python 3.10 or newer and has no mandatory third-party
Python dependencies. The shipped examples use its supported YAML subset; JSON is
also valid, including in a `.yaml` file. Install `.[yaml]` for additional YAML
syntax. Duplicate mapping keys and unknown settings are rejected with either
parser, rather than silently changing the security profile.

On macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/egw config init
```

On Windows PowerShell, activation of a script is unnecessary:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\egw.exe config init
```

Use that environment's `egw` executable for the rest of this guide, or add its
scripts directory to your PATH. `config init` never overwrites an existing file.
`config init --mode enterprise` writes an intentionally incomplete profile: fill
in release pins before `config check` can succeed. Configuration files contain
paths, topology and credential variable names; keep passwords in the OS key store
or a private environment file, never in Git or command history.

`egw secret set ENCLAVE_BASTION_PASSWORD` uses a hidden prompt; `--stdin` accepts
a value from an approved secret source for noninteractive setup. Avoid the legacy
positional value, which can enter shell history. `secret get` reports only whether
a value is present. These commands and MCP schema/client-config exports work
without a topology or audit database.

## First connection

### Choose the controller

An existing VM must have QEMU Guest Agent installed with its virtio-serial channel
and the QGA socket matching `appliance.runtime_dir` and `appliance.name`. Use the
same managed name, disk and matching UEFI variable store that were used to start
it. A running VM in an arbitrary desktop hypervisor is not automatically a managed
QEMU Appliance. `heal` repairs a reachable Appliance; it cannot invent its QGA
channel, install a VPN license or authenticate an unapproved session.

For a new managed Appliance, `egw init --help` describes Windows/VirtIO installation
media, disk creation and the QGA preparation flow. Boot and finish that installation
before attempting the connection below. Native acceleration requires matching
Host/guest architectures. Software TPM in a guest is not hardware attestation;
managed TPM on a native Windows Host still depends on an available supported
backend. VPN/provider packages require their own version/architecture approval.

Windows Direct mode (`appliance.hypervisor: direct`) uses the existing Windows
Host as the controller. In Standard mode it uses PowerShell without native helpers.
On a POSIX Host, Direct mode is useful for an already reachable SSH TargetNode:
set `bastion.enabled: false`, `targets.app01.via: appliance` and a reachable
`provider.probe_host`/`probe_port`. No Windows registry or RDP checks apply there.

### Validate, stage, start

1. Copy `config/enclave.example.yaml`, or use `egw config init`; edit VM paths,
   network probe, Bastion and TargetNode. `provider: custom` means the approved
   connection is managed externally. It performs no automatic installer/key import.
2. Run `egw config check`. It reports the **effective** security flags and the
   hop on which each TargetNode's SSH client runs. It opens no connection and
   does not create an audit database.
3. Run `egw doctor --preflight`. This only checks Host prerequisites; remote QGA,
   RDP, application-control policy and SSH authentication remain explicitly untested.
4. Run `egw agents stage`, or `egw heal` on a reachable Windows Appliance.
   Both scripts are delivered as one immutable content-addressed bundle under
   `C:\EnclaveGateway\spool\agents\<digest>`. Existing generations are preserved;
   bytes and, when required, Authenticode publishers are checked before publication.
5. Open the approved Appliance-to-Bastion RDP session. Ensure its redirected
   drive exposes the configured `bastion_spool_dir`. In a PowerShell window **on
   Bastion**, run the complete `start_command` printed by staging. Leave the
   foreground Standard worker running.
6. Provision SSH trust and login keys as described below, then run
   `egw doctor --probe-targets`, `egw exec app01 'id'` and
   `egw cp hello.txt app01:/tmp/hello.txt`.

`egw agents command` prints the expected startup command without a connection;
it does not claim that staging succeeded or a worker is running. `heal` also
changes MTU/clock/RDP settings and reconnects **its managed** RDP session. It is
not a read-only preflight. An absent worker yields `SESSION_PENDING_WORKER` until
the Bastion-side startup step is complete. It does not install an SDK on Bastion.
If endpoint policy forbids unsigned scripts or additional executables, Standard
cannot override it: obtain script approval, use the permitted signed mode, or
report that the endpoint is incompatible.

### Protect the redirected drive

The conventional `\\tsclient\C\EnclaveGateway\spool` path uses a redirected C:
drive. That RDP setting can expose more of the Appliance than just the spool.
Restrict redirection with your approved RDP client/volume arrangement and set both
spool paths consistently. Keep credentials outside redirected user-readable
locations. The spool is a command channel: grant access only to its trusted
operator/session. An arbitrary writer is not an untrusted service principal.

## SSH trust

There are **two different locations** to configure:

| Command | SSH client, private key and known_hosts |
| --- | --- |
| `exec`/`cp`/`sync`, `via: bastion` | Bastion RDP user's profile |
| `exec`/`cp`/`sync`, `via: appliance` | Appliance execution account; Host account in POSIX Direct mode |
| `egw ssh` / generated Host `ssh-config` | Host user's OpenSSH profile; traffic uses the VFS proxy |

`ssh_key_path` and optional `ssh_known_hosts_path` select files on the executing
hop for `exec`/`cp`/`sync`. A path to your Host's private key does not transfer it
to Bastion. Further TargetNode aliases in `via` form a checked hop chain; every
SSH hop needs its own approved identity and host-key trust. Host interactive SSH
also needs Host-side keys and trust; identical path strings can name different
files on different machines.

Obtain each server's public host key and SHA-256 fingerprint from its administrator
through a trusted channel. On the executing hop, inspect the candidate with
`ssh-keygen -lf <candidate-known-hosts> -E sha256`, compare the fingerprint, then
install the exact approved entry in that user's `known_hosts`. Non-default ports
use `[host]:port`. `ssh-keyscan` alone does not authenticate a key. Keep
`StrictHostKeyChecking=yes`; do not remove a changed entry until the administrator
has verified the rotation. Hashed existing entries can be inspected with
`ssh-keygen -F <host> -f <known_hosts>`.

Generate or provision the login key **on that hop** and install its public part
in the target account's `authorized_keys`. Prefer an approved agent for encrypted
keys; protect unattended keys with account/file ACLs. In Standard mode, key-based
SSH works without `egw-askpass.exe`. `egw ssh-copy-id app01` is a separate password
bootstrap path: Windows-hop password authentication requires an approved native
askpass helper and trusted publishers. It generates an unattended hop key if
needed; it does not establish host-key trust. Windows TargetNode authorized_keys
placement/ACL policy requires its administrator's provisioning process.

## Daily work

```sh
egw status
egw doctor --probe-targets
egw exec app01 'uname -a'
egw cp ./release.tar.gz app01:/tmp/release.tar.gz
egw sync ./release app01:/srv/app/releases/new
egw sync app01:/var/log/app ./logs
egw forward
egw ssh app01
egw ssh-config
```

Use `--sudo` only with an approved target privilege policy. Windows targets do not
support sudo. File and shell paths are interpreted on the selected operating
system; use PowerShell scripts for Windows nodes. `ssh-config` prints entries;
review before adding them to an existing Host configuration. Loopback listeners
are the default. A successful TCP probe proves reachability, not VPN identity.
Heartbeat telemetry proves liveness, not signed identity; Enterprise `doctor`
checks fresh worker trust before issuing its functional ping.

Operations return transaction identities. Use `egw transactions --help` to query
outcomes and reconcile indeterminate results. Never repeat a mutating command
with a new identity merely because an acknowledgement or connection was lost.
Standard runspaces share process/session trust; a timeout does not establish that
an arbitrary native grandchild has stopped. Use Enterprise owned jobs when that
containment is required. Keep result retention, disk capacity and credential
rotation in your operational plan.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| No config / unknown setting / duplicate key | `egw config init`, edit and run `egw config check`; a typo is not ignored |
| Preflight succeeds, connection fails | Preflight checked only Host files/tools; validate QGA, VPN, RDP and remote policy |
| QGA socket missing | Match the existing VM's virtio channel, runtime directory and managed name; confirm QGA service |
| `SESSION_PENDING_WORKER` / no fresh heartbeat | Run `egw agents stage`, verify redirection and execute its printed command inside Bastion RDP |
| Script is blocked / ConstrainedLanguage | Obtain administrator approval under the actual endpoint policy; do not bypass it |
| Native helper absent | Standard key-based/in-process work needs no helper; explicitly requested isolation or password helper needs the approved package |
| Host-key verification failed | Verify the expected fingerprint and known_hosts **on the SSH hop**, retaining strict checking |
| `Permission denied (publickey)` | Check target account, authorized_keys ACLs and the key/agent on the hop |
| Enterprise hash/signature/SID mismatch | Stop and deploy the approved matching release/account; no fallback or blind pin update |
| Disconnect / deadline / indeterminate transaction | Query the retained transaction identity; do not replay effects automatically |

For MCP transport, policy and signing deployment, see [SECURITY.md](SECURITY.md).
For lab commands and limits, see [maintainer qualification](../contrib/qualification/README.md).

References: [OpenSSH configuration](https://man.openbsd.org/ssh_config),
[ssh-keyscan trust limitations](https://man.openbsd.org/ssh-keyscan), and
[PowerShell execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).
