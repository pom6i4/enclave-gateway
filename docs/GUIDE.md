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

## Maintain agent generations

`egw agents prune` previews the managed generations on the Appliance. The current
configuration's bundle is always retained. `--keep <sha256>` protects additional
rollback versions; the default minimum age is seven days. Legacy generations,
changed files, extra contents and linked paths are preserved for manual review.
Incoming staging directories and transaction results are outside this operation.

After reviewing the preview, stop the managed workers in their Bastion sessions
and apply only the exact eligible identifiers:

```sh
egw agents prune --keep <rollback-bundle-sha256>
egw agents prune --apply --remove <retired-bundle-sha256> --keep <rollback-bundle-sha256>
```

Repeat `--remove` or `--keep` for multiple generations. Keep the same age/retention
options between preview and apply. Apply checks the complete requested set again
under an exclusive lease before deleting. A worker executing directly from that source generation, another
maintenance operation, an active local copy, or changed eligibility makes it refuse the operation. It
never stops a worker automatically. Staging and new managed workers take shared
leases, so they cannot race an active cleanup. Older packages without this
protocol are not adopted for automatic cleanup, even when staged again. Re-sign
and approve modified scripts through the Enterprise release procedure.

Use a trusted local Windows filesystem on the Appliance and an RDP redirector
that preserves Windows file-sharing semantics. Protect the spool and lease file
from unrelated writers; do not replace the lease file to clear a busy error.
Filesystem I/O failures can leave a partially removed generation; inspect it
before retrying. Cleanup is not a transaction rollback or evidence-retention tool.

## Prepare a support snapshot

`egw diagnostics preview` is offline. It displays a small allow-listed JSON
payload and its SHA-256: software/platform versions, security flags, aggregate
topology counts and Host preflight result codes. It does not include addresses,
paths, profile/target names, signer identifiers, commands, configuration files,
logs, command results or credentials. Remote diagnosis remains a separate step.

```sh
egw diagnostics preview
egw diagnostics save --output support.json --sha256 <reviewed-preview-sha256>
```

Saving recomputes the snapshot and refuses if its digest changed. It never
overwrites an existing file and sends nothing. Review before sharing; software
versions and enabled security features can themselves be sensitive. Files use
mode 0600 on POSIX; choose an appropriately ACL-protected output directory on
Windows. This snapshot is separate from `egw report`, which exports a local audit
report and can contain operational details.

CLI setup errors and doctor checks include stable diagnostic categories. `exec`
reports the exit code and transaction identity on stderr while preserving stdout
and remote stderr. A Windows-hop SSH result retains its own exit code, including
nonzero command results. SSH status 255 is ambiguous: OpenSSH uses it for client
failures, but a remote command can also return 255. Use the diagnostic text as a
hint, verify the channel, and reconcile indeterminate outcomes before retrying.

## Existing VM control paths

`appliance.name` is the identity returned by QMP `query-name`. Existing launchers
can use unrelated control filenames; set `qga_socket_path`, `qmp_socket_path` and
`pid_file_path` explicitly instead of making symlinks or changing the expected VM
identity. A mismatch reports expected and actual names and fails closed. Protect
the endpoint parents and verify that all three paths belong to that VM.
Overrides are for attachment: `up` does not create a new VM using external endpoint
paths, and `down` leaves their cleanup to the owner launcher.

`config init` produces commented YAML with the VM identity, runtime/disk/firmware
paths and optional endpoint overrides. An empty `provider.probe_host` follows
`bastion.host`, and probe port zero follows `bastion.port`; an explicit probe keeps
its configured destination. A deployment without Bastion needs an explicit probe
when using the empty starter value. `status` reports the source address itself,
not the string representation of a network-management object.

## Start, migrate and stop a worker

The printed start command copies the exact hashed bootstrap/worker pair into
`%LOCALAPPDATA%\EnclaveGateway\agents\<digest>` on Bastion, verifies the local
bytes and starts the local bootstrap. It holds the source bundle lease only while
copying; the resident script does not remain loaded from the redirected drive.
Normal endpoint policy still applies, and Windows file copy retains the source's
alternate streams, including an Internet zone marker when present.

Check `Get-ExecutionPolicy -List` on Bastion first. Undefined scopes can resolve
to Restricted on Windows clients. For an approved Standard development session,
`egw agents command --execution-policy RemoteSigned` prints a command with an
explicit **process-only** setting. It refuses to weaken an effective AllSigned
policy; Group Policy remains authoritative. This option is unavailable for signed
profiles. There is no automatic Bypass or Unblock-File step. Use an approved signed
package when signing or application-control policy requires one.

For redirected spools, durable transaction identities live under
`%LOCALAPPDATA%\EnclaveGateway\state\<storage-id>` on Bastion. `worker_storage.json`
in the spool binds that local journal to its original machine/account. Keep both
sides and include the journal in the operational backup plan. A missing or foreign
journal prevents startup; deleting it is not a reset procedure.

To upgrade a legacy redirected deployment, stop its old worker first, preserve its
`.transactions` directory, then generate the startup command with:

```sh
egw agents stage --migrate-legacy-state
```

Review and run the printed command once in the approved Bastion session. Migration
copies and flushes the legacy identities locally before publishing the binding,
leaves the originals intact and does not replay old requests. Unknown/incomplete
legacy files require reconciliation. Do not run the legacy worker again against
that spool after migration. An older backup or a snapshot rollback also requires
outcome reconciliation; journal identity alone does not establish backup freshness.
Perform migration in foreground before registering persistent startup.

`egw agents stop --timeout 45` requests an acknowledged graceful stop. It refuses
while jobs or mux connections remain active, and never kills an unrelated process.
Close those connections, let jobs finish and retry with a new operation. Its
`WORKER_STOP_ACCEPTED` receipt is an acknowledgement; observe stopped status before
starting the printed command again. A mutex and an exclusive spool session lease
reject duplicate workers. Reinstall/re-sign changed Enterprise scripts and update
approved pins before using them.

## WAN RDP behavior and cleanup

The worker uses direct .NET file operations on the redirected spool. It scans the
directory once per recovery pass and uses a bounded advisory `request_index.json`
to open new request/cancel files by name. The index is an optimization: the
individual envelopes and durable identities remain authoritative. Missing, corrupt
or overwritten hints are recovered by a periodic full scan (five seconds after
hints have been observed). Older publishers retain the scan-based path.

Heartbeat telemetry includes loop/scan timing and journal location. Publication
defaults to five seconds. The default
freshness allowance is 45 seconds, configurable as `bastion.heartbeat_max_age_sec`
(5–300). Readiness is checked before publication; an absent/stale/stopped worker
returns `session_pending_worker` without queuing a command. Freshness is a liveness
hint, not signed identity, and a ready worker can still disconnect after preflight.
Enterprise continues to require fresh attestation before protected dispatch.

Transfers do not enqueue unconditional two-second VFS cleanup requests. Hop-spool
stages use direct controller cleanup; remote temporary-file cleanup belongs to
the existing transfer command where possible. Interrupted transfers can still
leave owned staging files for later reconciliation.

`egw clean` attempts local Appliance cleanup first, even if Bastion is unavailable.
It atomically claims expired, unclaimed requests before removing them, removes
eligible orphan cancels/old responses and retains fresh transfer chunks. Processing
files are deferred unless the supported local-journal protocol and an exclusive
session lease establish that no worker is running. Durable journals, agent
bundles and unrelated files are preserved. Output reports partial cleanup and
`deferred_processing`; a failed tier gives a nonzero exit code. It is not a blanket
spool deletion command.

The ViPNet adapter includes Mobile installation candidates and `info`, guarded by
exact configured version, architecture and trusted publisher matching. These are
probe candidates, not evidence that every Client version/driver/architecture is
qualified. No license, key import or provider installation is performed.

## Repeat a field measurement

Use a separate checkout/venv at the exact candidate commit and a private config.
Keep the existing support bridge available until acceptance and rollback have
been checked. The operator-run probe preserves each timing and stores no command
output, topology or credentials in its result receipt:

```sh
python3 scripts/qualification/field_probe.py \
  --egw /path/to/venv/bin/egw --config /path/to/enclave.yaml \
  --source-sha <full-tested-commit> --node app01 \
  --output /path/to/private/new-probe --samples 5 --parallel 4
```

`--copy-root /tmp` additionally writes, reads, verifies and deletes one uniquely
named synthetic TargetNode file; supply an approved scratch directory for that
OS. Earlier output is never overwritten. The declared commit is operator supplied;
the launcher's hash does not attest an installed package. Compare individual
samples and tails under the same RDP conditions. Do not infer WAN latency from a
local or delayed-loopback sample. Test tunnels, long transfers and controlled RDP
loss/recovery separately before replacing an operational bridge; this probe does
not disconnect a session or switch the environment automatically.
