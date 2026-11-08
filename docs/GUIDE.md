# Engineer and administrator guide

English · [Русское руководство](ru/GUIDE.md)

Choose the administrator-approved route before connecting. See
[explicit SSH and RDP routes](ROUTING.md). `config init --route ssh` creates
an agentless starter; the default `--route rdp_vfs` retains the RDP workflow.
Failures never change transports automatically.

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

### Configuration discovery and private state

For an installed `egw` executable on PATH:

```sh
egw config init --global
# Edit ~/.config/enclave-gateway/enclave.yaml, then run from any directory:
egw config check
egw doctor --preflight
```

The search order is explicit `-c / --config`, `ENCLAVE_CONFIG`, `./enclave.yaml`,
`./config/enclave.yaml`, then
`${XDG_CONFIG_HOME:-~/.config}/enclave-gateway/enclave.yaml`. XDG_CONFIG_HOME must
be absolute; a relative value is ignored. An explicit/environment configuration
that does not exist fails instead of silently selecting another deployment.
`config check` reports `configuration_file`. A local config takes precedence over
the global one: use `-c` or `ENCLAVE_CONFIG` to pin the deployment when needed.

State selection is explicit `--state-dir`, then `ENCLAVE_STATE_DIR`. Otherwise a
selected global config uses its sibling `state/` directory for `audit.jsonl`,
`audit.transactions.sqlite3` and the optional `.env`. This also applies when that
global file was selected explicitly. No `logs/` or `.env` is created in the current
directory. Other configs retain their existing local state defaults; relative
paths inside a config still refer to the working directory. Use absolute paths
for a global deployment. The config file and state paths are not exported as
topology settings.

`config init --global` creates a private application directory (0700) and config
(0600) on POSIX, refuses overwrite and rejects linked private directories. An
explicit `config init --output ~/.config/enclave-gateway/enclave.yaml` has the same
protection. State directories use 0700; Windows deployments must also protect
their enclosing profile with the appropriate account ACLs. Store the optional
`.env` privately (0600 on POSIX); OS credential storage remains supported. Offline
`config check` does not create state. Secret commands can locate the selected
state without parsing a topology or contacting a remote machine.

Windows paths have the same bytes with or without the optional PyYAML dependency:

| Path | Plain YAML | Single quoted | Double quoted |
| --- | --- | --- | --- |
| Local | `C:\EnclaveGateway\spool` | `'C:\EnclaveGateway\spool'` | `"C:\\EnclaveGateway\\spool"` |
| Redirected | `\\tsclient\C\EnclaveGateway\spool` | `'\\tsclient\C\EnclaveGateway\spool'` | `"\\\\tsclient\\C\\EnclaveGateway\\spool"` |

Double quotes interpret YAML escapes such as `\\`, `\"`, `\n`, `\r`, `\t`;
escape every backslash there. Single quotes are literal, with `''` representing
one apostrophe. Invalid escapes fail instead of changing a Windows path.

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

## VPN providers (`provider.type`)

`provider.type` selects one registered adapter; unknown names fail during config
loading. `egw config check` reports `provider_type` and
`provider_lifecycle_configured`. The latter means a manifest path is configured,
not that its contents, executable or live VPN session have been accepted.

| Type | Installed-artifact probe and deployment boundary |
| --- | --- |
| `vipnet` | ViPNet Mobile binary candidates; `info` runs only after the configured publisher/version/PE architecture match. Qualify the actual Client edition, driver and route separately. |
| `kontinent` | No assumed binary path or proprietary status arguments. Supply approved artifact/service settings for the installed АПКШ Континент release. |
| `anyconnect` | Cisco Secure Client / AnyConnect `vpncli.exe` candidates and `vpnagent` service; qualified binary may run `state`. |
| `openvpn` | OpenVPN binary and service candidates; inspects artifact/service evidence without guessing a status CLI invocation. |
| `wireguard` | `wg.exe` and tunnel-service candidates; qualified binary may run `show`. |
| `custom` | Explicit `binary_path` / `service_name` when artifact evidence is needed, or an externally managed approved VPN connection. No inferred status command. |

For installed-binary qualification, configure `expected_publisher` with the exact
Authenticode certificate subject, `qualified_versions` with exact file-version
strings and `qualified_architectures` with the approved PE values (`arm64`,
`x86_64`, `x86`). `binary_path` overrides adapter candidates; `service_name`
overrides its service pattern. Status command execution requires a valid
Authenticode signature and all three configured matches. Empty lists or a missing
publisher leave the binary `unqualified`; they do not authorize execution.
`configuration_matched` is artifact evidence. Driver qualification remains
`not_verified`; a successful network probe proves reachability, not VPN identity.

### Optional approved lifecycle recipes

Use `egw provider --help` for `install`, `connect`, `disconnect` and `import_key`.
These operations require an explicit hash-pinned `lifecycle_manifest`; neither
ViPNet nor Континент management commands are inferred from a provider name.
Existing VPN connections require no lifecycle recipe for ordinary `exec`/`cp`.

[`config/provider-lifecycle.example.json`](../config/provider-lifecycle.example.json)
is a schema-valid **custom-controller illustration**, not a vendor procedure.
Its controller path, zero hash, example publisher/version, source URL and arguments
are deliberately fictitious. Replace them with an administrator-reviewed,
documented procedure before apply. Each step pins the executable's SHA-256,
Authenticode publisher subject, exact file version and PE architecture. Manifest
`versions` / `architectures` constrain those controller steps; they do not qualify
VPN drivers. Keep installers, profiles and key material outside the repository.

Configure a private copy using an absolute manifest path on the Host and its
reviewed SHA-256 (`python3 -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('/absolute/private/provider-lifecycle.json').read_bytes()).hexdigest())"`).
Add these fields to `provider` in your private configuration:

```yaml
provider:
  type: custom
  lifecycle_manifest: /absolute/private/provider-lifecycle.json
  lifecycle_manifest_sha256: '<reviewed-manifest-sha256>'
  lifecycle_inputs:
    installer: 'C:\EnclaveGateway\approved\installer.msi'
    profile_file: 'C:\EnclaveGateway\approved\profile.conf'
    key_file: 'C:\EnclaveGateway\approved\key-container.dst'
```

The placeholder digest must be replaced before planning. `lifecycle_inputs` are
literal paths on the Windows execution host (Appliance, or Windows Direct Host),
not automatically uploaded Host files. Only whole argument placeholders such as
`{installer}`, `{key_file}` and `{profile_file}` are expanded; embedded placeholders
or shell fragments are not evaluated. `source` records the approved procedure's
provenance; it is not downloaded or executed.

Manifests are limited to 1 MiB. Revision must be the integer `1`; versions and
architectures must be nonempty unique string lists, with architectures limited to
`arm64`, `x86_64`, `x86`. Duplicate JSON keys, non-finite values, unknown actions
and malformed steps are rejected, including steps in unselected actions. Each
action contains 1–16 steps. Runtime hash/signature checks still apply after a valid
plan; passing the schema does not authorize execution.

```sh
egw provider --help
egw provider connect
# Review the returned steps, artifacts and approval_digest, then explicitly apply:
egw provider connect --apply --approval-digest <reviewed-plan-digest>
```

Without `--apply`, the command plans only; there is no `--dry-run` flag. A plan
reads the local manifest and hashes configured local artifacts, but does not run
the controller or contact the VPN. Apply recomputes the plan and rejects a changed
digest before execution. Runtime checks still verify the actual executable's
hash, signature/publisher, version and PE architecture. Apply also requires an
approved signed `egw-runtime.exe` and its configured trusted signer, including
when the surrounding security mode is Standard. Planning the example successfully
does not establish that it can execute.

Optional `lifecycle_local_artifacts` maps `installer` or `key_file` to private Host
files for the matching action; `lifecycle_artifact_publishers` supplies the
installer's approved publisher. Planning includes their content hashes. Apply
stages them under transaction-specific names, verifies delivery and attempts
cleanup; inspect `cleanup_pending` before considering the operation complete.
Approved success codes can report `reboot_required`, but no automatic reboot is
performed. Hash/signature checks do not establish that a proprietary procedure is
safe for your version: qualify it separately, without sharing production keys.

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

In Standard mode, a configured `ssh_key_path` with no
`security.askpass_helper_path` selects key authentication with `BatchMode=yes`.
A backup `password_env` is reported as ignored and its secret is not retrieved;
there is no interactive password fallback. `sudo_password_env` remains independent.
`config check` and `doctor --preflight` warn about this combination. Password-only
authentication without a helper is reported as unready during preflight. To use
SSH passwords, configure an approved native `security.askpass_helper_path` on the
executing hop; its runtime trust checks still apply. `ssh-copy-id` password
bootstrap requires that helper too. Custom/Enterprise retain their authentication
and signature requirements. A configured helper path is not proof that its
remote executable is installed or trusted.

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
| `SESSION_PENDING_WORKER` / no fresh heartbeat | Verify UTC clock synchronization on the Host, Appliance and Bastion. Check drive redirection and run the command printed by `egw agents stage` inside the approved Bastion RDP session. |
| Script is blocked / ConstrainedLanguage | Obtain administrator approval under the actual endpoint policy; do not bypass it |
| Endpoint product detects or removes a worker | Stop requests and follow the [incident procedure](ENDPOINT-INCIDENT.md); preserve unresolved transaction records |
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
Overrides default to attachment. The owner launcher creates and cleans up those
external endpoints. To let `egw up` create a managed VM with custom filenames,
set `appliance.attach_only: false` and place all three endpoints directly inside
the private `appliance.runtime_dir`. Use distinct filenames. If an endpoint is
already occupied and does not belong to the expected running VM, inspect it before
retrying. Set `attach_only: true` to require attachment even with default filenames.

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

Startup flags apply to that invocation; `stage` does not persist policy or
migration choices for a later `agents command`. To regenerate a Standard startup
command with both approved options, use
`egw agents command --execution-policy RemoteSigned --migrate-legacy-state`.
The multiline command verifies hashes and copies the approved scripts locally;
paste and execute it as a complete block. Do not shorten it by removing checks.

Review and run the printed command once in the approved Bastion session. Migration
copies and flushes the legacy identities locally before publishing the binding,
leaves the originals intact and does not replay old requests. Unknown/incomplete
legacy files require reconciliation. Do not run the legacy worker again against
that spool after migration. An older backup or a snapshot rollback also requires
outcome reconciliation; journal identity alone does not establish backup freshness.
With managed signed `-RegisterStartup`, perform migration in foreground before
registering the task. The per-user option below can register and migrate during
one foreground invocation; subsequent starts do not migrate again.

`egw agents stop --timeout 45` requests an acknowledged graceful stop. It refuses
while jobs or mux connections remain active, and never kills an unrelated process.
Close those connections, let jobs finish and retry with a new operation. Its
`WORKER_STOP_ACCEPTED` receipt is an acknowledgement; observe stopped status before
starting the printed command again. A mutex and an exclusive spool session lease
reject duplicate workers. Reinstall/re-sign changed Enterprise scripts and update
approved pins before using them.

### Per-user worker autostart

Opt in when generating the command, then run the complete printed command in the
approved Bastion session:

```sh
egw agents stage --persist-autostart --execution-policy RemoteSigned
# For a one-time legacy upgrade, also add --migrate-legacy-state.
# To reprint, repeat the required flags with: egw agents command ...
```

The process-policy option is Standard-only and explicit; omit it when the
endpoint already permits the approved scripts or the package requires signatures.
Staging alone does not modify Bastion's registry. Bootstrap `-RegisterAutostart`
copies the verified generation into `%LOCALAPPDATA%\EnclaveGateway\autostart-agents`,
saves the bootstrap byte-for-byte as `start_worker.ps1` and atomically writes
`autostart.json`. Its protected local directory belongs only to the current SID
and SYSTEM. Settings preserve Files/Stream, state location, runtime, isolation,
signatures and publishers. Persistent starts verify both script hashes and never
save `-MigrateLegacyState` or an unsigned laboratory override. Authenticode and
Internet-zone alternate streams survive script copying. Signed/AllSigned starts
retain AllSigned; an explicitly selected Standard process RemoteSigned is retained
without overriding Group Policy. No SDK or native runtime is added for Standard
runspaces.

Only after the local files are prepared does bootstrap register
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EnclaveGatewayWorker`.
Individual files are published atomically; interrupted multi-file updates fail
hash checks and can be re-registered from the approved command. HKCU Run executes
at **user logon**, may be delayed by Windows and has a 260-character command limit
([Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)).
A normal RDP disconnect/reconnect is not a new logon trigger; leave the resident
worker running through disconnects. This registration is not a crash supervisor.
The existing singleton rejects duplicates. Managed Enterprise deployments can
use the signed scheduled task with its reconnect trigger described in SECURITY.md.

To decommission, while the worker is still running:

```sh
egw agents stop --unregister-autostart --timeout 45
```

The worker removes only its current user's `EnclaveGatewayWorker` value, confirms
`WORKER_STOP_ACCEPTED;AUTOSTART_UNREGISTERED`, then stops. An older worker lacking
that receipt cannot claim successful removal. Normal `agents stop` leaves
autostart enabled. If already stopped, remove that value in the Bastion user's
session (or restart the approved worker and use this command); the Host cannot
edit that user's registry through Appliance HKCU. Local generations and journals,
unrelated Run values and managed scheduled tasks are retained.

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

After a verified worker exit, `egw clean` skips remote Bastion cleanup and returns
`ok: true` when the Appliance cleanup succeeds. Its result explicitly says
`bastion_cleanup: skipped_worker_stopped` and `bastion_cleaned: false`: local
Bastion stage files have not been inspected. Verification requires the supported
storage binding and an exclusive session lease, not an absent or stale heartbeat.
Without that evidence an unavailable worker remains an error. Run cleanup before
stopping the worker when expired Bastion stage files also need inspection.

For Stream history, stop the worker first, then run `egw clean`. The Appliance
removes only old-instance heartbeat snapshots and zero-length response
placeholders, on its **local Windows filesystem** while holding the exclusive
worker session lease. The descriptor's latest instance is preserved, as are
nonempty `ipc_res_*` endpoints, old request streams, links and durable journals. Native
handle-based deletion checks file size and deletes the same object without a
close/reopen race. Locked files are deferred. The JSON details include
`stream_cleanup`, `stream_removed`, `stream_preserved`, `stream_deferred` and
`stream_error_codes` (counts by native error code).
Missing/invalid descriptors prevent Stream pruning; invalid descriptors or cleanup
errors fail visibly. Redirected/mapped network cleanup paths are rejected.

Doctor's worker/target probes and each active Bastion cleanup step allow up to
45 seconds. Mux open, I/O, half-close and close allow up to 60 seconds by default
(open keeps its existing five-second response allowance). Explicit caller budgets
and enclosing operation deadlines still apply. These are failure timeouts, not
performance acceptance thresholds; a slow successful probe is not a latency pass.
The short-command gate remains 800 ms. Select stream mode for its separate
heartbeat and request path; the compatible files protocol still performs costly
redirected metadata operations on WAN routes.

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

### Short-command latency over redirected drives

`bastion.spool_protocol: files` remains the compatible default. To evaluate the
persistent stream channel, select `bastion.spool_protocol: stream`, stop the old
worker, run `egw agents stage`, then start its new command in the Bastion session.
Host and worker must select the same protocol; readiness rejects a mismatch.
Stream mode requires direct file IPC through QGA or Windows Direct control.
It requires no compiler or additional executable in Standard mode. Enterprise
keeps its signed package, native isolation and fresh attestation requirements.

Stream mode keeps the redirected request reader open and publishes
heartbeats on a separate runspace. Short requests avoid directory enumeration,
claim renames and response renames. Up to four response writers create an
independent framed result for each transaction and close it before readback.
A bounded lookahead prepares up to 32 response handles before requests arrive;
up to four more can be delivering results. Request starts are aligned to 4 KiB
blocks, which select immutable response tickets without a separate Host counter.
The initial reserve is filled before readiness. Replenishment uses one
preparer while at least eight handles remain and up to four below that level,
so metadata preparation does not continuously compete with responses.
Preparation uses ordinary .NET APIs and never executes a payload.
[Windows QGA](https://github.com/qemu/qemu/blob/master/qga/commands-win32.c)
opens files with read sharing only, so a persistent redirected writer cannot
coexist with its QGA reader. Independent results also avoid repeatedly opening
an existing shared UNC file. The local durable transaction journal still
commits before execution and before response delivery. Concurrent Host processes
serialize complete request frames using a lock derived from the canonical QGA
endpoint. QGA calls use a FIFO thread gate so a hot poller cannot starve
other callers. A complete short reply is validated and both acknowledged spans
are erased within the same QGA synchronization. Legacy delivery keeps its
existing separate readback; no command or response validator is replayed.
Concurrent calls may share an in-flight readiness snapshot after checking its
absolute heartbeat expiry. The validated descriptor from that check is reused
within dispatch, and still compared with attested identity. The transport does
not cache completed checks; the existing engine readiness cache stays bounded
to one second. Attestation is independent.
Do not share one endpoint through independent remote socket relays.

Stream liveness uses alternating same-instance heartbeat snapshots. Status,
doctor and the session supervisor select the newest fresh snapshot, including
stopped snapshots. Readers reject foreign instances and prefer a readable stopped snapshot over
older or equally timed running data. A locked slot may leave the previous fresh
snapshot in use; heartbeat data remains a liveness hint, not proof of process life. `worker_state.json` is only a
startup/stopped compatibility marker in this mode; use `egw status` for live
telemetry. The configured heartbeat age limit is unchanged.

### Stream recovery after a redirected-drive disconnect

Run the worker through the staged **local bootstrap**. In Stream mode bootstrap
supervises recognized redirected-path/handle failures and waits with a capped
1/2/5-second backoff for the same spool and an exclusive session lease. It closes
the old instance before starting a new one, publishes a new descriptor and warms
its response reserve. The supervisor holds its own singleton throughout backoff;
a duplicate bootstrap is rejected. Direct invocation of `bastion_worker.ps1`
does not provide supervision. Re-stage and restart an older deployment to acquire
the new bootstrap; an already running older process is not patched in place.

Recovery requires the original Bastion-local durable journal. Its storage binding
is pinned from the failed instance; a missing/changed binding or local journal
fails closed. Migration is permitted only on the initial invocation. Before every
restart bootstrap checks unchanged worker bytes and the configured signature and
runtime requirements. `STREAM_RECOVERING` reports the failed phase and Win32 code;
it also retains the underlying exception type and message. Windows PowerShell
5.1 can report an aborted redirected read as a tokenless
`OperationCanceledException`; the Stream I/O handler classifies this as native
I/O cancellation (995). Explicit cancellation tokens do not authorize recovery.
The recognized codes follow
[Microsoft's error definitions](https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d).
Access denial, journal/policy/signature errors, singleton conflicts and exhausted
capacity are not generic retry conditions. Files mode retains its existing behavior.

Startup and recovery never enumerate or prune old IPC files over `\\tsclient\C`.
A fresh instance GUID provides an independent namespace, so retained old files
cannot collide with new endpoints. Pruning belongs to explicit Appliance-local
`egw clean` after a verified worker exit, not to a background redirected-drive
scan competing with command traffic. Nonempty responses, old request streams,
transaction records and unrelated names remain available for reconciliation;
they are not automatically resubmitted. Responses already logically erased may
have nonzero file length and are retained too. Plan retention/archival for this
evidence rather than deleting all `ipc_*` files during a live session.

An exchange interrupted by disconnect can still return an indeterminate outcome
or cancellation, even after the next command succeeds. Inspect the existing
transaction identity and reconcile external effects; recovery never replays the
payload. TCP/mux connections belonging to the old instance are closed and must be
reopened by their clients. Readiness/attestation and latency gates are unchanged.

A normal worker return, including `egw agents stop`, ends supervision. The
explicit `-StopFile` is also observed during backoff; use a local path when it must
remain available during drive loss. A Host stop RPC cannot cross an unavailable
channel. HKCU Run still triggers only at logon: a killed bootstrap, fatal policy
error or actual user logoff needs an approved start/logon or the managed task.
This is channel recovery within the existing session, not general crash supervision.

Each frame contains a delimiter, SHA-256 and Base64 JSON. Incomplete/corrupt
frames cannot execute. This checksum establishes completeness, not authenticity.
The request JSON limit is 1 MiB; select `files` before dispatching larger commands.
Responses above 32 KiB use the existing response-file delivery, without executing the
command again. There is no automatic protocol fallback after publication.
Each worker instance owns a new request endpoint and result namespace. The
request stream (including block padding) and total framed responses are capped at 64 MiB each,
including a 1 MiB reserve for stop, cancellation and attestation. Ordinary requests stop
before consuming this reserve; responses near capacity use response-file delivery.
The request stream therefore holds at most 16,384 minimum-size requests,
including reserved control blocks; larger requests consume more blocks. Successful
exchanges erase their own request/response spans before returning. Failed or
interrupted exchanges retain evidence for transaction reconciliation. Zeroing is
logical erasure, not a guarantee against filesystem snapshots or SSD recovery.

Stop the worker before archiving exhausted stream endpoints. Preserve the
Bastion journal and `worker_storage.json`: restarting must never reset replay
protection. `egw clean` is not an archive/reset command for stream endpoints.
An accepted stop is distinct from confirmed worker exit.

Measure the complete CLI invocation, including publication, result readback and
erasure, with a fixed safe output marker. Keep cold startup, warmed Standard,
Enterprise/native isolation, parallel load and large transfers as separate
cohorts. For a cold cohort, confirm worker readiness with a read-only check
and include the first TargetNode invocation. Record source hashes,
QGA/client/server versions, redirection direction,
network delay method and measured RTT. Compare a simple bridge on the identical
route; a delay per TCP `recv` chunk is not a fixed network RTT. LAN results do not
qualify customer WAN latency.

`scripts/qualification/latency_gate.py` accepts a receipt with a `scope` and a
`cohorts` mapping. Each cohort contains the complete list of
`{"elapsed_ms": 500, "ok": true}` samples. Run it with `--input receipt.json
--output gate.json`. Every cohort needs at least 30 samples, every sample must
succeed, and every sample must be at most **800 ms**. It has no threshold override
and refuses to overwrite earlier results. Preserve failed runs, including
observer/setup failures, separately from valid performance measurements.

On newer Windows clients, the first `.rdp` launch may ask for account-level
permission to open RDP files and a separate resource-forwarding confirmation.
Review the destination and publisher, and enable the requested **Drives**
forwarding for the spool. Unrelated WebAuthn/security-key forwarding is not
needed by egw. These prompts happen before the worker can see `\\tsclient\C`.

For a lab with two Windows guests, use independently installed or correctly
Sysprep-generalized images. Duplicate machine SIDs can cause RDP authentication
to fail even with the correct password. Keep Windows identity checks enabled;
see [Microsoft's duplicate SID guidance](https://support.microsoft.com/en-au/servicing/os/windows/docs/2025/10/kerberos-and-ntlm-authentication-failures-due-to-duplicate-sids).

## Managed endpoint policies

For an administrator-approved foreground worker without Bastion autostart or
custom executables, see [the endpoint-policy guide](ENDPOINT-POLICY.md).
The experimental `structured_only` profile in `0.3.0b5` rejects unsupported
operations and never falls back to the universal worker. Its
[Windows qualification scope](ENDPOINT-POLICY.md#qualification-status) is
separate from EDR approval and the portable interpreter tests.

### Operator-started OpenSSH on Bastion

If endpoint policy permits the operator to start the system OpenSSH client, use
the [Standard configuration](../config/enclave.structured.example.yaml)
for one Linux target and select this backend explicitly.

```yaml
bastion:
  execution_profile: structured_only
  structured_backend: operator
  spool_protocol: stream
  lease_seconds: 28800
```

Choose how to trust the adapter:

- With corporate signing, keep `security.require_signed_agents: true` and
  pin the signed file's hash and approved publisher. Put the approved file in
  `security.agent_package_dir`.
- Where endpoint policy allows unsigned adapters, set
  `security.require_signed_agents: false` and
  `security.enforce_worker_attestation: true`. Pin the script hash in
  `security.worker_sha256` and the operator's Windows SID in
  `security.worker_account`. `trusted_signers` can be empty. The system
  OpenSSH binary still requires a valid Microsoft signature.

1. Set `owner_sid` to the operator's SID and `operator_state_dir` to a local
   NTFS path in the approved policy. The file can live in a private operator
   profile directory or an administrator-managed directory. Limit policy
   writers to the operator SID, SYSTEM and Administrators. Verify the policy
   SHA-256 out of band and configure `bastion.worker_policy_sha256`. Verify the
   target host key in `known_hosts`.
2. Run `egw agents stage`. Deploy the staged `operator_target.py` in a
   root-managed directory on the Linux target, with Python 3.10+. Use
   `target_authorized_keys_prefix` with the helper path and dedicated public
   key in `authorized_keys`.
3. Run the staging receipt's `bastion_copy_command` in Bastion PowerShell.
   It verifies the policy, creates the state directory and copies the
   hash-verified adapter next to the policy. Then run `start_command`. If the
   unsigned adapter needs RemoteSigned, request it with
   `egw agents command --execution-policy RemoteSigned`. This applies to the
   current PowerShell process and respects Group Policy.
4. Open a separate CMD window in the same RDP session and run the OpenSSH
   command printed by the adapter.

```sh
egw agent-verify
egw exec app01 'uname -s' --timeout 15
egw cp ./hello.txt app01:/tmp/hello.txt --timeout 15
egw cp app01:/tmp/hello.txt ./hello-returned.txt --timeout 15
```

Ordinary `exec` and `cp` have a 15 s overall limit, including fresh attestation.
This profile has no interactive SSH or TCP proxy. The adapter exits if OpenSSH
disconnects. Reconcile unfinished transactions before restarting it.

The lease defaults to eight hours. `bastion.lease_seconds` accepts
60–86,400 seconds. On a managed Windows Appliance, `egw heal` applies the
IPv4 `appliance.mtu` (default 1200) and disables RDP over UDP. `egw doctor`
reports the configured value and compares it with the managed adapter MTUs.

For files up to 512 MiB, use chunked copy after `egw agent-verify` reports
`chunked_copy_slots_v1: true`. It transfers 1 MiB blocks, verifies SHA-256 on each
block and publishes the destination after verifying the whole file. Each
request is limited to 15 s. `--timeout` sets the total copy budget. Allow enough
time on the foreground lease to finish and stop the worker.

```sh
egw cp --chunked --timeout 900 ./artifact.bin app01:/tmp/artifact.bin
egw cp --chunked --timeout 900 app01:/tmp/artifact.bin ./received.bin
egw agents stop --timeout 15
```

[Deployment and recovery](ENDPOINT-POLICY.md#larger-files-with-the-operator-backend)
