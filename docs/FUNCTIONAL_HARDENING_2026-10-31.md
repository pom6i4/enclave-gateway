# Functional hardening: remaining implementation work

This record describes the initial implementation. Subsequent actual Windows checks and fixes are recorded in the [Windows lab qualification](WINDOWS_LAB_QUALIFICATION_2026-11-01.md).

This change implements six additional mechanisms. Local checks and prepared Windows checks are listed separately below. It does not use a customer enclave, client key container, certificate private key, or a live client RDP/VPN session.

| Mechanism | Implemented interface | Configuration/deployment boundary |
|---|---|---|
| Provider lifecycle | `egw provider`, MCP `enclave_provider`: plan/apply installation, connect, disconnect and key import through approved versioned recipes | A real proprietary controller/CLI procedure must be supplied and approved for its exact version. No undocumented universal ViPNet/Kontinent CLI is claimed |
| Scoped directory sync | Descriptor-relative regular-file protocol, chunk transfer, hash verification and atomic file replacement | POSIX endpoint needs Python 3; Windows endpoint/Host needs the managed runtime. No symlinks, reparse points, hardlinks or special files |
| Owned command cancellation | Windows suspended creation + Job assignment before resume; private cancellation token; POSIX supervisor with private authenticated socket; separate SSH cancellation request | Stops owned process trees. Network loss, external service actions and prior side effects remain indeterminate; no rollback guarantee |
| Journal retention | Automatic payload archival/expiry, archive integrity checks, age/count/byte limits and permanent idempotency tombstones | Identity capacity is finite; a full namespace fails before new dispatch. Expired results never cause replay |
| Principal isolation | One backend process and OS account per principal; UID drop on POSIX, token/SID-checked Windows logon; private configuration/state/environment | Dedicated standard service accounts and private ACLs must be provisioned. This is an optional deployment mode, not an automatic migration of existing sessions |
| Running worker verification | Fresh challenge, exact worker version/hash, startup/current signature evidence, immutable SID and runtime hash/model checks | Requires release pins and a protected control channel. This is application evidence under a trusted OS, not TPM attestation against a compromised administrator |

## Scoped sync

With a path-limited grant, `node_sync` uses `rooted-files` instead of remote tar extraction. It merges directories and replaces individual files atomically; it does not delete extra destination files or commit the entire tree atomically. Each copy verifies the source manifest hash before replacement. POSIX executable permission bits are retained without setuid/setgid bits. Temporary file names belong to one operation; cleanup never removes unrelated files.

POSIX operations use open directory descriptors, `openat`-style operations with `O_NOFOLLOW`, single-link regular-file checks and directory-relative rename. Windows uses `NtCreateFile` relative to directory handles, opens reparse points themselves and rejects them, enumerates through handles, and renames relative to the retained destination-directory handle. Root directory identities and OS account/ACL boundaries must be protected from an administrator moving or replacing them.

The protocol limits each block to 192 KiB and enumerates at most 10,000 entries. Excluded subtrees are skipped before file reads. Case/Unicode-equivalent path collisions are rejected for cross-platform consistency. File data is passed through stdin; large scripts do not need to fit Windows command-line argument limits. Missing dependencies and unsupported filesystems fail closed.

## Journal storage lifecycle

Example configuration:

```json
{
  "journal_retention": {
    "max_age_seconds": 604800,
    "max_results": 10000,
    "max_payload_bytes": 67108864,
    "archive_seconds": 7776000,
    "max_archive_bytes": 536870912,
    "interval_seconds": 60,
    "max_identities": 1000000
  }
}
```

`egw transactions maintain` explicitly runs maintenance. MCP `enclave_transaction(action="maintain")` additionally requires `allow_cancel` and all-node administrative visibility. Foreground completion also enforces payload count/byte limits, while time-based maintenance is periodic. Archive files are private, contain a SHA-256 in their reference and are validated before hydration. POSIX modes are 0700/0600; Windows deployment needs a private user ACL.

Payload limits count UTF-8 bytes. Maintenance pages through metadata and loads only evicted payloads, one at a time. Archive batches are limited to 256 records or approximately 8 MiB of payload, with a single larger historical record preserved as one batch.

Live rows are retained. The state and identity of an indeterminate operation are retained even after detailed error payloads expire. A concise indeterminate reason remains in the primary journal. A completed operation with an expired or unavailable result returns `result_expired`/`archive_unavailable`; it is not rerun. Archive corruption is not interpreted as permission to retry. Cleanup/maintenance failure does not overwrite an already committed command outcome. SQLite may retain reusable free pages; these limits govern retained payloads/archives, not a guarantee that a previously oversized database immediately shrinks on disk.

The worker's separate 100,000-record tombstone capacity remains explicit. Host result retention does not delete worker duplicate-protection identities. Never clear a live namespace to make an ambiguous request run again.

## Provider management

`config/provider-lifecycle.example.json` is a schema example with deliberately unusable hashes/version/publisher. It is not a vendor procedure. Select a trusted local manifest in the provider configuration:

```yaml
provider:
  type: custom
  lifecycle_manifest: /etc/enclave-gateway/provider-lifecycle.json
  lifecycle_manifest_sha256: '<SHA-256 of the reviewed manifest>'
  lifecycle_inputs:
    installer: 'C:\EnclaveGateway\stage\provider.msi'
    key_file: 'C:\EnclaveGateway\stage\fixture.dst'
    profile_file: 'C:\EnclaveGateway\profiles\fixture.conf'
    tunnel_name: fixture
  lifecycle_local_artifacts:
    installer: /srv/egw-artifacts/provider.msi
    key_file: /srv/egw-private/fixture-container
  lifecycle_artifact_publishers:
    installer: 'CN=Approved installer publisher'
```

Paths and values here are examples. Local artifacts are read only when the selected action explicitly uses configured staging: installer for `install`, key container for `import_key`. There is no default discovery or reading of existing client keys. Planning hashes configured artifacts without including their contents in output. Applying rechecks the plan, transfers to unique operation-owned paths, verifies transfer hashes and installer publisher, then runs the controller. A changed artifact causes approval/hash rejection. Temporary upload cleanup is reported; `completed_cleanup_pending` is not presented as complete cleanup.

```sh
egw provider install
# Review the complete plan, then use its approval_digest:
egw provider install --apply --approval-digest <reviewed-digest> --tx-id install-fixture-001
```

Each recipe step pins the executable hash, exact Authenticode publisher, file version and PE architecture. Arguments are fixed strings or whole approved input placeholders. Passwords are resolved by `stdin_env` from the backend vault and sent through stdin, not command-line arguments. Controller stdout/stderr is suppressed from lifecycle responses; status and reboot-required flags are returned. MSI controller recipes must include `/norestart`. The gateway does not invoke a reboot; an approved controller contract must also suppress reboots/external asynchronous effects as appropriate.

Provider management requires `allow_provider_management` plus the Appliance node/tool grant. Dry planning contacts no remote system. Apply requires the plan digest and a stable operation ID is supported. A success exit code establishes only the controller-reported result; functional tunnel/driver/provider acceptance is separate. The generic recipe executor covers all four actions but does not manufacture undocumented proprietary CLI support. No real provider installation, connection or key import was exercised here.

## OS account and process isolation

Trusted-single-user behavior remains available. Use `egw mcp --isolation-map /etc/enclave-gateway/isolation.json --policy /etc/enclave-gateway/broker-policy.json` for untrusted principals. Bind HTTP locally or use an approved authenticated transport deployment.

Example POSIX mapping (accounts must already exist):

```json
{
  "principals": {
    "alice": {
      "identity": "uid:2001",
      "python": "/opt/egw/bin/python3",
      "config": "/etc/enclave-gateway/alice/config.json",
      "policy": "/etc/enclave-gateway/alice/policy.json",
      "state_dir": "/var/lib/enclave-gateway/alice"
    }
  }
}
```

The broker needs the OS privilege to create the selected account process. It clears supplementary groups and does not copy arbitrary broker environment/secrets into workers. State, environment/vault file, operation journal, tunnels and cancellation routing belong to the selected profile. A child startup handshake must match identity/configuration; no automatic replay or worker restart is performed after an interrupted request. For Windows, configure `identity: "sid:<actual SID>"`, `username`, optional `domain`, `password_env`, signed `runtime_helper`, its `runtime_sha256`, and `trusted_signers`. The broker pins the helper before delegating any login credential. The helper verifies the logon token SID before process creation, rejects administrative/service-system accounts, loads the private user profile and creates a non-inherited environment. The broker requires the Windows token/profile/service-session privileges for this operation; account creation and privilege/ACL provisioning are deployment steps, not performed by this change.

Use dedicated service accounts. API users receive MCP credentials, not the service account's OS login credentials. Accounts and writable VM disks/control endpoints, remote Bastion SIDs/spools, SSH target accounts, backend policies and private state directories cannot be shared between principal profiles. Controller identity is pinned by SID, never display name. Backend policy permissions must match the broker grant for exactly one principal. Arbitrary broker secrets are not inherited by the child. Host file endpoints in untrusted mode stay under that profile's `state_dir/data`.

Example tool/node relationship:

```json
{
  "tools": ["node_exec", "node_read_file", "enclave_status", "enclave_agent", "enclave_transaction"],
  "nodes": ["@appliance", "@bastion", "app01"],
  "tool_nodes": {"node_exec": ["app01"], "node_read_file": ["app01"]},
  "allow_arbitrary_exec": true,
  "read_roots": {"app01": ["/srv/app/logs"]}
}
```

`tool_nodes` restricts the global node set for that tool. Diagnostic controller visibility does not grant controller shell/file access. Strong untrusted profiles require explicit target-only node-operation grants when controllers are visible, reject controller write roots/unrestricted paths and sudo/root grants, and require pinned worker/runtime hashes, trusted signers, mandatory worker verification and owned SSH commands. Dedicated non-administrative SSH target accounts are required. `allow_repair` separately permits heal/clean/doctor fixes; a diagnostic grant alone cannot mutate controller settings.

Distinct accounts protect principal boundaries under the configured OS/ACL policy. Arbitrary execution intentionally grants the remote account's capabilities. This is not a container, kernel exploit boundary, defense against an administrator, or a guarantee against all resource exhaustion. Correct OS provisioning, protected software/configuration and target account permissions remain necessary.

## Cancellation and worker evidence

Windows runtime modes are `fs`, `run`, `run-as`, `cancel`. Command processes are created suspended, assigned to a Job with kill-on-close and no breakaway flags, then resumed. Both foreground timeout and normal completion dispose owned job state; a cancellation token can be sent over a separate SSH request. POSIX execution uses an account-private Unix socket and process group, with `WNOWAIT` to avoid reusing a reaped PID as a kill target. Inconclusive stop acknowledgement is reported conservatively. Cancellation cannot roll back completed writes, stop an external installer/service action, or be delivered through a broken network; such operations retain indeterminate status.

Windows worker payloads use separate native-owned processes by default. The portable runspace mode exists for local qualification/trusted compatibility and is reported as `runspace-lab`; strict verification rejects it. Signature verification itself runs in a read-only runspace so OS trust/revocation checks cannot block mux socket dispatch. Requests carry expiration deadlines and expired queued requests are refused before dispatch.

Configure `security.worker_sha256`, `worker_version`, `worker_account` (SID), `runtime_sha256`, `trusted_signers`, `enforce_worker_attestation: true`, `require_process_isolation: true`, and `owned_ssh_commands: true` for strict profiles. Signed-file hashes come from the final signed package, not an unsigned source hash.

`egw agent-verify` / MCP `enclave_agent` validates a fresh random challenge, exact version/hash, startup/current signature identities, immutable SID and loaded/current runtime digest and execution model. Responses explicitly list which checks were verified. A tracked operation verifies once, then binds every request and response to that verified worker instance/hash; standalone mux polls use a two-second verification lease and the same binding. The worker refuses a mismatched request before payload dispatch. An instance change aborts without replay. This avoids rehashing a large native executable for every data block. Cached heartbeat metadata is not a substitute. This verifies application evidence over the approved control channel under the OS/account trust assumptions above; it does not provide hardware-backed attestation of a hostile OS.

## Build and qualification

```powershell
./scripts/release/build_helper.ps1 -Component runtime -Runtime win-x64 -OutputDir ./build/runtime-win-x64
./scripts/release/build_helper.ps1 -Component runtime -Runtime win-arm64 -OutputDir ./build/runtime-win-arm64
python scripts/release/prepare_package.py --helper build/askpass-win-x64/egw-askpass.exe --runtime build/runtime-win-x64/egw-runtime.exe --output build/release-complete-x64
```

The complete package requires both executables. Sign/verify through the existing Windows release scripts; neither certificates nor signing services are contacted by building. The package remains unsigned until that separate step. Deploy native runtime files on the Windows Host/Appliance/Bastion/SSH endpoint where the relevant operation runs. POSIX SSH endpoints require Python 3 with process/socket primitives. No insecure fallback is used if a required helper or trusted release pin is missing.

Run `scripts/qualify.py` with explicit Python paths and optional real PowerShell/.NET fixture variables as documented in the main guide. In a separate disposable Windows lab, run `python scripts/qualification/native_windows.py --runtime <built-exe> --allow-unsigned-lab --output build/qualification/native-windows.json` to exercise rooted file operations and retain a real descendant handle across Job cancellation. This fixture does not qualify signing. No Windows execution or cross-account logon qualification has been claimed from a macOS cross-build.

The previous [local qualification record](LOCAL_QUALIFICATION_2026-10-31.md) describes the earlier commit. The [functional qualification record](FUNCTIONAL_QUALIFICATION_2026-10-31.md) describes this change. Current per-interpreter source/log hashes and final worker evidence are retained locally under `build/qualification/autonomous-*`. Hosted Actions and its billing/remediation are unchanged. No installation, account creation, signing, deployment or tests were performed in the client environment.

## Primary API references

- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) and [CreateProcessAsUser](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
- [NtCreateFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile), [FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info), and [CreateEnvironmentBlock](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createenvironmentblock).
- [Microsoft installer options](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options). Public vendor procedures must be assessed separately for the chosen product/version.
