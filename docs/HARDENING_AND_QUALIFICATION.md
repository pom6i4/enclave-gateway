# Operation safety and isolated qualification

The [functional follow-up](FUNCTIONAL_HARDENING_2026-10-31.md) extends scoped sync, lifecycle management, retention, process isolation and worker verification. This guide describes the baseline hardening implementation and its acceptance boundaries. The earlier [security audit](SECURITY_AUDIT_2026-10-31.md) remains a historical record. Hosted Actions are unchanged. No customer enclave, VPN credentials, key container, signing certificate or live RDP session is needed for the local checks below.

## Implemented contracts

| Area | Current behavior | Boundary |
|---|---|---|
| Qualification | Explicit interpreter matrix, real PowerShell worker on disposable files and loopback, Windows entry point, isolated VM seed generator | Preparing a seed or cross-compiling does not establish Windows/QGA/RDPdr acceptance |
| Transactions | Private SQLite journal, stable operation IDs, owner-scoped results, restart lookup, cancellation and expired-operation reconciliation | Ambiguous work is never automatically replayed; remote effects are not rolled back |
| Authorization | Authenticated principal → tools, nodes, file roots and destination CIDRs; tunnel ownership; filtered discovery | This is a service authorization boundary. Shell/SQL and shared worker accounts require separate trust decisions |
| Multiplexing | Asynchronous connect, bounded nonblocking socket turns, partial writes, separate EOF/half-close, bounded sessions | Disposable Windows and redirected-drive results are recorded below; deployment latency needs its own measurement |
| Deadlines | One monotonic budget across tracked nested operations, QGA polling, stripes and SSH stages; cancellation notifications can be read while stdio work runs | OS calls and bounded best-effort cleanup can outlive the foreground budget; guest/SSH descendant termination is not confirmed |
| Providers | Revisioned adapters, artifact/version/architecture/signature evidence, read-only public CLI only for explicit matches | No guessed proprietary import commands, automatic key import or driver qualification |
| Windows release | Native askpass, default signature/publisher enforcement, allow-listed package, signing/verification/install scripts | Build outputs remain unsigned; disposable lab trust/AllSigned checks are recorded separately from production signing |

## Durable operation identity

Tracked engine operations include command execution, file transfer/read/patch/sync, heal, clean and SSH key bootstrap. Nested stages share one operation ID and deadline; VFS requests retain separate phase IDs with an `operation_id` correlation field.

```sh
egw exec @appliance 'Write-Output fixture' --tx-id fixture-operation-001
egw transactions get fixture-operation-001
egw transactions list --limit 25
egw transactions cancel fixture-operation-001
egw transactions reconcile
```

Use the PowerShell command above only against a disposable Windows appliance. The `capabilities` command reports local capabilities without contacting an enclave:

```sh
egw capabilities
```

`--tx-id` is also supported by `cp` and `sync`. MCP tracked tools accept `tx_id`; `enclave_transaction` supports `get`, `list`, `cancel`, `reconcile`. CLI identity is `local`. Stdio identity is configured by the trusted launcher. HTTP identity comes from the matched bearer credential, never `actor`, a tool argument, a display name or a request header claiming a principal.

Reusing an ID with the same principal, operation and argument fingerprint retrieves the original retained outcome. A conflicting fingerprint or owner is rejected. IDs identify the original operation, not the current contents of a subsequently modified local source file. Use a new ID for new work. A running or indeterminate operation is never resubmitted as a retry. A failed command's retained exit status is also returned without replay.

States are `accepted`, `running`, `cancel_requested`, `completed`, `failed`, `cancelled`, `indeterminate`. `cancelled` before dispatch establishes that the tracked payload was not sent. After dispatch, timeout, transport loss or cancellation can yield `indeterminate`: an external process or side effect may remain. Reconciliation only marks expired unresolved rows indeterminate; it neither probes the remote system nor proves that it stopped. Cancellation is scoped to the verified owner and currently visible nodes.

MCP operation errors carry `code`, `stage`, `tx_id`, `node`, `retryable` and `indeterminate`. HTTP tool endpoints map operation failures to 422 and policy denials to 403; JSON-RPC exposes structured error data. Returned execution metadata includes `tx_id` and stage `timings_ms`.

The journal is adjacent to the audit log, with suffix `.transactions.sqlite3`. It uses SQLite transactions and `synchronous=FULL`; POSIX permissions are 0600. On Windows, put the audit/journal directory under a private user ACL. The journal retains scrubbed outputs, including file contents when read through the API, and hashes of arguments. Scrubbing cannot recognize every sensitive document: protect, back up and retain this database as sensitive local data. It is not an encrypted vault. Result payloads now have automatic archival/expiry limits; transaction identities are retained to prevent replay.

The worker flushes metadata/response temporary files before publication and leaves transaction tombstones across worker restarts. Responses are transient (five minutes); use the Host journal for retained results. The default worker capacity is 100,000 tombstones, after which new payloads fail before execution. Archive an old spool only after stopping its owned worker, resolving outstanding work and preserving the journal; start a distinct spool namespace afterward. Deleting tombstones and replaying old envelopes destroys duplicate protection. This is not a distributed exactly-once or power-loss qualification claim.

## Principal grants

Start from [the deny-by-default example](../config/access-policy.example.json):

```sh
egw mcp --policy config/access-policy.example.json --principal local
# viewer credential is resolved by name from the existing environment/vault:
egw mcp --policy config/access-policy.example.json --listen 127.0.0.1:8765
```

Each HTTP `token_env` names a distinct credential of at least 16 characters. The example contains no credential. Keep credential provisioning outside command history. The legacy single bearer maps only to the configured launcher principal. Without `--policy`, existing trusted-single-user behavior is retained; enabling a policy makes absent grants deny access.

- `tools`, `nodes`: explicit names or `*`. `@appliance` and `@bastion` are canonical reserved nodes. Read-only mode remains an additional restriction.
- `read_roots`, `write_roots`: remote roots keyed by node. `local_read_roots`, `local_write_roots`: Host roots for explicit transfer endpoints. Patch requires both remote read and write access. Internal disposable staging is not a user-selected export path.
- Remote paths must be absolute, without traversal, environment expansion, alternate data streams, reserved Windows device names or ambiguous trailing dots/spaces. File operations reject detected symbolic/reparse-point ancestors. Local containment resolves links before checking roots.
- Scoped directory sync uses the rooted regular-file protocol described in the functional follow-up. Trusted unrestricted sync retains the tar path.
- `destinations`: strict IPv4/IPv6 CIDRs. Scoped network endpoints require IP literals; arbitrary DNS resolution is not an authorization proof. Every proxy connection checks its captured grant in the listener thread. Scoped HTTP requests disable redirects. These are logical destination grants, not replacements for OS egress controls or a hostile remote account sandbox.
- `allow_arbitrary_exec`: required for shell and SQL. Those languages can access whatever the remote account can access, irrespective of structured file/network grants. Do not give this permission to an untrusted principal in a shared worker process. Use distinct OS accounts/processes and ACLs when principals need stronger isolation.
- `allow_root` permits explicitly requested elevated/destructive execution. `allow_cancel` permits cancellation/reconciliation of owned work. Tunnel list/stop is owner scoped.
- Status/doctor require Appliance and Bastion node grants because their probes access both. Target probes and SSH configuration are filtered by visible nodes. The shared audit is administrative and additionally requires `nodes: ["*"]`; it is not a per-principal audit store.

Ancestor checks do not eliminate a race with another privileged filesystem writer. The remote account/ACL must prevent an adversary from changing granted path ancestors during an operation. Do not claim these checks provide a filesystem sandbox against an administrator.

## Provider adapters

Adapters have an explicit revision and capability report. `vipnet`, `kontinent` and `custom` have no invented CLI or automatic binary discovery. Public WireGuard/AnyConnect status commands run only after all configured values match:

```yaml
provider:
  type: vipnet
  binary_path: ''
  qualified_versions: []
  qualified_architectures: []
  expected_publisher: ''
```

Populate those fields from separately approved installed artifacts, not from a guessed version or merely a familiar filename. Architecture matching uses the PE machine field; version matching is exact; publisher matching requires both an exact certificate subject and a valid Authenticode signature. A matching configuration remains distinct from functional driver/VPN qualification. Service/network observations are diagnostic evidence, not key import or tunnel acceptance. The earlier local checks used no provider or key. The separate Windows record covers a real WireGuard driver with newly generated disposable keys.

## Native credential helper and Windows release

`native/askpass` is a .NET 10 console application with no external package dependency. It reads only `EGW_ASKPASS_B64` from its inherited process environment, ignores the optional OpenSSH prompt, validates strict UTF-8 and a single nonempty line, writes one UTF-8 line, and exits 2 silently on invalid input. It does not read a password file or execute a shell. Its byte buffer is zeroed; managed strings/environment and privileged memory inspection are not eliminated.

The SSH wrapper uses a named mutex to serialize the process environment and restores prior values in `finally`. No temporary `.cmd` or `.ps1` password helper is generated. The configured helper must exist and, by default, have a valid signature from an explicitly configured signer:

```yaml
security:
  askpass_helper_path: '%LOCALAPPDATA%\EnclaveGateway\bin\egw-askpass.exe'
  trusted_signers: []
  require_signed_helpers: true
  require_signed_agents: true
```

`require_signed_agents` participates in running-worker verification when `enforce_worker_attestation` is enabled; use the release pins and strict profile settings described in the functional follow-up. The managed bootstrap enforces signatures independently. Use an approved Windows execution policy/WDAC/AppLocker deployment to enforce trust at the initial entry point as well; a script's own signature check cannot establish the trust of that script itself.

Build and package without accessing a certificate:

```powershell
./scripts/release/build_helper.ps1 -Runtime win-x64 -OutputDir ./build/askpass-win-x64
./scripts/release/build_helper.ps1 -Runtime win-arm64 -OutputDir ./build/askpass-win-arm64
python scripts/release/prepare_package.py --helper build/askpass-win-x64/egw-askpass.exe --runtime build/runtime-win-x64/egw-runtime.exe --output build/release-win-x64
```

The allow-list contains both native executables, four agents and verifier/installer scripts. Build the runtime component as described in the functional follow-up. The manifest explicitly says `unsigned` and `qualified_windows: false`. It does not sweep local directories for binaries, keys or environment files. Binary outputs stay ignored by Git. Use separate packages for the two architectures.

Only on a separate signing workstation, with its own code-signing certificate already available in the Windows certificate store:

```powershell
./scripts/release/sign_windows.ps1 -PackageDir ./build/release-win-x64 -CertificateThumbprint $thumbprint -TimestampServer $timestampServer -ReleaseSequence 1
./scripts/release/verify_windows.ps1 -PackageDir ./build/release-win-x64 -TrustedThumbprints @($thumbprint)
./scripts/release/install_windows.ps1 -PackageDir ./build/release-win-x64 -TrustedThumbprints @($thumbprint)
```

The operator must authenticate the installer/verifier entry point through the approved signing policy before running it. A thumbprint is a certificate identifier, not a request to export its private key. The signing script uses the store, SHA-256, timestamping and post-sign verification. Release metadata revision 2 additionally uses a detached SHA-256 CMS signature and per-installation release ordering; see [local acceptance and release policy](LOCAL_ACCEPTANCE.md) for the high-water mark, explicit rollback and revision-1 migration boundaries.

Install and activate as the same Windows account; each generation uses that SID and SYSTEM in its private DACL.

Installation stages a complete generation under `versions/<manifest-sha256>`, checks the copied package and deployed payload, and atomically selects it through `installation.json`. Existing concrete paths keep their previous generation. Read the returned `runtime_path`, `helper_path` and `agents_path`, explicitly update trusted configuration and release hash pins, then perform the approved startup and fresh attestation procedure. Initial installation also requires this configuration step. Legacy top-level files remain available during migration. Installation sets a private user/SYSTEM DACL without requesting SACL privileges; it does not launch agents, reconnect RDP or change VPN state.

Use the approved installer entry point for status, rollback and removal of abandoned staging generations:

```powershell
./scripts/release/install_windows.ps1 -Action Status -InstallDir $installDir -TrustedThumbprints @($thumbprint)
./scripts/release/install_windows.ps1 -Action Rollback -InstallDir $installDir -TrustedThumbprints @($thumbprint)
./scripts/release/install_windows.ps1 -Action Recover -InstallDir $installDir -TrustedThumbprints @($thumbprint)
```

Rollback verifies the previous generation before switching the selection. Corrupt installed files fail closed. These operations retain the explicit activation step and existing pins. Process interruption during staging is covered by qualification; a Windows power-loss durability guarantee is outside it.

The bootstrap forwards an explicitly selected `-RuntimeHelper` to immediate and registered startup and uses the absolute system PowerShell path. Relative runtime paths are resolved against the PowerShell working directory before persistence. UTF-8 persistent parameters live in `bastion_startup.json` beside the signed installed scripts; protect that directory with the account's private ACL. A SID-specific task with logon and remote-reconnect triggers uses `-UseStartupConfiguration`, the current user's interactive token, limited privileges, no stored password and an unlimited resident execution time. Duplicate task instances are ignored; registration restarts only that SID's managed task and returns `worker_health: requires_fresh_attestation`, without launching a second foreground worker. A successful registration removes the legacy Run value. Persistent startup waits up to 30 seconds for the redirected share. It accepts `-TrustedSignerThumbprints` (or `-TrustedSignerThumbprintsCsv` for a native startup command), keeps the redirected `SourceSpool` separate from the installed `WorkerPath`, and rechecks copied scripts before startup registration. `-AllowUnsignedLab` is only for disposable fixtures and is refused for persistent startup. Production signing and startup require their own acceptance; disposable Windows signing and startup checks are recorded separately below. Existing session credential-refresh behavior and broader endpoint execution-policy acceptance are outside this helper change.

## Reproducible isolated checks

The matrix runner uses the exact interpreter executables supplied; it does not install Python, change Actions or connect to configured appliances:

```sh
python3 scripts/qualify.py \
  --python /path/to/python3.10 --python /path/to/python3.11 \
  --python /path/to/python3.12 --python /path/to/python3.13 \
  --python /path/to/python3.14 --output-dir build/qualification/local
```

Every run retains logs, hashes and a source inventory in `matrix.json`. Optional local native tests can be enabled with `EGW_TEST_DOTNET` (dotnet executable), `EGW_TEST_HELPER` (built helper DLL) and `EGW_TEST_POWERSHELL` (PowerShell executable). Without them, the native/parser checks are explicitly skipped; a green core suite alone does not qualify those components.

Run the real worker without a VM, using only temporary files and loopback TCP:

```sh
python3 scripts/qualification/worker_loopback.py --powershell /path/to/pwsh \
  --transactions 10000 --output build/qualification/worker.json
```

It checks script execution, fairness under a slow read, binary bytes, half-close with delayed response, empty/exact/multiple/partial block files with Unicode/apostrophes, no replay after restart, cancellation, remote timeout, malformed input and connection refusal. The soak samples memory/threads and, on Windows only, handles. Post-warmup sampled growth limits are 256 MiB working set and 64 threads/handles; this finite workload is not proof of indefinite leak freedom. The fixture removes inherited credential-related variables, owns its worker/socket processes, and cleans up its disposable directory. It never uses the configured VPN, Bastion or customer environment.

Prepare a separate synthetic Windows seed without starting a guest or creating a disk:

```sh
python3 scripts/qualification/prepare_lab.py --arch x86_64 --output build/isolated-lab
```

It uses loopback endpoints, a custom provider with no installer/key, TCG configuration and separate ports. A licensed Windows ISO and matching VirtIO/QGA media must be supplied for an actual VM. Isolate the test guest from the client environment and use synthetic accounts. For real RDPdr acceptance, use a second disposable Windows session and redirected drive. Once inside that stand:

```powershell
./scripts/qualification/windows.ps1 -PythonExecutables @('C:\lab\py310\python.exe','C:\lab\py311\python.exe','C:\lab\py312\python.exe','C:\lab\py313\python.exe','C:\lab\py314\python.exe') -Transactions 10000 -RuntimeHelper ./build/runtime-win-x64/egw-runtime.exe -AllowUnsignedLab
```

The Windows runner records only the Windows-local test scope. QGA/RDPdr/driver qualification requires separate recorded evidence; it is not inferred from this command.

## Validation recorded locally

The committed procedure is independent of machine-specific executable paths and runtime reports, which stay under ignored `build/qualification`. See the [local qualification record](LOCAL_QUALIFICATION_2026-10-31.md) for exact versions and metrics. That earlier session used disposable local files and loopback. Its Windows status is historical; subsequent isolated Windows evidence is recorded separately below. Linux execution remains outside these records.

## Primary references

- [Python contextvars](https://docs.python.org/3/library/contextvars.html) explains context propagation primitives; executor tasks explicitly receive copies here.
- [Python sqlite3](https://docs.python.org/3/library/sqlite3.html) documents the SQLite interface and transaction controls used by the Host journal.
- [Socket.Poll](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.socket.poll) documents readiness checks used by bounded worker turns.
- [Set-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) documents Windows signing with a certificate and timestamp server; its availability does not establish a signed release.

## Signed disposable Windows checks

The [Windows lab record](WINDOWS_LAB_QUALIFICATION_2026-11-01.md) supersedes the earlier session's Windows status. It records each actual OS, architecture and acceptance boundary separately.

Use an isolated guest with synthetic accounts and a newly created lab code-signing certificate. Keep its private key inside that guest. Install the public certificate in that guest's trusted stores and sign the runtime and worker copies. Supply their exact hashes and signer to qualification; production signing and enterprise execution policy require their own evidence.

```powershell
./scripts/qualification/windows.ps1 -PythonExecutables @('C:\lab\python\python.exe') `
  -RuntimeHelper C:\lab\package\egw-runtime.exe -TrustedSigner '<lab-thumbprint>' `
  -Transactions 10000 -ExecEvery 10 -OutputDir C:\lab\results
python scripts/qualification/native_windows.py --runtime C:\lab\package\egw-runtime.exe `
  --trusted-signer '<lab-thumbprint>' --output C:\lab\results\native.json
```

`native_windows.py --time-scale 8` is available for explicitly labeled slow emulation (valid range 1..8, default 1). It scales only the fixture waits and its signature-stage cap; verification still cannot extend an active operation deadline. It does not establish normal timing acceptance. The optional parser fixture accepts `EGW_TEST_POWERSHELL_TIMEOUT_SEC` in 30..240 seconds, default 30.

`ExecEvery 10` reports 1,000 command executions and 9,000 mux I/O iterations for 10,000 iterations. The default remains command execution on every iteration. Functional cases also exercise a full uncompressed 4 MiB block, concurrent native launches and mux fairness. Reports retain the maximum command duration and resource samples. Failed runs retain worker logs, packet metadata and relevant durable transaction records alongside the report.

The transport accepts blocks from 1 byte through 4 MiB. Larger configured values are rejected because the nested Base64 request and native stdin envelope must remain within their limits.

For two pre-provisioned standard accounts, `scripts/qualification/windows_accounts.py --configuration C:\lab\accounts-fixture.json --output C:\lab\results\accounts.json` checks real SID launch, private file/environment denial, wrong-SID rejection, a 100 KiB SSH script and controller-tool denial. The protected fixture configuration references the broker policy, private environment, isolation map and each account's canary. Optional `sync` fixtures supply source/remote/received directories and expected file hashes within the granted private data roots; they test scoped push/pull, exclusions and preservation of extra destination files. The checker never creates accounts or changes their passwords.

`rdpdr.py` uses an already established redirected drive and a signed worker running in that Windows RDP session. Its protected configuration contains the host `spool`, guest `remote_spool`, dedicated guest `remote_dir`, unique `tx_id`, approved `worker_sha256`, `runtime_sha256`, `sid` and `signer`. The signed evidence must identify a redirected spool and a nonzero Windows session. Run the first phase with `--phase before --output build/qualification/rdp/before.json`; reconnect the disposable RDP session and restart its owned worker; then run `--phase after --output build/qualification/rdp/after.json` with the same configuration. It verifies a 4 MiB + 1 byte round trip, a changed worker instance and rejection of replay without repeating the marker side effect. The checker opens no login and consumes no credentials.

For bootstrap from a custom managed installation, pass `-RuntimeHelper` explicitly or place the runtime under the selected `InstallDir\bin`. Persistent startup records that exact runtime path and verifies its publisher before registration. Qualification tasks and startup entries belong only to the disposable lab account.

## Offline VM state and reproducible lab checks

Stop the VM before capturing or restoring state:

```sh
egw -c config/enclave.yaml down
egw -c config/enclave.yaml snapshot --name golden_ready
egw -c config/enclave.yaml reset --snapshot golden_ready
egw -c config/enclave.yaml snapshot --recover
egw -c config/enclave.yaml up
egw -c config/enclave.yaml profile create development --create-disk --output-dir build/profiles/development
```

Profile creation also requires a stopped source. A created profile uses an independent flattened backing bundle, its manifest digest, matching NVRAM and optional TPM state, its own runtime directory and planned ports. Startup verifies both the bundle and the overlay's actual backing file. Source-disk mutations cannot change that backing bundle. Generation without `--create-disk` is planning only and does not establish a captured base.

Bundles live in `appliance.snapshot_dir`, or beside the disk in `<disk-stem>.states`. They include a standalone qcow2 disk, firmware variable file, optional configured `tpm_state_dir` and a hash/size manifest. Architecture, firmware digest and resource kinds must match. Capture/restore holds a state lock, refuses a configured live VM/control endpoint and quiesces its managed TPM backend. Replacement stages each resource on its destination filesystem and records recovery intent before the first rename. Startup recovers an interrupted replacement before launching a guest. Unexpected mutation or corruption fails closed. Existing internal qcow2 snapshots remain in their original disk; use a newly captured complete bundle for the new reset procedure.

RAM, external services and host credentials are outside a bundle. Process-crash recovery does not establish an abrupt-power-loss guarantee, particularly across filesystems or on Windows without directory fsync. Managed `swtpm` launching/quiescence currently requires a POSIX host with `swtpm` and `swtpm_ioctl`. Software TPM state is separate from physical TPM attestation. Use short, private local runtime paths; Unix socket path limits also apply to the Windows Winsock adapter.

The public lab entry points consume explicitly identified disposable resources:

- `disposable_windows.py` creates a new private VM directory and runs actual `egw init` disk/media generation and detached installation. Supply licensed Windows, matching VirtIO/QGA media and firmware, with optional Secure Boot/software TPM. Machine-stage installation configures QGA without autologon; generated completion can run from its media or via QGA. The installer CD follows the system disk in boot priority, allowing an initially empty disk to fall through and later reboots to continue from the installed system. Seed media contains generated credentials and remains private. No proprietary provider is installed by this fixture. Official unsigned QGA MSI media requires explicit `egw init --guest-agent-sha256 <approved-hash>` approval; the disposable fixture pins its explicitly supplied file and records that identity. This verifies selected bytes, not publisher identity. Without a pin, the machine stage requires a valid Authenticode signature; invalid signatures fail even with a matching pin. Phase/failure records contain no setup passwords.
- During `specialize`, machine preparation defaults to a SYSTEM startup task that waits for Setup/OOBE completion, persists across setup reboots and removes itself after success. The explicit `--completion-mode SetupComplete` option stages a SYSTEM `SetupComplete.cmd` hook instead. QGA MSI installation and its VSS COM registration run after Windows Setup; no automatic logon is needed. An existing different hook is rejected for explicit integration. Windows Setup does not check hook exit codes, so acceptance requires the machine readiness record and actual QGA connectivity. [Microsoft documents](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-a-custom-script-to-windows-setup?view=windows-11) that OEM product keys disable this hook outside Enterprise and Server editions; the default startup-task mode avoids that hook dependency. Qualification of a particular OEM edition/licence remains separate from the mechanism.
- `windows_boot_media.py` can replace an ISO's existing EFI boot extent with that same ISO's vendor-provided `efisys_noprompt.bin`. It preserves the filesystem/catalog and validates the original extent; it does not disable Secure Boot.
- `vm_state_lifecycle.py --configuration <fixture.json> --output <new-directory> --guest-os windows --with-profile` runs public CLI lifecycle operations, checks every restored resource hash before boot, verifies persistent canaries and exercises an independent pinned profile. Input is `{"scope":"disposable-vm-state","config":<ordinary-config-object>}` with restricted networking. Linux mode uses `--guest-os linux`; its QGA clock operation requires the guest's `hwclock` utility.
- `windows_host.py` runs actual QEMU/TCG, QMP and QGA from an explicitly disposable Windows Host. The prepared guest needs an operational QGA and clock prerequisites. This is functional software emulation, without a WHPX timing or acceleration claim.
- `windows_upgrade.ps1` consumes two independently signed lab packages and a new workspace. It checks version switching, rollback, tampering, sharing/publication failure, a real child-process kill during staging, deployment exclusion and corrupt rollback refusal.
- `posix_accounts.py`, `posix_storage_faults.py` and `qga_faults.py` cover pre-provisioned Linux UID/SSH isolation, real ENOSPC/corruption and control interruption. The lost-ack case drops the real acknowledged PID before API delivery to its caller; it does not claim a wire-level packet-loss observer.
- `worker_faults.py` kills only its newly created signed worker after observing a real side effect, and separately corrupts an actual execution reply. Both cases require an indeterminate retained operation and reject replay.
- `rdp_transfer_fault.py` observes consumption of its own blocks through an already connected RDPDR share. Run `before`, disconnect only the disposable client after `ready_for_disconnect`, reconnect/restart its owned worker, then run `after`. A lost reply can follow a complete commit: acceptance permits a complete old or complete new destination, rejects a partial file and blocks replay. `expect_previous_target: true` additionally requires an observed early interruption to preserve the old generation. It opens no login and consumes no credentials.
- `long_soak.py` runs a finite 180..7200-second mixed workload with up to 128 fast and 32 silent streams, periodic file transfers/native commands and post-warmup resource bounds. A partial, stopped or failed run is not a qualifying pass.

These checks leave workflow configuration and hosted Actions unchanged. The separate [expanded qualification record](AUTONOMOUS_QUALIFICATION_2026-11-01.md) lists actual outcomes, source/evidence identities and remaining acceptance boundaries.

The subsequent [local acceptance and signed metadata guide](LOCAL_ACCEPTANCE.md) documents the installed-distribution check, plan runner, native trust readback, startup-task preparation and Windows TPM backend limitation.
