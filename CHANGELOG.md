# Changelog

## 0.3.0 Beta 6

Package version `0.3.0b6` and Git tag `v0.3.0-beta.6`.

- Preserve milliseconds when synchronizing the Appliance clock during `heal`.
  Accept Stream heartbeat timestamps up to five seconds ahead of the Appliance.
- Recommend a 35-second readiness window after the first OpenSSH attachment.

- Use the remaining dispatch budget for operator SSH requests and reserve
  local pipe time for a protocol v2 command timeout reply.
- Give `agent-verify --wait-ready` a separate readiness window and report
  startup expiry at preflight. Retry transient probes within that window.
- Start managed Appliances from `heal` and report unavailable QGA endpoints
  at connection. Preserve operator RDP sessions and existing staging by default.
- Print a shorter hash-verified Bastion copy command for explicitly approved
  unsigned deployments using `RemoteSigned`.
- The source adapter `bastion_structured.ps1` has SHA-256
  `26b759f3925b312cb11d484bb7f9b4a548be8ce8b387609ad697b7fb87b580a2`.
  Recheck the deployment pin against the approved bytes before staging.

## 0.3.0 Beta 5

Package version `0.3.0b5` and Git tag `v0.3.0-beta.5`.

- Allow an explicitly approved `bastion.operator_exec_max_sec` above the
  15-second default. A confirmed command timeout preserves the SSH session
  for subsequent requests and records the timed-out outcome as indeterminate.
- Stage the hash-verified Linux peer alongside the Windows adapter and print
  a local `attach-ssh.cmd` command for manual attachment in the same RDP session.
- Reclaim only zeroed operator IPC files on the Appliance after verifying the
  stopped worker and spool identity. Preserve interrupted transactions.
- Allow explicit QEMU control paths in a private managed runtime with
  `appliance.attach_only: false`. Existing external paths retain attachment
  semantics by default.

## 0.3.0 Beta 4

Package version `0.3.0b4` and Git tag `v0.3.0-beta.4`.

- Standard `operator` can run under a non-administrator Windows SID with an
  unsigned adapter when policy allows it. The controller requires exact
  adapter and policy SHA-256 pins, the operator SID and fresh attestation.
  Microsoft system OpenSSH still requires a valid Microsoft signature.
- The operator may own the pinned policy. Unapproved principals with write
  or ownership-changing rights are rejected. Signed `operator` deployment
  still validates the adapter's publisher.
- `egw agents stage` ships the Linux peer, prints a verified local copy command,
  and supplies the forced-command prefix for the dedicated target SSH key.
- The foreground lease defaults to eight hours and is configurable in
  `bastion.lease_seconds`. The IPv4 Appliance MTU defaults to 1200, and
  `egw doctor` compares configured and observed adapter MTU values.

## 0.3.0 Beta 3

Package version `0.3.0b3` and Git tag `v0.3.0-beta.3`.

- Add `egw cp --chunked` for the signed `operator` backend over Stream. Require
  attested `chunked_copy_slots_v1` to transfer files up to 512 MiB in 1 MiB blocks.
- Pipeline each upload block through a reusable slot into OpenSSH. Hold back
  the final byte until the block's SHA-256 matches. Read download metadata and
  bytes through one response handle. Publish only after whole-file verification.
- Keep the 15 s request limit and the 10 s attestation budget. `--timeout`
  sets the overall copy budget.
- On the isolated Windows Server 2022 x64 RDP lab under KES 14.1.0.423, the 3 MiB
  and 65 MiB round trips matched SHA-256. All 136 blocks met the 15 s limit.
  The slowest was 2.692 s, with zero new KES events and zero added exclusions.
  [Qualification scope](docs/ENDPOINT-POLICY.md#operator-backend-under-kes-141)
- The PowerShell-enabled suite discovered 329 tests. 313 passed and 16 were
  skipped. This release distributes source and Python packages.

## 0.3.0 Beta 2

Package version `0.3.0b2` and Git tag `v0.3.0-beta.2`.

- Add the opt-in `structured_only` operator backend for one Linux target.
  The operator starts system OpenSSH in the RDP session. A signed Windows
  adapter uses local named pipes, and a dedicated SSH key selects the Linux
  protocol peer.
- Add `stream_upload_v1` and bounded Deflate. For large raw attachments,
  overlap RDP reads with SSH writes and withhold the final byte until the
  complete SHA-256 matches. The Linux target verifies the staged file before
  replacing the destination.
- Qualify the operator backend on an isolated Windows Server 2022 x64 RDP
  route under KES 14.1. All 24 uploads of 1 MiB finished in 5.07–11.49 s
  within the 15-second limit, with matching SHA-256 and zero new KES events
  in the captured log. See the [test scope](docs/ENDPOINT-POLICY.md#operator-backend-under-kes-141).
- Document the operator setup and trust model in English and Russian.

### Earlier qualification and test fixes

- Qualify the published Beta foreground worker on native Windows Server 2022
  x64 under AllSigned, including current-SID credentials and wrong-SID denial.
  Keep the 15-second limits unchanged. This check covers the Beta 1 local spool.
- Accept the exact published Python wheel with fresh self-contained x64 helpers
  in a clean Windows Python 3.14.5 installation without an SDK.
- Remove and verify deletion of the local-spool fixture's nonexportable signing
  key as well as its temporary certificate trust.
- Make the portable replay test cancel only after observing its side effect,
  avoiding a cold-process startup race while retaining restart/replay checks.

## 0.3.0 Beta 1

Package version: `0.3.0b1`. Git tag: `v0.3.0-beta.1`.

The foreground `structured_only` profile is experimental. This Beta does not
certify KES compatibility. The published `v0.2.0` tag remains unchanged.

### Local endpoint qualification and Direct interactive SSH

- Add native interactive `egw ssh` for a Direct Host's explicitly approved SSH
  route. Preserve each jump's key and host-key checks without RDP fallback.
- Reject RDP-only SSH configuration export for Appliance SSH targets.
- Add a disposable Windows local-spool acceptance fixture with synthetic signing
  trust cleanup and a 15-second bound on each native credential request.
- Verify Windows ARM64 foreground startup under AllSigned and SID-bound
  Credential Manager writes. Test SYSTEM refresh for a different interactive
  user's SID with the native ARM64 helper within the existing 15-second cap.
- Exercise the signed foreground worker through actual RDP drive redirection to
  an isolated Linux OpenSSH server. Check binary transfers with SHA-256 and
  strict rejection of a changed SSH host key.
- Verify manual foreground restart after real RDP disconnect/reconnect with
  durable replay rejection. Check cleanup before and after acknowledged stop.
  Native Windows x64 and KES acceptance remain open for this profile.
- Add negative policy tests and durable replay rejection across worker restart.
- Send large Appliance PowerShell sources through QGA stdin to stay below the
  Windows command-line size limit while retaining separate request data.

### Explicit policy-approved routes

- Add `config init --route ssh` for an agentless Appliance SSH route.
- Resolve each configured SSH jump chain consistently in setup and execution.
  Report the route and disabled fallback in capabilities.
- Reject RDP operations when Bastion is disabled. Reject unavailable TCP mux
  before opening listeners. Do not stage workers or clean old RDP state in
  the agentless route.
- Keep diagnostics and repair grants scoped to the configured control hops.
  Provide separate SSH and RDP operator guides in English and Russian.

### Endpoint policy hardening

- Remove command-history suppression from worker execution and SSH wrappers.
- Carry legacy SSH credentials and stdin separately from PowerShell source.
  Reject mismatched older workers before launching SSH.
- Refresh Appliance RDP credentials through native Windows Credential Manager
  with SID-bound session selection and stdin-only input. Qualification is scoped
  to the tested Windows ARM64 environment.
- Add an offline autostart-removal command that preserves files and processes.
  Warn on opt-in persistence and bound repeated Stream recovery.
- Add an explicit signed foreground `structured_only` worker for direct Linux
  targets through system OpenSSH. It uses an independently approved local policy
  and supports Files without startup registration or AppData code installation.
  Enterprise process isolation is not claimed. Windows ARM64 RDP qualification
  does not establish KES approval or native Windows x64 acceptance.


## 0.2.0 Beta

The following earlier changes belong to the existing Beta baseline.

### Configuration and security

- Discover global/XDG configuration with explicit environment overrides; keep
  global audit, transaction state and optional environment files outside CWD.
  Add private `config init --global` and preserve explicit config precedence.
- Make dependency-free quoted YAML escapes consistent with PyYAML for Windows
  paths. Report missing SSH password helpers before remote execution; Standard
  key-only operation ignores an unused backup password without retrieving it.

- Validate lifecycle JSON with exact field types, unique keys, approved architecture
  values and bounded manifest size. Validate all configured actions before planning;
  reject malformed inputs before execution or local artifact hashing.
- Reject unknown VPN adapters during configuration loading and expose provider and
  lifecycle configuration in the offline summary.
- Add a private, read-only audit of stored Git blobs, commit metadata and historical
  paths, with explicit inventory-bound review of synthetic fixture findings.

### Operations and transport

- Wake Stream dispatch, response writers and response preparation when work
  arrives. Keep bounded queues and preserve durable transaction outcomes.
- Reduce short-command overhead by deferring unrelated CLI and transfer imports
  and writing SSH stdin directly while draining both output streams.
- Remove redirected-drive history scans/deletion from Stream startup and recovery.
  Prune retired heartbeats and empty response placeholders only in explicit local
  Appliance cleanup after a verified worker exit. Use exclusive handle-based
  deletion; preserve latest-instance files, nonempty outcomes, requests and links,
  and report deferred files and cleanup errors.

- Handle Windows PowerShell 5.1 tokenless RDPDR read cancellation during Stream
  recovery; retain the underlying exception and reject explicit token cancellation.
  Refresh existing per-user autostart without SACL privileges or empty-string
  backup paths in atomic file replacement.

- Recover Stream workers through the local bootstrap after classified redirected
  drive/handle failures, with capped backoff, supervisor singleton, rechecked
  trust and pinned durable storage. Preserve no-replay and normal stop behavior;
  retain obsolete endpoints for explicit Appliance-local cleanup.

- Add opt-in per-user Bastion autostart with verified local generations, retained
  security/protocol settings and one-time migration. Require explicit worker
  acknowledgement when removing its HKCU Run entry during graceful stop.

- Preserve authenticated POSIX cancellation acknowledgement when an already closed
  peer makes the client half-close report ENOTCONN; other errors still fail.

- Add opt-in bounded stream IPC over RDP drive redirection, with independent
  heartbeat publication, fair QGA access, committed response readback and logical
  erasure. Durable transaction outcomes and no-replay behavior remain authoritative.
- Stage verified agents and transaction journals locally on Bastion. Keep Standard
  runspaces separate from Enterprise signed native isolation requirements.
- Support explicit attachment paths for existing VM control endpoints, worker
  singleton/stop, safe generation pruning and allow-listed support snapshots.
- Report skipped cleanup after verified worker exit separately from actual remote
  cleanup. Allow WAN control budgets without changing latency acceptance limits.

### Public distribution

- Add a public local candidate assembly/verification command with exact source,
  build, schema and artifact acceptance bindings, complete checksum inventory,
  runtime notices and sanitized provenance. Hosted workflows are not required.
- Add offline installed-artifact acceptance on Windows x64/ARM64 and Linux,
  including SDK-independent native execution, filesystem/cancellation checks,
  read-only MCP denial and temporary laboratory signing with trust/key cleanup.

- Document first connection, six provider adapters, explicit lifecycle approval,
  SSH trust and Standard/Enterprise deployment boundaries.
- Add release preparation and component compatibility guidance. Keep unsigned
  reproducible artifacts, SBOM and lab qualification separate from production trust.
- Use SPDX license metadata and preserve the base interpreter in nested POSIX
  installation checks, including standalone Python 3.10.
- Classify SBOM runtime material by the delivered Windows targets; host-only
  runtime downloads remain excluded from the delivered dependency scope.

The package currently reports version `0.2.0` and Beta status. This section is not a
published release announcement. Choose the release version/tag and signing channel
as an explicit maintainer decision; artifact receipts bind the exact source commit.
