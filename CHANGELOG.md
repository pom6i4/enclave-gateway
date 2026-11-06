# Changelog

## Unreleased

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
  with SID-bound session selection and stdin-only input. Windows acceptance of
  this operation remains pending.
- Add an offline autostart-removal command that preserves files and processes.
  Warn on opt-in persistence and bound repeated Stream recovery.
- Add an explicit signed foreground `structured_only` worker for direct Linux
  targets through system OpenSSH. It uses an independently approved local policy
  and supports Files without startup registration or AppData code installation.
  Enterprise process isolation is not claimed. Real Windows/RDP/KES qualification
  remains pending; portable tests do not establish endpoint approval.


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
