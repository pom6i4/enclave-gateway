# Changelog

## Unreleased

### Configuration and security

- Validate lifecycle JSON with exact field types, unique keys, approved architecture
  values and bounded manifest size. Validate all configured actions before planning;
  reject malformed inputs before execution or local artifact hashing.
- Reject unknown VPN adapters during configuration loading and expose provider and
  lifecycle configuration in the offline summary.
- Add a private, read-only audit of stored Git blobs, commit metadata and historical
  paths, with explicit inventory-bound review of synthetic fixture findings.

### Operations and transport

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
