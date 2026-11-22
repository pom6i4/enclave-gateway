# Changelog

## Unreleased

Working package version: `0.4.0rc4`. No release is published by these changes.

- Record **PASS / УСПЕХ** for the local RC4 upgrade and rollback cycle against
  exact `v0.3.0`. The same SQLite journal retained completed outcomes, archived
  results and indeterminate states through the downgrade and return to RC4.
  Repeated MCP requests caused zero additional dispatches. The `v0.3.0` schema
  rejected RC4 chunked requests before dispatch. Field RDP reconnect remains
  open. See the
  [local rollback receipt](contrib/qualification/LOCAL_ACCEPTANCE.md#local-rollback-between-v030-and-040rc4).
- Record operator-reported **PASS / УСПЕХ** for exact installed RC4
  `a46529825a87e80e6e218d39cfa2a40089d5fb68`. First-attempt 128 MiB MCP push
  completed in 944.574 seconds. Pull completed in 366.294 seconds. All three
  copies matched in size and SHA-256. Each ledger contained 129 completed
  copy records with no repeated data offsets. Fresh MCP sessions returned
  retained outcomes without new copy dispatch. Clock checks passed. Worker
  stop released the lease without respawn. Protection remained active with
  zero new reported events. See the
  [RC4 field record](contrib/qualification/FIELD_ACCEPTANCE.md#accepted-transfer-verification-040rc4).
- Close the RC4 round-trip field gate for the exercised Standard operator route.
  Retain historical failed attempts without attributing their physical cause
  to the local QGA slow-reader defect. Document the remaining
  [stable 0.4.0 gates](docs/STANDARD_OPERATOR_040_READINESS.md).
  Preserve candidate manifests and all original artifacts. No runtime or
  package-version change accompanies this documentation update.

- Bound each QGA binary-response poll to 64 KiB so a later wire-read timeout
  cannot discard an entire accumulated MiB. Retain the decoder cursor across
  polls. Require EOF before erasing a complete binary response. Preserve the
  original step deadline and all receipt checks without replaying requests.
- Add a local 128 MiB MCP pull regression with delayed visibility at block 30
  and a slow QGA reader. Verify failure on the previous implementation and
  completion after the correction. Reject trailing data and untrusted receipts.
  Add an allow-listed last-read outcome to distinguish open failures from
  interrupted reads without exposing raw QGA errors.
- Record incomplete RC3 field acceptance. The 128 MiB push passed. Pull stopped
  after 29 verified MiB with no response bytes for block 30. Saved diagnostics
  report no QGA read timeout, so the local slow-reader defect does not establish
  the cause of that field stop. Preserve the original candidate artifacts.

- Recover one transient timeout of periodic Standard operator copy attestation
  with a new read-only challenge. Each challenge retains its ten-second budget.
  The original part deadline still bounds both checks and data publication.
  Preserve nonce verification and pinned identity checks. Never replay a copy
  request or continue on stale evidence. Add safe attestation attempt counters.
- Reproduce the RC2 field stop after 38 verified MiB through the local MCP and
  QGA file algorithms. Verify a complete 128 MiB synthetic upload after recovery.
  Verify bounded failure without part 39 or commit when fresh verification fails.
  The physical cause of the real-channel response delay remains unresolved.
- Record operator-reported **PASS / УСПЕХ** for clock verification of exact
  candidate `18b43df51ca7360534447bde67953a819e5cb8cc`. One `heal` corrected a
  −17539 ms Appliance offset. Independent checks immediately afterward and at
  60 seconds and 300 seconds passed the ±2000 ms interval gate. The final
  reported offset was −3 ms. Worker identity and RDP continuity were preserved.
  Acknowledged stop took 40.84843 seconds without respawn. Protection remained
  active with zero new events. Preserve incomplete 128 MiB acceptance and the
  original candidate artifacts. See the
  [clock field record](contrib/qualification/FIELD_ACCEPTANCE.md#accepted-clock-verification-040rc2).
- Prepare a distinct unpublished clock candidate from committed source.
  Bind its wheel to the candidate manifest and fill the operator prompt from
  that manifest. Preserve the original RC1 bundle and stable release artifacts.

- Sample implicit QGA clock-setting timestamps after control-lock acquisition
  and stream synchronization. Verify QGA-backed `heal` with a read-only guest
  time bracket after initialization. Report offset uncertainty and fail the
  clock gate instead of treating a command acknowledgement as measured success.
  Preserve explicit timestamps and avoid automatic time-setting retries.
- Record a successful bounded 8 MiB diagnostic pull on the original RC1.
  Preserve incomplete 128 MiB acceptance. Verify the reported clock arithmetic
  without attributing the observed drift to the newly identified clock defect.
- Record **INCOMPLETE / ПРОВЕРКА НЕ ЗАВЕРШЕНА** for installed candidate
  `a8d9cf0fa60219220e5363d33bd2423ec90e2818`. One 128 MiB push completed;
  none of six pulls completed. Reconcile exact failed offsets with worker
  records. Preserve passed diagnostics and no-replay checks without claiming
  a completed round trip or an established code defect.
- Withdraw the unsupported 25-minute idle-policy diagnosis. Reconcile historical
  development block 74 from the raw ledger and exact request identity.
  Add partial-frame recovery regressions through the QGA file algorithms.
  Verify late/stopped-worker outcomes preserve the destination and reject replay.
  Add a bounded reverse-path investigation prompt before another full field run.
- Prepare an unpublished Standard operator candidate with bounded copy progress
  and Host-side read timings. Retain observations with success and error results.
  Preserve original observations when a transaction is queried again.
- Add local late-read and late-download regressions without extending deadlines
  or replaying requests. Add an offline ledger-offset analyzer. Keep effective
  RDP policy and historical counter reconciliation as external evidence gates.
  See [transfer diagnostics](docs/MCP_TRANSFER_DIAGNOSTICS.md).

- Record operator-reported functional **PASS / УСПЕХ** for installed development
  commit `363d8f72dc2c3ab1eebf9d60a3a95215cba468b3`. Fresh MCP initialization and
  a 128 MiB round trip passed. Completed and interrupted transaction checks
  showed zero new copy-dispatch after MCP restart.
  The round trip passed on attempt four; three failed pulls remain recorded.
  The successful run used external test activity; its causal benefit is unproven.
  Raw ledger review distinguishes 75 records from 74 pull parts and establishes
  the failed wait at offset 76546048. The earlier block-123 annotation is incorrect.
  The measured 61.7018-second file-timestamp interval is not network RTT.
  This does not establish unattended
  reliability or authorize stable promotion. See the
  [development field record](contrib/qualification/FIELD_ACCEPTANCE.md#accepted-development-block-040dev0).
- Add explicit MCP `node_transfer` chunked mode through the existing operator
  copy engine. Add a whole-copy timeout with bounded numeric validation.
  Ordinary copy remains the default. Unsupported chunked routes fail closed.
- Preserve copy authorization and stable transaction results without replay.
  Add MCP wrapper coverage for a 128 MiB round trip and ambiguous completion.
  Add an opt-in worker/peer pipe fixture for the same MCP transfer size.
- Automate fresh installed stdio MCP acceptance against the exact wheel.
  Isolate configuration and inherited environment. Verify a Python audit I/O
  guard before initialization. Require version agreement and clean EOF shutdown.
- Expand source and installed-package CI to Python 3.10 through 3.14 on all
  three hosted operating systems.
- Add a post-0.3.0 roadmap and select the stable release as the next candidate's
  upgrade/rollback baseline. Historical acceptance remains unchanged.

## 0.3.0

Package version `0.3.0` and immutable tag `v0.3.0` at
`29dad2ea643e5eed7fffc1a795827aa485ab1b85`.

- Record successful local verification of installed `0.3.0` and a fresh stdio
  MCP server. All 65 runtime files matched the published wheel.
  `initialize` reported `serverInfo.version: 0.3.0`. Local smoke checks passed.
  Operating-system network denial kept the check isolated from the real enclave.
  The test process exited through stdin EOF with code zero.
  Existing IDE sessions were untouched.
- Close the release cycle for the accepted Standard operator scope.
  Broader platform and profile qualification remains separate.
  The tag and original release assets remain unchanged.
- Record post-release operator-reported **PASS / УСПЕХ** for installed `0.3.0`
  under KES `21.3.10.1001`. All 65 runtime files matched the release.
  First-attempt 128 MiB push took 996.247 s. Immediate pull took 688.846 s.
  All three copies matched size and SHA-256. Three `heal` calls retained the
  worker and synchronized clock. Stop released the lease in 32.223 s.
  No new indeterminate outcomes or KES events were observed.
  See the [installed v0.3.0 record](contrib/qualification/FIELD_ACCEPTANCE.md#accepted-installed-release-v030).
- Publish source and Python artifacts for Standard operator.
  Post-release documentation supplements preserve the original asset bytes.
- Record operator-reported **PASS / УСПЕХ** for `0.3.0rc1` at
  `33fbcdecfba01ea8ed995379d39d8bc49886f706` under KES `21.3.10.1001`.
- Verify actual RDP disconnect/reconnect with the same Windows session.
  The old worker exited. A new manual attachment passed fresh attestation.
- Confirm no repeated effect through the Host journal and independently through
  the durable worker ledger for completed and interrupted transaction IDs.
- Verify Beta 7 to RC upgrade and explicit rollback without journal loss.
  Final worker stop took 27.584 s. Protection stayed active with zero new events.
- Preserve all agent bytes and worker attestation version `0.3.0`.
  Final runtime differs from the accepted RC only in its package version.
- Retain platform qualification limits and source-bound acceptance records.
  See the [RC acceptance record](contrib/qualification/FIELD_ACCEPTANCE.md#accepted-candidate-030rc1).

## 0.3.0rc1 — unpublished Standard operator candidate

- Prepare a source/Python candidate for the Standard foreground operator scope.
  Beta 7 field acceptance remains bound to its original release.
- Preserve agent bytes and the worker attestation version `0.3.0`.
  The only runtime source change from Beta 7 is the package version declaration.
- Correct security guidance for negotiated 45-second copy steps. Older adapters
  retain their 15-second budget.
- Define separate RDP reconnect and upgrade/rollback acceptance gates.
  Add an anonymized operator prompt without private deployment identifiers.
- Keep stable promotion pending exact-artifact checks and remaining acceptance.
  No release tag or package publication is implied.

## 0.3.0 Beta 7

Package version `0.3.0b7` and Git tag `v0.3.0-beta.7`.

This source/Python prerelease packages the application code field-accepted at
`65e1fb9abf7a609955aa0dafabf42fdae47f096d`. Runtime source differs only in the
package version declaration. Agent scripts and protocol identities are unchanged.

- Record post-release operator-reported **PASS / УСПЕХ** for installed `0.3.0b7`
  at `bcafbb1ae71bd044ed6ec4a8a0cf7fafbefd7f44` under KES `21.3.10.1001`.
  All 65 installed package files matched the release. First-attempt 128 MiB
  push took 960.868 s. Immediate pull took 606.161 s with matching SHA-256.
  Three `heal` calls preserved the worker and QGA-synchronized clock.
  Controlled recovery verified no application-request replay. Stop released
  the lease in 30.202 s. Protection remained active with zero new KES events.
  See the [installed Beta 7 acceptance record](contrib/qualification/FIELD_ACCEPTANCE.md#accepted-release-beta-7)
  for injected indeterminate outcomes and measurement limits.

- Record successful operator-reported field acceptance of
  `65e1fb9abf7a609955aa0dafabf42fdae47f096d` under KES `21.3.10.1001`.
  A 128 MiB push completed in 952.45 s on its first attempt. The immediate
  pull completed in 729.39 s on its first attempt with matching SHA-256.
  Controlled QGA recovery preserved one request publication per copy step.
  See the [anonymized acceptance record](contrib/qualification/FIELD_ACCEPTANCE.md#accepted-source-65e1fb9)
  for scope and evidence limits.

- Recover transient Stream response-read failures within the original request
  deadline. Bound QGA polling exchanges and retry synchronization before dispatch.
- Retry only confirmed zeroing after a cleanup disconnect. Release upload slots
  after a verified block acknowledgement and preserve unresolved payloads.

- Recognize the Windows and numeric QGA missing-PID errors when retiring orphan
  observations. Preserve unresolved PIDs on unrelated control errors.
- Observe Stream metadata with write/delete sharing and bounded retries during
  `heal`. Preserve typed heartbeat timestamps and stopped-pulse precedence.

- Bind PowerShell QGA results to a fresh invocation marker. Drain timed-out
  process records on later launches and reject unresolved raw-command PID
  collisions without replaying commands.
- Retire stopped operator publication metadata even after large transfers.
  Reclaim up to 4096 scrubbed IPC files in one local maintenance pass while
  retaining payloads and transaction evidence.
- Report worker control-observation errors separately from missing heartbeats.
  Give Doctor's operator snapshot reads a 15-second observation budget.

- Allow deletion sharing in structured readiness snapshots. Retry transient
  publication with bounded backoff and rewrite transient state in place when a
  reader blocks replacement. Durable transaction records keep atomic publication.
- Wait for stopped operator telemetry and worker-lease release after stop
  acknowledgement. Report pending shutdown when the total stop budget expires.
- Negotiate 45-second chunked-copy steps with the matching adapter and Linux
  helper. Between steps, cache readiness for up to 15 seconds and attestation for
  30 seconds, retaining identity checks and the total deadline. Refresh Pulse
  while waiting on a long copy operation.
- Preserve successful QGA clock synchronization through Appliance initialization.
  Recommend a 60-second readiness window for cold RDPDR startup and poll once per
  second while waiting.
- Recognize Windows OWNER RIGHTS and inherit-only CREATOR OWNER policy ACLs
  when the owner is approved. Reject third-party directory and file writers
  during both policy installation and subsequent adapter copies.
- Accept up to five seconds of Bastion clock lead throughout heartbeat checks,
  including repeated reads during chunked copy. Cap cached freshness at one
  heartbeat window from the read.
- Retry transient spool publication with delete-and-move when RDPDR rejects
  replacement. Keep durable journal publication atomic. During operator staging,
  retire stopped-session IPC and telemetry under the exclusive worker lease,
  retaining payloads and transaction evidence.
- Remove stale operator launchers before system OpenSSH signature verification.
  Show verification progress and `OPERATOR_ATTACH_READY` after publication.
- Select native system OpenSSH from both 32-bit and 64-bit CMD consoles.
- Explain password-based sudo through `--secret-env` and `sudo -S` over stdin.
- Source adapter SHA-256 for `security.worker_sha256` is
  `9e74e6d3574be53610bdce46c4d8182036630fbf4455183219c97572bd25f046`.
  Recompute the deployment pin after signing the approved adapter.

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
