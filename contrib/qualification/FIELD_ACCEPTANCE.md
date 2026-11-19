# Source-bound field acceptance

This register summarizes operator-supplied anonymized field reports. Each entry
applies to its exact source revision and the deployment profile described below.
The operator retains raw evidence in private storage. The public summary was
reviewed against the immutable source hashes; raw private logs were not
independently inspected for this record.

## Accepted release: Beta 7

- Result: **PASS / УСПЕХ**, as reported by the operator.
- Tested package: `0.3.0b7`.
- Tested tag: `v0.3.0-beta.7`.
- Tested release commit: `bcafbb1ae71bd044ed6ec4a8a0cf7fafbefd7f44`.
- Evidence provenance: the operator's completed release-specific field report.
- Installation identity: all 65 installed package files matched the exact tag.
  There were no content differences or extra package files.
- Published wheel SHA-256:
  `7b200c5459355d3d262be11ff3e5aa66b67a6c05f52d5870147ccfa4dad48ee8`.

The initial precheck found the previous `0.3.0b6` installation. The operator
explicitly installed the verified published Beta 7 wheel before testing and
restarted the full acceptance program. No mixed-version run was accepted.
Release checksums passed for all five entries in `SHA256SUMS`. Both CLI and
package metadata reported `0.3.0b7` from the working environment's installed
package without source-path overrides.

### Release deployment scope

- Host: macOS ARM64 with Python `3.14.5`.
- Appliance: Windows 11 ARM64 through QGA `109.1.0`.
- Route: approved VPN followed by domain RDP drive redirection.
- Bastion: Windows 10 x64 with a non-administrator domain operator session.
- Target: Linux x64 with Python `3.11.2` and the system OpenSSH forced-command peer.
- Protection: Kaspersky Endpoint Security for Windows `21.3.10.1001`.
- Security mode: `standard` with the existing approved unsigned-agent policy.
- Execution profile: `structured_only`.
- Structured backend: `operator`.
- Spool protocol: `stream`.
- Worker attestation: enforced and freshly verified.
- Heartbeat window: 300 seconds throughout the run.
- Advertised copy-step cap: 45 seconds.
- Whole-copy timeout: 1800 seconds.
- Foreground lease: eight hours with approximately 6.4 hours remaining at start.

All deployed adapter and Linux peer copies matched the public component hashes
in [Component identity](#component-identity). The reported supervisor resource
matched its public source hash. The configured adapter pin matched the deployed
bytes. Fresh attestation confirmed the loaded adapter and the approved policy.
The private policy digest and staging-bundle identifier are intentionally omitted.

There was no background supervisor on Bastion. During `heal`, the Appliance
executed `session_supervisor.ps1` once with `-ObserveOnly`. This acceptance does
not establish background supervisor restart or reconnect behavior.

### Release heal and clock measurements

Each of three consecutive `heal` calls returned `APPLIANCE_INIT_OK` and
`SESSION_ACTIVE` with the same worker instance. OpenSSH did not reconnect and
heartbeat continued updating. Each successful QGA clock sync was followed by
initialization with `HostEpochUtcMs 0`; the `Set-Date` fallback was not invoked.

Clock observations used QGA `guest-get-time` with five samples before and five
after each call. The operator also sampled immediately after QGA sync and after
Appliance initialization. Offset is remote UTC minus the Host request midpoint.
Durations used a monotonic clock. Uncertainty included at least half the RTT.

| Heal | Duration | Median offset before | Median offset after | Reported total uncertainty | Previous 1.6 s rollback |
| --- | --- | --- | --- | --- | --- |
| 1 | 3.72 s | -7.865 ms | +8.651 ms | ±41.828 ms | Absent |
| 2 | 2.98 s | +7.438 ms | +3.302 ms | ±87.643 ms | Absent |
| 3 | 2.28 s | +6.720 ms | +11.068 ms | ±74.621 ms | Absent |

The measurement uncertainty was sufficient to distinguish the historical
rollback. Direct millisecond Host-to-Bastion clock measurement was unavailable
through the restricted worker protocol. The domain time source was confirmed
separately. No Bastion clock-offset measurement is claimed.

### Release ordinary 128 MiB round trip

A new incompressible file generated with `os.urandom` completed the ordinary
cycle without fault injection. All three copies matched in size and SHA-256.
Both directions retained the same worker and exceeded the heartbeat window.

| Direction | Bytes | Data blocks | Duration | Attempt | Exit code |
| --- | --- | --- | --- | --- | --- |
| Push | 134217728 | 128 | 960.868 s | First | 0 |
| Immediate pull | 134217728 | 128 | 606.161 s | First | 0 |

The worker journal contained exactly 128 `push_part` entries plus one
`push_commit`. Pull contained one `pull_info` plus 128 `pull_part` entries.
Block offsets were unique. There were no duplicate publications or unexplained
indeterminate outcomes. Temporary upload parts were absent after commit.

### Release controlled QGA recovery

Isolated Host harnesses injected faults over the installed Beta 7 on the real
route. These results are separate from the ordinary transfer above.

- Lost initial sync reply: the first connection closed after 1001.54 ms.
  Synchronization recovered with one application `guest-exec` and the original
  deadline preserved.
- Lost accepted `guest-exec` acknowledgement: exactly one dispatch and one
  marker execution occurred. The result remained explicitly indeterminate at
  `control.receive` without command replay.
- Response-read timeout: one request publication and one upload-slot fill
  completed the 1 MiB test step with matching size and SHA-256.
- Response-read connection reset: observation resumed on the same response
  slot without request replay or upload refill. The original deadline survived.
- `worker_state.json` read timeout: observation continued without a false
  worker-unavailable result. One command executed and the worker was unchanged.
- Recoverable partial response erasure: the response was validated once.
  Cleanup resumed with the remaining 544-byte response range before releasing
  the upload slot. No request or payload was resent.
- Persistent response-erasure failure: the bounded cleanup attempt returned
  `worker_result_cleanup_failed` at `vfs.erase`. The operation was executed
  once. Its indeterminate journal entry and 416-byte nonzero response remained
  available for reconciliation.

Positive recovery checks preserved the original deadline. Read-side QGA polling
was distinguished from application-command execution. The two expected
indeterminate outcomes above belonged to deliberately injected faults and were
not ordinary transfer failures.

No accumulated production-orphan PID existed. A synthetic missing identifier
was checked against the real Windows QGA response `PID lld does not exist`.
The registry retained it on an unrelated access error and removed it on the
confirmed missing-PID result. Later calls made zero further queries for that
identifier. Subsequent raw guest execution succeeded without a false collision.
This is not acceptance of collecting previously accumulated production orphans.

### Release stop, cleanup and protection

- `agents stop --timeout 60` completed in 30.202 seconds with exit code zero.
- `WORKER_STOP_ACCEPTED` was followed by fresh `stopped` telemetry.
- The foreground worker exited and released its session lease.
- An exclusive lease open succeeded and no worker-held IPC handles remained.
- A subsequent observation after 12 seconds still showed a stopped worker.
- One `clean` call completed in 1.780 seconds with no errors.
- Cleanup removed 404 fully zeroed IPC files.
- Cleanup preserved the 416-byte nonzero response from the deliberate fatal
  cleanup test. There were no deferred removals.
- Durable journals and diagnostic indeterminate evidence were preserved.
- Synthetic test files were removed after integrity evidence was recorded.
- VPN and QGA remained available. The test worker was left stopped.
- KES retained 28 running protection components.
- Both observed Kaspersky event logs recorded zero new events.
- No protection exclusions or trust-policy relaxations were introduced.

### Release evidence limits

The public summary is based on the supplied operator report. Its underlying
receipts and raw logs remain private and were not independently inspected here.
The report identified no runtime defect or deployment regression after the
explicit pre-test installation correction. Injected failures do not establish
their natural occurrence during ordinary transfers.

Acceptance applies to this release on the exercised route and endpoint policy.
It does not qualify other KES versions or native helper distributions. It does
not establish Enterprise signing qualification. All actual environment
identifiers and private policy fingerprints are excluded from this record.

## Accepted source: 65e1fb9

- Result: **PASS / УСПЕХ**.
- Tested commit: `65e1fb9abf7a609955aa0dafabf42fdae47f096d`.
- Python package version: `0.3.0b6`.
- Installation identity: the report verified all 65 package source files against
  the exact checkout by size and SHA-256.
- Evidence provenance: the operator's final anonymized field-acceptance report.
- Related automated verification: [successful six-job source CI](https://github.com/pom6i4/enclave-gateway/actions/runs/44315961350).

### Tested scope

- Host: macOS ARM64.
- Appliance: Windows ARM64 controlled through QGA.
- Route: approved VPN connectivity followed by RDP drive redirection to Bastion.
- Bastion: Windows x64 with a non-administrator domain operator session.
- Target: Linux x64 through system OpenSSH and the Python forced-command peer.
- Protection: Kaspersky Endpoint Security for Windows `21.3.10.1001`.
- Security mode: `standard`.
- Execution profile: `structured_only`.
- Structured backend: `operator`.
- Spool protocol: `stream`.
- Adapter deployment: approved unsigned source with process-scoped `RemoteSigned`.
- Worker attestation: enforced with the configured identity and hashes.
- Heartbeat freshness window: 300 seconds.
- Advertised copy-step cap: 45 seconds.
- Whole-copy timeout: 1800 seconds.

The reported deployment preserved its existing protection policy and trust
configuration. These results qualify the exercised profile on this route.
Other endpoint policies and deployment profiles require their own acceptance.

### Component identity

The report matched the deployed agents to the accepted source. Source digests:

- `bastion_structured.ps1`:
  `9e74e6d3574be53610bdce46c4d8182036630fbf4455183219c97572bd25f046`.
- `operator_target.py`:
  `c311bc22e653e2a1c2453620d4055895e6820d42d2384ac9f05aa3bdcd8e580f`.
- `session_supervisor.ps1`:
  `6fe79d02e1402eb4e763b7146a17ff7bb7641fbabbeaa70b03504d0ac0affde0`.

The adapter source digest matches the structured example's `worker_sha256` pin
at the tested commit. Corporate signing requires a pin for the approved signed
bytes. The package version alone does not identify this accepted revision.

### Ordinary end-to-end results

One new incompressible file of **134217728 bytes (128 MiB)** completed the main
cycle without diagnostic fault injection. The same worker instance remained
active throughout push and immediate pull.

| Direction | Data blocks | Final auxiliary operation | Duration | Attempt |
| --- | --- | --- | --- | --- |
| Push | 128/128 | `push_commit` | 952.45 s | First |
| Pull | 128/128 | `pull_info` | 729.39 s | First |

All three copies matched in size and SHA-256. The upload's temporary parts
directory was absent after final publication. Both directions continued beyond
the 300-second heartbeat window. There were no duplicate step publications.

Further reported results:

- Known orphaned QGA PIDs were reaped and removed after the real
  `PID lld does not exist` response. Later calls stopped polling those PIDs.
- A subsequent direct `exec_guest` completed without a false PID collision.
- Three consecutive `heal` calls returned `APPLIANCE_INIT_OK` and `SESSION_ACTIVE`.
- Successful QGA clock synchronization passed `HostEpochUtcMs 0` to initialization.
- The previous approximately 1.6-second clock rollback did not recur.
- Worker instance identity survived all three `heal` calls.
- Stop completed in 33.37 seconds and released the worker-session lease.
- One `clean` call completed in 1.60 seconds and removed all 370 eligible zeroed
  IPC files. Three nonzero negative-test evidence files were preserved.
- Durable transaction journals were preserved.
- KES retained its active protection state and recorded zero new events.

### Controlled recovery and negative checks

Recovery checks used isolated Host harnesses on the real route. Their deliberate
faults are distinct from the ordinary 128 MiB transfer results.

| Controlled scenario | Reported result |
| --- | --- |
| Lost synchronization reply before dispatch | Recovered within the original deadline after closing the first connection in 1002.71 ms |
| Lost acknowledgement after `guest-exec` dispatch | No command replay |
| Response-read timeout | Recovered without request replay |
| Response-read connection reset | Recovered without request replay |
| `worker_state.json` read timeout | Response observation continued without a false worker-unavailable result |
| Disconnect after partial confirmed erasure | Only the remaining response range was erased |
| Request expiry | `deadline_exceeded` preserved unresolved evidence |
| Cancellation | `cancelled` stopped further polling |
| Missing test endpoint | `qga_unavailable` at `control.connect` before command dispatch |

Each controlled 1 MiB copy step had:

- One upload-slot fill.
- One request-frame publication.
- One worker execution.
- A matching destination size and SHA-256.

The partial-erasure check validated the complete response once. Recovery erased
only the remaining 544-byte response range before releasing the upload slot.

There were zero product failures in the ordinary or positive recovery scenarios.
The two `indeterminate: true` results belonged to the deliberate post-dispatch
expiry and cancellation checks. Both retained their unresolved frames as
required. There were no unexplained indeterminate outcomes.

### Evidence limits and final state

No natural QGA synchronization or read-retry events occurred during the main
copy cycle across 39527 reported QGA synchronizations. Recovery behavior was
exercised separately through the controlled scenarios above. A fatal erasure
failure was covered by unit tests; field checks exercised successful partial
erasure recovery without damaging working ACLs.

The operator reported the test worker stopped with its lease released. Temporary
test files were removed. Negative-test evidence and durable journals remained
available for reconciliation. No manual environment recovery was required.

This acceptance record does not change release tags or establish Enterprise
signing qualification. Requalify changed source or a different endpoint policy.

The public record omits:

- Environment addresses.
- Account identifiers.
- Private paths.
- Filled configuration files.
- Raw logs.
- Customer-specific artifact identifiers.

## Release mapping

`v0.3.0-beta.7` packages the accepted application code as Python version
`0.3.0b7`. The runtime source difference from the tested revision is the package
version declaration. All three agent scripts retain the hashes listed above.
Release build and installation checks are recorded separately in
`release-manifest.json`. The earlier field acceptance remains bound to `65e1fb9`.
The subsequent installed-release acceptance above binds the published Beta 7
wheel to `bcafbb1ae71bd044ed6ec4a8a0cf7fafbefd7f44`.

The GitHub Release includes a post-release `BETA7_FIELD_ACCEPTANCE.md` supplement
with its own `BETA7_FIELD_ACCEPTANCE.sha256`. The original six release assets
retain their published bytes. The original `FIELD_ACCEPTANCE.md` describes the
earlier source acceptance; its digest in the original manifest remains valid.
