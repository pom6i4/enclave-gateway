# Source-bound field acceptance

This register summarizes operator-supplied anonymized field reports. Each entry
applies to its exact source revision and the deployment profile described below.
The operator retains raw evidence in private storage. The public summary was
reviewed against the immutable source hashes; raw private logs were not
independently inspected for this record.

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
