# Source-bound field acceptance

This register summarizes operator-supplied anonymized field reports. Each entry
applies to its exact source revision and the deployment profile described below.
The operator retains raw evidence in private storage. The public summary was
reviewed against the immutable source hashes. Except where an entry explicitly
records a later saved-evidence review, underlying private logs were not
independently inspected.

## Accepted transfer verification: 0.4.0rc4

- Result: **PASS / УСПЕХ** for the reported transfer program.
- Exact source: `a46529825a87e80e6e218d39cfa2a40089d5fb68`.
- Installed package: `0.4.0rc4`.
- Wheel SHA-256:
  `a8697dee4e8ff770ae8ffa79d9a89ffba4ac5f965fc66d2d49014d03d8b682fd`.
- Worker attestation version: `0.3.0`.
- Adapter SHA-256:
  `9e74e6d3574be53610bdce46c4d8182036630fbf4455183219c97572bd25f046`.
- Release status: unpublished candidate.

This entry records the operator-supplied anonymized report. Its package
identity was independently compared with the retained candidate manifest and
wheel. Underlying deployment traces were not independently inspected for this
entry. Raw evidence remains private. Deployment identifiers are omitted.
Private policy hashes are omitted. Staging-bundle identifiers are omitted.
Synthetic payload hashes are not reproduced; their reported equality is retained.

### Installed identity and operating conditions

The operator verified the bundle checksum set before installation. The offline
candidate verifier passed without Python optimization. The installation was
noneditable. All 65 runtime files matched the wheel with no extra runtime files.
The owned stdio MCP server reported `serverInfo.version: 0.4.0rc4` and protocol
`2025-03-26`. Fresh worker attestation verified the pinned adapter. It advertised
`chunked_copy_slots_v1: true` and `operator_copy_max_sec: 45`.

The exercised route used the Standard operator profile through QGA and RDP to
one approved Linux Target. No agent restaging was reported. Existing protection
remained enabled. Network policy was unchanged. No supervisor was started.
No synthetic user input was used. Foreign processes were untouched. No new
RDP disconnect event was reported during the transfers or repeat window.

The whole-copy budget was 1800 seconds per direction. The client budget was
2400 seconds per call. The outer observer budget was 7800 seconds. The original
45-second step cap was retained. Automatic client retries were disabled.

Reported read-only clock intervals remained inside the ±2000 ms tolerance.
The final atomic sample reported an offset of −329 ms. Its lower bound was
−330 ms. Its upper bound was −328 ms. Reported uncertainty was 1 ms.
`host_clock_stable` and `verified` were true. This is a read-only clock gate;
it does not repeat the separate RC2 clock-repair program.

### First-attempt 128 MiB transfers

The source contained 134217728 bytes of synthetic, practically incompressible
data. Pull started only after push completed and the Target file was checked
independently. Both operations used explicit chunked mode without root access.

| Observation | Push | Pull |
| --- | ---: | ---: |
| Attempts | 1 | 1 |
| Client monotonic duration, seconds | 944.574 | 366.294 |
| Verified data blocks | 128 | 128 |
| Verified bytes | 134217728 | 134217728 |
| Copy request publications | 129 | 129 |
| Completed worker copy records | 129 | 129 |
| Repeated data offsets | 0 | 0 |
| Highest step duration, ms | 16798 | 7020 |
| Attestation attempts | 28 | 12 |

Both Host journal outcomes were `completed`. Both destinations were committed.
Independent checks reported equal sizes and SHA-256 for all three copies.
The final response-read outcome was `complete` in both directions.

The offline ledger analyzer reported 128 unique push parts and one push commit.
Pull had one metadata request and 128 unique pull parts. There were no missing
data offsets. There were no failed copy records. No indeterminate copy record
was reported for this program.

The raw diagnostic objects omitted `attestation_retries`. They omitted
`read_timeouts`. They omitted `connection_losses`. No corresponding fault was
reported. Missing fields are retained as absent observations rather than
invented measurements. This program does not exercise those recovery branches.

Pull reported 8482 response-read API calls with 6305 empty observations. Their
difference is 2177: one metadata response plus 17 data-bearing API calls per
block. The final call also performs the separate EOF observation internally.
That internal read is not an additional `response_reads` increment. These
counters do not independently measure RDP write latency.

### Retained outcomes after MCP restart

The operator renamed both owned Host files so their original paths were absent.
The Target file remained unchanged. The first owned MCP server closed through
stdin EOF with exit status zero. A fresh server reopened the same journal
namespace under the same principal and initialized as `0.4.0rc4`.

Each original call was repeated once with its unchanged transaction identity
and original arguments. New JSON-RPC message identities were used. Both calls
returned their retained result with unchanged diagnostics. The absent source
was not required. The original download path was not recreated.

The operator reported zero new copy dispatches in the repeat window. The worker
ledger gained no copy records. Relevant spool observations were unchanged.
Flight-recorder observations were unchanged. Journal update timestamps were
unchanged. Target file metadata was unchanged. Equal payload hashes alone are
not used as the no-replay proof.

### Stop and preservation

Acknowledged worker stop completed in 29.97657 seconds with exit status zero.
The reported worker state was fresh `stopped` and its exclusive lease was free.
The follow-up observation after 10.5 seconds found no respawn. Endpoint
protection remained active with zero new reported events. No residual owned
MCP process was reported. No owned transfer remained active.

Only this program's synthetic files were removed after reconciliation. Global
spool cleanup was not run. Historical indeterminate transactions were retained.
Journal integrity verification passed. The rollback wheel remained unchanged.
The original RC4 bundle remains immutable with field acceptance still marked
pending in its build-time manifest. This separate record supplies the later
field outcome; it does not rewrite the old manifest or checksum set.

### Acceptance boundary

This closes the 128 MiB round-trip gate for the exact RC4 on the exercised
Standard operator route. It does not establish the cause of the earlier RC3
block-30 delay. Historical failures remain recorded. One successful cycle does
not establish indefinite unattended reliability or another deployment cohort.
Actual RDP disconnection and reconnection were not exercised by this program.
Preserving a rollback wheel does not prove an executed rollback. Remaining
stable-promotion gates are tracked in the
[0.4.0 readiness review](../../docs/STANDARD_OPERATOR_040_READINESS.md).

## Incomplete transfer verification: 0.4.0rc3

- Result: **INCOMPLETE / ПРОВЕРКА НЕ ЗАВЕРШЕНА**.
- Exact source: `2558e125df2f8d8ddd5748c920753da5961aea7e`.
- Installed package: `0.4.0rc3`.
- Wheel SHA-256:
  `df5ee88d1d7031b9f3bfdedbaa43fda56d68b5a34d05a6818e7b41d478b21986`.
- Worker contract version: `0.3.0`.
- Adapter SHA-256:
  `9e74e6d3574be53610bdce46c4d8182036630fbf4455183219c97572bd25f046`.

The operator reported an exact noneditable installation with all 65 runtime
files matched to the wheel. An owned fresh MCP server initialized successfully.
The saved structured report was inspected alongside the matching worker ledger.
Raw evidence remains private. Deployment identities are omitted. Private policy
hashes are omitted. Staging-bundle identifiers are omitted.

The first 128 MiB push completed in 1019.6634 seconds. All 128 data parts were
verified and the destination was committed. The ledger contained 128 unique
data offsets and one commit. There were 30 attestation attempts with no retry.

Pull stopped after 29 verified MiB at offset 30408704 while waiting for data
block 30. Elapsed whole-copy time was 261.8697 seconds. The last step reached
45001 ms against its 45000 ms cap with zero response bytes. The error was
`worker_response_timeout` at `vfs.response`, with an indeterminate outcome.
The ledger held one metadata request and 30 completed data requests. The exact
inner request identity matched block 30. Its SSH reply took 372 ms with exit
status zero. There were seven attestation attempts with no retry.

Completed worker records precede response publication. They do not prove
delivery to Host. The saved diagnostics reported no read timeout or connection
loss. The earlier empty-read counter also included response-open failures;
it cannot distinguish missing files from exclusively held slots. No retained
per-read trace resolves that boundary. A separately reproduced QGA slow-reader
defect includes local read timeouts and is not an established field cause.

RDP continuity was reported throughout. After a fresh owned MCP session, the
same push transaction returned its retained result. The same indeterminate
pull transaction was rejected without another copy dispatch. The destination
was not committed. No new worker copy records appeared in the repeat window.
The worker stopped normally in 32.18034 seconds without observed respawn.
Endpoint protection remained active with zero new reported events. The RC3
attestation-retry branch was not exercised. Full round-trip acceptance remains
incomplete. The original RC3 bundle is preserved without modification.

## Accepted clock verification: 0.4.0rc2

- Result: **PASS / УСПЕХ** for the clock field program.
- Exact source: `18b43df51ca7360534447bde67953a819e5cb8cc`.
- Installed package: `0.4.0rc2`.
- Wheel SHA-256:
  `6828c271a91a0305dd0413aa094ebdc36d297d6d43e94c2aa05030cfe6416871`.
- Worker attestation version: `0.3.0`.
- Adapter SHA-256:
  `9e74e6d3574be53610bdce46c4d8182036630fbf4455183219c97572bd25f046`.
- Required 128 MiB round-trip acceptance: **INCOMPLETE / ПРОВЕРКА НЕ ЗАВЕРШЕНА**.

This entry records the operator's anonymized field report. The package identity
matches the retained private candidate manifest. The underlying deployment logs
were not independently inspected for this entry. Raw measurements remain in
private storage. No deployment identities or private policy hashes are published.
Staging-bundle identifiers are omitted.

### Installed identity and preconditions

The operator verified the manifest and bundle checksums before installation.
The offline candidate verifier passed without Python optimization. All 65
installed runtime files matched the exact wheel after a noneditable update.
There were no unexpected runtime files. `QgaClient.guest_clock_status()` was
present. A fresh owned stdio MCP server reported `serverInfo.version: 0.4.0rc2`.
Existing IDE processes were untouched.

An online SQLite backup passed its integrity check before the update. The
working journal namespace was preserved. No older database was restored over
new transactions. Approved deployment pins were retained without restaging.
Appliance network settings already matched the approved configuration before
the full `heal` call. Bastion kept its domain time source. No synthetic input
was used. No background supervisor was launched.

### One heal and bounded clock measurements

The operator issued exactly one MCP `enclave_heal` without credential refresh.
It returned exit code zero with `APPLIANCE_INIT_OK` and `SESSION_ACTIVE`.
The internal `APPLIANCE_CLOCK_CHECK` passed. Independent read-only QGA samples
were then taken immediately after completion and at the two later checkpoints.
Lock waiting and stream synchronization were excluded from each sample window.

All values below use Appliance minus Host. The acceptance gate requires the
entire offset interval to fit inside ±2000 ms. Host clock stability passed for
every sample. Each reported uncertainty was 1 ms. Each reported RTT was 1 ms.

| Sample | Actual elapsed after heal | Offset | Lower bound | Upper bound | Verified |
| --- | ---: | ---: | ---: | ---: | --- |
| Before heal | Before call | −17539 ms | −17539 ms | −17538 ms | false |
| Internal heal check | During call | −2 ms | −2 ms | −1 ms | true |
| Immediate independent check | 0.000 s | −9 ms | −9 ms | −8 ms | true |
| 60-second check | 60.002 s | −3 ms | −3 ms | −2 ms | true |
| 300-second check | 300.002 s | −3 ms | −3 ms | −2 ms | true |

The original approximately 17.5-second offset was correctly rejected. After
the one repair, every independent interval remained within the gate throughout
the five-minute program. This is acceptance of the exercised clock correction
and its verification, not a claim of indefinite time stability.

### Session continuity and final state

Fresh worker attestation passed before `heal` and after the 300-second hold.
The worker instance was unchanged. Operator identity was unchanged. Loaded
adapter bytes were unchanged. The approved policy binding was unchanged.
The challenges were fresh. No RDP disconnect or reconnect event appeared.
The same client process and established connection were retained.

The owned test MCP server closed through stdin EOF with exit code zero.
Acknowledged worker stop took 40.84843 seconds. Fresh `stopped` telemetry and
exclusive lease access confirmed termination. A second check after 10.5 seconds
found no respawn. No residual owned SSH process remained.

Protection stayed active with 28 running components. Both protection event logs
had zero new entries. The Bastion time source was unchanged. Host remained on
installed `0.4.0rc2`. Journal integrity passed afterward. The indeterminate
record count stayed unchanged. No prior ambiguous copy operation was replayed.

### Qualification boundary

The clock field program is complete for this exact candidate and tested route.
No 128 MiB transfer was attempted in this program. The reverse-path delay is
not explained or declared fixed by successful clock verification. Stable
promotion remains blocked by the incomplete long-transfer acceptance.

The original RC1 bundle remains immutable. The RC2 candidate bundle also keeps
its build-time bytes and manifest. This later report does not rewrite them.
Stable `v0.3.0` retains its tag and release artifacts. Recording this result
does not publish a new release.

### Subsequent RC2 128 MiB MCP attempt

The operator subsequently reported **INCOMPLETE / ПРОВЕРКА НЕ ЗАВЕРШЕНА**
for one main 128 MiB upload on the same original RC2 wheel. Host verified
38 MiB before `deadline_exceeded` at `control.receive`. Step 39 was entered
but its copy request was not published. No upload commit was issued. The target
destination was absent; only uncommitted staging parts remained until cleanup.
The required pull was not started after the failed push.

A later offline review matched the saved Host observations with all 38 copied
worker records for that operation. Every record was a completed `push_part`
with exit code zero. Offsets covered the first 38 distinct parts without gaps
or duplicates. The last target SSH reply took 353 ms. Host request publications
were also 38. The timeout occurred during periodic read-only attestation before
publishing part 39, not during a data request for that part.

The operator reported no RDP disconnect. The worker remained running until
the acknowledged stop. Clock observations remained within the accepted gate.
One unchanged repeat of the indeterminate transaction returned its retained
diagnostics without new copy-dispatch. Acknowledged stop took 35.59875 seconds.
The lease was free without respawn at the later check. Protection stayed active
with zero new events. The new indeterminate record was preserved.

Controlled local regressions reproduce this stop after 38 verified MiB.
The working-source correction permits one new read-only challenge within the
original part budget. Each challenge retains its ten-second limit. No mutating
request is replayed. This corrects the immediate Host abort on a transient
periodic verification timeout. It does not establish why the physical route
delayed that challenge. The corrected source is not the original RC2 artifact
and has not received field acceptance.

## Incomplete candidate acceptance: 0.4.0rc1

- Result: **INCOMPLETE / ПРОВЕРКА НЕ ЗАВЕРШЕНА**.
- Exact source: `a8d9cf0fa60219220e5363d33bd2423ec90e2818`.
- Package version: `0.4.0rc1`, unpublished candidate.
- Wheel size: 279944 bytes.
- Wheel SHA-256:
  `42017e2b4045da9d8dbd0fe70b7c05c53a6b3519509a890ee0d34dc4e322e0c3`.
- Sdist size: 245291 bytes.
- Sdist SHA-256:
  `c1569bda6d6214e44d050318c5a523b4d3dade07c7c4d547b4cf772ed1ece13f`.
- Worker attestation version: `0.3.0`.
- Agent bytes: unchanged from stable `v0.3.0`.

The operator supplied a completed observation report. A subsequent offline
review inspected copied MCP traces and worker ledger records. Root JSON
observations were also inspected. Original evidence stayed private and unchanged.
Observer scripts were not executed. No live deployment was contacted by this
review. This record distinguishes raw trace/ledger comparisons from the
operator's policy and filesystem observations.

### Installation and scope

The tested route retained the Standard operator profile described in the
development entry below. Host used macOS ARM64 with Python `3.14.5`.
The noneditable installed runtime matched all 65 wheel files. The isolated
installed-package checker passed. Fresh live MCP initialization reported
`serverInfo.version: 0.4.0rc1`. Fresh worker attestation passed with a 45-second
copy-step capability. Approved pins were preserved without restaging agents.
The existing Host journal namespace was retained after a SQLite online backup.

### Policy evidence corrects the old idle-timeout attribution

The operator's read-only policy observations reported no configured idle limit.
No active-session duration limit was reported. The disconnected-session limit
was also zero. Computer and user Terminal Services policy keys were absent.
The RDP-Tcp limits were zero. The user AD override was absent. Computer
`gpresult` was unavailable to the non-administrator account; the corresponding
registry policy key was readable. These are retained observations from that
window, not a guarantee against future domain-policy changes.

The operator additionally reported an RDP connection surviving more than
60 minutes without keyboard or pointer input. RC1 used no synthetic input.
The previous approximately 25-minute idle-policy explanation is withdrawn.
The successful development run's pointer activity remains a historical test
condition; its causal benefit was not established.

Transport disconnect events were recorded during reverse-transfer testing.
Client event 1105 accompanied event 1026 with reason 267. The report also
records server event 40 with reason `0x80070040`. Native client reconnect took
approximately 13–23 seconds. Redirected-drive loss caused the foreground worker
to exit in affected cases. Those events do not identify the failing network
component or prove that every timeout had the same cause.

### Transfer results and exact failed offsets

One 128 MiB push completed on its second attempt. All 128 data receipts were
verified. The target's independent size and SHA-256 matched the Host source.
Its 129 worker records matched the 129 request publications, including commit.
The first push failed while waiting for block 4 and remained indeterminate.

None of the six 128 MiB pulls completed. The following measurements were
independently reconciled between Host traces and private worker ledger records.
Each failed request was matched by its inner request identity. Offsets and
publication counts agreed. Each pull includes one metadata request.

| Pull attempt | Host duration | Failed data block | Offset bytes | Verified blocks | Publications | Last worker state | Target SSH reply |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| 1 | 539.8793 s | 64 | 66060288 | 63 | 65 | indeterminate | 445 ms |
| 2 | 233.2142 s | 18 | 17825792 | 17 | 19 | indeterminate | 2243 ms |
| 3 | 601.6665 s | 69 | 71303168 | 68 | 70 | completed | 578 ms |
| 4 | 644.0819 s | 69 | 71303168 | 68 | 70 | indeterminate | 394 ms |
| 5 | 1042.6262 s | 105 | 109051904 | 104 | 106 | indeterminate | 1350 ms |
| 6 | 127.7360 s | 6 | 5242880 | 5 | 7 | indeterminate | 573 ms |

Every matched last target request had exit code zero. The observed error stages
included `control.receive`. Other errors occurred at `qga.guest-file-seek` or
`qga.guest-file-read`. The remaining stage was `vfs.response`. These stages
identify where Host observed failure; they do not isolate its origin.

All five indeterminate last worker records retain `exit_code: 0` and a
`MethodInvocationException`. Their `failure_stage` is `ssh`. Source review
shows that this broad phase remains selected while the worker writes the final
durable record and sends the response. These records contain no
`operator_failure_phase` from the SSH helper's catch boundary. The evidence
therefore narrows those failures to after the SSH result returned, but cannot
distinguish durable-record publication from response publication. The phase
label alone must not be interpreted as failed target execution.

The worker writes a completed durable record before sending the response.
Consequently `completed` does not by itself timestamp response visibility on
Appliance. No independent worker response-publication duration is retained.

Attempt 3 differs from the worker-indeterminate cases. Its worker ledger records
all 70 requests as completed. The operator observed a complete 1049120-byte response
after approximately 55.14 seconds, beyond the 45-second step cap. The worker
remained alive and passed subsequent fresh attestation without an RDP break.
The precise delay boundary is still unresolved. Increasing the whole-operation
budget would not extend this step cap.

Saved UTC timestamps associate client events with attempts 4–6. Cross-machine
clock error was not independently bounded in this review, so these differences
are approximate associations rather than precise causal ordering. For attempt 4,
the disconnect event was about 15 seconds after the Host error. For attempt 5,
it was about 6.5 seconds before the error. For attempt 6, it was about 20.9
seconds before. This is not evidence that the recorded disconnect caused attempt
4's timeout. The other attempts cannot be assigned that same
event correlation from the available timestamped summary.

### Integrity and no replay

All seven failed operations retained indeterminate outcomes. Each unchanged
request was repeated exactly once after reconciliation. Every repeat returned
`transaction_indeterminate` with the original diagnostics. The report records
zero new worker copy-dispatch for each repeat. No incomplete Host download was
published. Owned temporary downloads were removed. Historical journal records
were not cleared.

The completed push returned its identical retained result after a test MCP
restart with the local source absent. No new worker copy-dispatch appeared.
Only owned test processes were closed through stdin EOF.

Acknowledged worker stop took 31.63069 seconds. The operator confirmed fresh
`stopped` telemetry and a free session lease. A second check after 10.5 seconds
found no respawn. Protection stayed active without new events. Host remained on
`0.4.0rc1` with the stable rollback wheel retained. No active operations remained.

### Subsequent bounded reverse-path probe

The operator reported **PASS / УСПЕХ** for the diagnostic program on the same
original RC1 wheel. The probe did not reinstall Host. A single 8388608-byte
pull completed in 67.1973 seconds. All eight parts were verified and committed.
The Host hash matched the synthetic Target source. Nine completed worker
records were reported, including metadata. The longest observed step was
16.563 seconds. No RDP disconnect was reported in that probe window.
Acknowledged final stop took 28.80414 seconds without respawn.

Selected saved JSON observations were inspected offline afterward. The clock
measurement source was read without executing it. The copied source inputs
were hash-recorded. This review recalculated the two Appliance calibration
windows; it did not independently re-execute the field program or inspect every
one of its 6404 retained input files.

- Appliance minus Host before the probe: −16.4830 seconds.
- Before-probe half-window uncertainty: ±1.1758 seconds.
- Appliance minus Host after the probe: −17.0717 seconds.
- After-probe half-window uncertainty: ±0.6483 seconds.

The windows overlap. The readings establish an approximately 17-second offset
in that window, not a demonstrated rate of increasing drift. Bastion's much
wider observation windows do not establish a precise change in its offset.
The new calibration cannot be applied retroactively to the earlier six attempts.

An independent local Appliance metadata observer sampled every 250 ms without
competing QGA reads. The report records 272 samples. The retained event list
was also inspected. Reported intervals from request publication to full-sized
response visibility ranged from 4.674 to 15.434 seconds. Those intervals include
work before `Send-OperatorFrame`, including durable-record publication.
They do not isolate the data write or `Dispose()` duration. Absence of a sampled
intermediate size does not establish that such a state never existed.
Zero bytes read on Host alone also does not prove a live RDP session or an
exclusively held descriptor throughout the wait.

The 55.1375-second historical measurement is now explicitly defined as the
interval between the previous slot's erase timestamp and the next slot's
response timestamp on Appliance. It is not a direct duration of one response
write. The broad reverse-path boundary remains the main investigation area.
The concrete transport mechanism is unresolved. A product defect causing the
pull failure is not established.

A separate local review identified a clock-setting defect: implicit Host UTC
was sampled before QGA lock waiting and stream synchronization. Working-source
regressions cover the correction and post-`heal` verification. No retained
measurement proves that this defect caused the field offset or transfer delay.
The [short clock field prompt](MCP_CLOCK_HEAL_FIELD_PROMPT_RU.md) applies only
after preparing an exact new source-bound wheel containing that correction.
The original RC1 bundle is not replaced by the working-source change.

### Remaining gate

The required 128 MiB round trip is incomplete. Diagnostic consistency passed.
No-replay checks passed. No product defect causing the reverse-path delay is
established by these observations. Stable promotion remains blocked pending
reverse-path investigation and a complete acceptance run. Local controlled
regressions cover partial-frame recovery and late/stopped-worker outcomes;
they do not reproduce the real RDP transport fault.

Use the [bounded reverse-path investigation](MCP_REVERSE_PATH_PROBE_RU.md)
before another full acceptance run. Do not change the adapter or increase
timeouts to conceal the failure. This entry creates no tag or release.
The original candidate bundle and stable release assets remain immutable.

## Accepted development block: 0.4.0.dev0

- Operator-reported result: **PASS / УСПЕХ** for the tested MCP functionality.
- Exact source: `363d8f72dc2c3ab1eebf9d60a3a95215cba468b3`.
- Package version: `0.4.0.dev0`, unpublished development code.
- Field-built wheel size: 278458 bytes.
- Field-built wheel SHA-256:
  `4db9a470e6fcef7a7fc71d2b9fdf987ceb113537773c8ef8871477b961a98aae`.
- Field-built sdist size: 252604 bytes.
- Field-built sdist SHA-256:
  `1331e022f383c7c9ef59c1276a49cf5b688f56b36606783cc0d6eaffe6ffd0c4`.
- Installed runtime comparison reported 65 matching files.
- Runtime mismatches: zero.
- Unexpected runtime files: zero.

The supplied report binds these field-built artifacts to a clean detached
checkout of the source above. It reports successful installed-package acceptance.
A later read-only local review found the original field-built archives through
the installed distribution's wheel-origin metadata. Both archive hashes matched
the report. All 65 wheel runtime files were independently compared byte-for-byte
with this exact Git source. These are field-cohort identities, not published
release checksums. Source agent identities also matched the immutable source. The
[15-job CI run](https://github.com/pom6i4/enclave-gateway/actions/runs/44612440164)
passed for that exact source.

### Development block scope and Host update

- Host: macOS ARM64 with Python `3.14.5`.
- Build tools: setuptools `81.0.0`.
- Wheel build tool: wheel `0.47.0`.
- Packaging library: packaging `26.3`.
- Installer: pip `26.1.1`.
- Route: QGA Appliance followed by approved VPN and actual RDP drive redirection.
- Execution: system OpenSSH on Bastion to one Linux Target.
- Target interpreter: Python `3.11.2` on Linux x64.
- Security mode: `standard`.
- Execution profile: `structured_only`.
- Structured backend: `operator`.
- Spool protocol: `stream`.
- Worker attestation: enforced with unchanged approved deployment pins.
- Protection: Kaspersky Endpoint Security for Windows `21.3.10.1001`.

Host was updated from installed `0.3.0` to the exact field wheel using an offline,
noneditable installation. Existing configuration and journal namespace were
preserved. Historical transaction results remained available. The operator used
the SQLite backup API before the update and retained the stable rollback wheel.
Existing IDE-owned MCP processes were untouched.

Agent bytes remained identical to `v0.3.0`. No restaging was reported.
The worker attestation version stayed `0.3.0`. Fresh attestation reported
`chunked_copy_slots_v1: true`. The attested copy-step budget was 45 seconds.
The foreground lease was eight hours.

### Installed and live MCP checks

The automatic installed-package check passed against the exact field wheel.
Its separate local MCP check also passed with an isolated empty configuration.
The Python audit guard passed all three denial probes. This portable guard is
not an operating-system sandbox.

Three new real-route test MCP sessions reported the expected initialization:

- Server name: `enclave-gateway`.
- Server version: `0.4.0.dev0`.
- Negotiated protocol: `2025-03-26`.
- Tool definitions: 18.
- `ping`: successful.
- `node_transfer` exposed `chunked`.
- `node_transfer` exposed bounded `timeout_sec`.
- `node_transfer` exposed `tx_id`.

The mutable test sessions used the original configuration and journal. The
client disabled automatic retries. Its call timeout was 2400 seconds. Each main
copy used `chunked: true` and a whole-copy timeout of 1800 seconds.

### Four retained round-trip attempts

All four 128 MiB pushes completed. The first three pulls failed and remained
indeterminate. The fourth complete round trip passed. It must not be presented
as first-attempt end-to-end success.

| Attempt | Push wall time | Pull wall time | Pull outcome |
| --- | ---: | ---: | --- |
| 1 | 1141.7581 s | 333.8557 s | Response timeout with an RDP disconnect |
| 2 | 1080.8767 s | 406.4611 s | Response timeout with an RDP disconnect |
| 3 | 1061.7158 s | 646.1164 s | Response timeout at the 45-second step budget |
| 4 | 1098.7722 s | 1168.3885 s | Completed with matching size and SHA-256 |

The original observer associated the first two disconnects with an approximately
25-minute RDP input-idle policy. That attribution was withdrawn after the
[RC1 policy observations](#policy-evidence-corrects-the-old-idle-timeout-attribution).
The development test did use periodic synthetic pointer activity from an external
observer. No further RDP disconnects were reported after that intervention.
Its causal benefit is unproven. The product and agent bytes were unchanged.
Keep this historical test condition visible without recommending it as a policy
bypass or treating it as proof of unattended operation.

For attempt 3, the observer reported a complete 1 MiB response arriving at an
interval of approximately 61.7 seconds, beyond the 45-second step budget.
The RDP session and worker reportedly remained active. The proposed VPN/RDP
throughput explanation is an observer inference; the delayed boundary was not
independently isolated in this record.

### Follow-up review of saved attempt-3 evidence

Selected saved JSON observations and the original attempt-3 MCP trace were
reviewed offline after the field report. The original files were preserved.
The observer scripts were read, not executed. No live enclave was contacted.

The trace contains one publication of the main pull tool call. Its recorded
monotonic duration is 646.1164 seconds. Its error is `worker_response_timeout`
with an indeterminate result. The saved final ledger-query output contains 75
matching operation records. Of these, 74 are `pull_part` records. That first
review did not have the full raw ledger listing. A later offline review of the
retained raw snapshot matched the exact inner request identity in the trace
to one completed `pull_part` record. Its `copy_offset` is 76546048 bytes.
The failed wait therefore concerned data block 74. Its target SSH reply took
400 ms with exit code zero. The 75 records consist of one `pull_info` plus
74 distinct data parts. The earlier free-text block-123 annotation is withdrawn
as incorrect. The visible IPC response slot 258 comes from aligned request-stream
position and does not identify a data-block ordinal.

The saved file timestamps independently show a 61.7018-second interval between
response slots 257 and 258. This confirms the timestamp interval stated in the
report. It is not a measurement from request dispatch to response, or a direct
measurement of network delay. Keep the VPN/RDP explanation as an inference.
The exact historical offset is now reconciled from retained evidence. The
timestamp interval still does not isolate where the response was delayed.

### Retained failed outcomes and successful round trip

Each failed pull left its Host destination unpublished. Before any new attempt,
the operator reports reconciling the prior journal and filesystem evidence.
New attempts used new transaction identities and new synthetic paths. No failed
identity was cleared or automatically replayed.

The successful attempt used 134217728 bytes of random, effectively
incompressible data. All three copies matched size and SHA-256. The main push
produced 129 worker records. The main pull produced 129 worker records. Each
main operation completed in the Host journal with the retained result.

### Completed-result deduplication across MCP restart

The operator renamed the two owned local test files after the successful
round trip. Their original source and received-file paths were confirmed absent.
Only the test MCP server was closed through stdin EOF and restarted.
The new session kept the same journal namespace and principal.

Repeating each original request with the same transaction identity and unchanged
arguments returned its retained result. New JSON-RPC request IDs were used.
The push lookup took 0.0023 seconds. The pull lookup took 0.0007 seconds.
Neither absent local path was recreated. The target file stayed unchanged.

The report independently compares the durable worker ledger before and after
the repeat window. No new copy records appeared. Active spool metadata stayed
unchanged. FlightRecorder copy counts and hash-chain endpoint stayed unchanged.
This evidence goes beyond comparing the final file hash alone.

### Controlled cancellation and ambiguous-result rejection

A separate 24 MiB synthetic upload was cancelled through
`enclave_transaction` after observed dispatch. The original tool call returned
`cancelled` with an indeterminate outcome after 13.1616 seconds. The Host journal
retained that state.

The operator channel closed and the worker stopped. The report confirms free
session lease and released IPC handles before the next worker was attached.
No target destination was published. One uncommitted 1 MiB part remained until
the operator completed reconciliation and recorded the evidence.

A fresh MCP session with the original journal repeated the unchanged request
against its original transaction identity. The response was
`transaction_indeterminate` at the journal stage in 0.0015 seconds.
There were zero new copy-dispatch records. The target state did not change.
This is rejection of replay, not resumption or rollback of the interrupted copy.

### Final state and qualification limits

Final acknowledged worker stop completed in 35.14637 seconds. Fresh `stopped`
telemetry and exclusive lease access confirmed termination. A second observation
after 10.5 seconds found no respawn. No IPC handles remained held. All three
owned test MCP sessions closed through stdin EOF with exit code zero.

Protection remained active. The product event log had zero new entries. A
separate service log gained four informational events. No new detection or
blocking event affecting Gateway was reported. No exclusions were added.

Host remained on installed `0.4.0.dev0`. The stable rollback package was retained.
No operations remained in progress. Historical indeterminate records were kept.
Five additional indeterminate records were retained from this program:

- Three failed main pulls.
- The intentional cancellation.
- An observer command during channel teardown.

Owned synthetic files were removed only after reconciliation. Journals were not
rolled back or globally cleaned. The operator reported no outstanding recovery.

This is operator-reported functional acceptance of the exact development block
under the stated session-continuity conditions. It does not establish reliable
first-attempt or unattended long-running transfer. It does not close a new full
RDP reconnect/upgrade/rollback program. It does not qualify other profiles.
No code correction is established by this report alone. The source of the
reported delay remains an investigation boundary.

No `0.4.0` release or tag is created by recording this result. Stable `v0.3.0`
and its original artifacts remain unchanged. Actual environment identities and
private policy hashes are omitted. Staging-bundle identifiers are omitted.

## Accepted installed release: v0.3.0

- Result: **PASS / УСПЕХ**, as reported by the operator.
- Tested installed package: `0.3.0`.
- Tested tag: `v0.3.0`.
- Release commit: `29dad2ea643e5eed7fffc1a795827aa485ab1b85`.
- Published wheel size: 278099 bytes.
- Published wheel SHA-256:
  `23f0d4852749ec587ce16c589a76b55802183042961c49836266fae7c9a00fbd`.
- Installation identity: all 65 runtime files matched the exact release source.
- Content differences: zero.
- Unexpected additional runtime files: zero.
- Evidence provenance: the operator's completed installed-release field report.

The reported artifact identities were checked against the published Release.
The wheel and source archive matched their published hashes. The release
manifest and checksum file matched too. All seven entries in `SHA256SUMS`
passed before installation.

### Installed release scope and update

- Host: macOS ARM64 with Python `3.14.5`.
- Appliance: Windows 11 ARM64 through QGA `109.1.0`.
- Route: approved VPN followed by native RDP drive redirection.
- Bastion: Windows 10 x64 with a non-administrator domain operator session.
- Target: Linux x64 with Python `3.11.2` and the forced-command peer.
- Protection: Kaspersky Endpoint Security for Windows `21.3.10.1001`.
- Security mode: `standard`.
- Execution profile: `structured_only`.
- Structured backend: `operator`.
- Spool protocol: `stream`.
- Worker attestation: enforced with unchanged independently approved pins.
- Heartbeat window: 300 seconds throughout the run.
- Advertised copy-step cap: 45 seconds.
- Whole-copy timeout: 1800 seconds.
- Foreground lease: eight hours.

The working Host environment was updated from `0.3.0b7` using the published
wheel. Installation completed in 462.21 ms with exit code zero. Both CLI and
package metadata reported `0.3.0` from installed `site-packages`. There was no
source-path override or editable-install substitution.

Configuration bytes and private permissions remained unchanged. Prior journal
records stayed readable in the same namespace. Consistent backups were retained
privately. The existing nonzero spool evidence was preserved.

Agent copies matched the approved public source hashes in
[Component identity](#component-identity). Arbitrary restaging was unnecessary.
Fresh attestation confirmed the loaded adapter and deployed bytes. The worker
identity contract stayed at `0.3.0`. The existing system OpenSSH startup signature
check was allowed to finish before readiness was asserted.

No background supervisor ran on Bastion. Appliance initialization invoked
`session_supervisor.ps1` once per `heal` with `-ObserveOnly`. This run does not
qualify automatic background supervisor restart.

### Installed release heal and clocks

All three consecutive `heal` calls returned `APPLIANCE_INIT_OK` and
`SESSION_ACTIVE`. The same worker instance remained active. OpenSSH did not
reconnect and heartbeat kept updating.

Each call performed successful QGA clock synchronization. Appliance
initialization received `HostEpochUtcMs 0`; the `Set-Date` fallback was not
invoked. Measurements used QGA UTC observations with Host request midpoints.
There were five samples before and five after each call. RTT and timer
uncertainty were retained in private evidence.

| Heal | Duration | Median offset before | Median offset after | Reported total uncertainty | Previous 1.6 s rollback |
| --- | --- | --- | --- | --- | --- |
| 1 | 2.767 s | +27.820 ms | +10.187 ms | ±75.116 ms | Absent |
| 2 | 2.653 s | -2.473 ms | -0.337 ms | ±32.511 ms | Absent |
| 3 | 2.381 s | -0.729 ms | -0.861 ms | ±20.730 ms | Absent |

Final offsets were consistent with zero within the reported uncertainty.
Direct millisecond Host-to-Bastion clock measurement was unavailable through
the restricted worker protocol. Its domain time source was confirmed
separately. No Bastion offset measurement is claimed.

### Installed release ordinary 128 MiB round trip

A new incompressible file generated with `os.urandom` completed push and
immediate pull without fault injection. All three copies matched size and
SHA-256. The same worker remained active throughout both transfers.

| Direction | Bytes | Data blocks | Duration | Attempt | Exit code |
| --- | --- | --- | --- | --- | --- |
| Push | 134217728 | 128 | 996.247 s | First | 0 |
| Immediate pull | 134217728 | 128 | 688.846 s | First | 0 |

The worker journal was correlated only with the current transfer operations.
Push had exactly 128 unique `push_part` entries and one `push_commit`.
Pull had one `pull_info` and 128 unique `pull_part` entries. Each direction had
129 completed entries with exit code zero. No duplicate step publication was
observed. Temporary upload parts were absent after commit.

Both directions exceeded the 300-second heartbeat window. There were no new
indeterminate operations during the installed `0.3.0` program.

### Installed release stop, cleanup and protection

- `agents stop --timeout 60` completed in 32.223 seconds with exit code zero.
- `WORKER_STOP_ACCEPTED` was followed by fresh `stopped` telemetry.
- The foreground worker and its attachment process exited normally.
- No worker-held IPC handles remained.
- Exclusive session-lease access succeeded immediately after stop.
- A second check after 10.5 seconds confirmed stopped status and free lease.
- No automatic worker restart occurred.
- One `clean` call completed in 1.923 seconds with exit code zero.
- Cleanup removed 332 fully zeroed IPC buffers.
- Cleanup preserved both historical nonzero evidence files.
- The preserved request size was 135168 bytes.
- The preserved response size was 416 bytes.
- There were no deferred removals or cleanup errors.
- Durable Host and worker journals remained available.
- Historical indeterminate records were retained separately from this run.
- Synthetic test files were removed after integrity evidence was recorded.
- Host remained on installed `0.3.0` with the test worker stopped.
- VPN and QGA remained available.
- KES retained 28 running protection components.
- Both observed Kaspersky logs recorded zero new events.
- No protection exclusions or trust-policy relaxations were introduced.

Protection observations used direct operating-system and vendor status checks.
New-event filtering used both the pre-run record boundary and the trial time
window. Log rotation was checked and had not occurred.

Before the upgrade, one historical expired running operation was reconciled to
indeterminate without execution. It was counted with the known historical
negative-test records. The count remained unchanged during the `0.3.0` run.
Historical uncertainty was not erased or presented as a new product failure.

### Installed release evidence limits and operational notes

The report identified no product defect or deployment error. All product
commands in this program completed successfully on their first attempt.
An incidental preparation adjustment in the diagnostic observer was separate
from the product-command results.

The CLI trial used new `0.3.0` processes. Existing IDE-owned stdio MCP sessions
were outside its scope. Such clients need their normal connection restart to
load updated modules. The CLI result does not attest their resident versions.

This record is based on the operator's supplied report. Underlying receipts and
raw field logs remain private and were not independently inspected here.
Acceptance applies to the exact installed package on the exercised route.
Other Host platforms and execution profiles require separate qualification.
Actual environment identities are omitted. Private policy hashes and
staging-bundle identifiers are omitted.

The Release adds `V030_FIELD_ACCEPTANCE.md` with a separate
`V030_FIELD_ACCEPTANCE.sha256`. The original eight release assets retain their
published bytes. The original manifest and checksum set remain valid for the
initial distribution. The tag stays bound to the original release commit.

## Accepted candidate: 0.3.0rc1

- Result: **PASS / УСПЕХ**, as reported by the operator.
- Tested package: `0.3.0rc1`.
- Tested commit: `33fbcdecfba01ea8ed995379d39d8bc49886f706`.
- Candidate wheel SHA-256:
  `7a7f108e0384a4e8e99024e47480de77682f6ea04448f4d6ca61c8c354621d5b`.
- Candidate sdist SHA-256:
  `74cdc38a5c4ef97eed933ffb6ba1206a8e0557d43f1f4b49168c8dd6d6887595`.
- Candidate source archive SHA-256:
  `1253f417038b2ce47992fa6e659f992f3de3e6ff80203bcfcbefd8c71c4d3672`.
- Rollback baseline: published `0.3.0b7` at
  `bcafbb1ae71bd044ed6ec4a8a0cf7fafbefd7f44`.
- Installation identity: all 65 runtime files matched at each stage.
- Evidence provenance: the operator's completed RC lifecycle report.

The reported artifacts match the locally prepared candidate hashes. All eight
entries in the candidate checksum file passed. The only runtime source change
from Beta 7 was the package version statement. Agent bytes were unchanged.
The independent worker attestation version remained `0.3.0` throughout.

### RC deployment scope

- Host: macOS ARM64 with Python `3.14.5`.
- Appliance: Windows 11 ARM64 through QGA `109.1.0`.
- Route: approved VPN followed by native RDP drive redirection.
- Bastion: Windows 10 x64 with a non-administrator domain operator session.
- Target: Linux x64 with Python `3.11.2` and the forced-command peer.
- Protection: Kaspersky Endpoint Security for Windows `21.3.10.1001`.
- Security mode: `standard`.
- Execution profile: `structured_only`.
- Structured backend: `operator`.
- Spool protocol: `stream`.
- Worker attestation: enforced with unchanged independently approved pins.
- Foreground lease: eight hours.
- Advertised copy-step cap: 45 seconds.
- Whole-copy timeout: 1800 seconds.

Actual deployment identifiers are excluded. The private policy hash and
staging-bundle identifier are not recorded. Public agent hashes remain those
in [Component identity](#component-identity).

### RC upgrade and clock smoke

The operator stopped the baseline worker and confirmed lease release before
installing the RC wheel into the same working Host environment. A consistent
SQLite backup was retained. The working configuration was unchanged. The same
Host journal namespace remained active without migration or restoration of an
older database. Earlier Beta 7 results were readable through the RC CLI.

Manual attachment produced a freshly attested worker without agent restaging.
A safe target command passed. `heal` returned `APPLIANCE_INIT_OK` and
`SESSION_ACTIVE` with that worker unchanged.

The Appliance clock had fallen approximately 772 seconds behind after a Host
pause. QGA synchronization corrected it. Initialization received
`HostEpochUtcMs 0` and did not call the `Set-Date` fallback. The final median
offset was -1.761 ms with reported total uncertainty of ±47.620 ms. The earlier
approximately 1.6-second rollback did not recur.

One new 1 MiB file completed push and immediate pull with matching size and
all three SHA-256 values. Push took 22.734 seconds. Pull took 11.013 seconds.

### RC actual RDP reconnect and duplicate rejection

The operator interrupted only the test's native `mstsc.exe` client on Appliance.
QGA and the VM were not restarted. Windows LocalSessionManager events 24 and 25
confirmed disconnection and reconnection of the same Windows session.
The redirected drive returned.

The old worker exited on redirected-channel loss during `ssh_reply`. It did
not respawn. Both session leases were free before a new manual attachment.
The last on-disk state still said `running` because the disconnected drive
could not receive a final stopped snapshot. Process exit and exclusive lease
checks established actual termination. A new worker instance passed fresh
attestation and executed a new safe command.

| Test operation | Independently observed effect | Host journal duplicate check | New worker ledger duplicate check |
| --- | --- | --- | --- |
| Completed operation | One completed execution | Returned the stored result | Rejected at request phase before SSH |
| Interrupted operation | One start and zero completions | Rejected as `transaction_indeterminate` | Rejected at request phase before SSH |

The interrupted command had a 28-second budget. Host observation returned
`worker_response_timeout` at `vfs.response` after 28.079 seconds without replay.
Both journals retained an indeterminate outcome. Its start marker was observed
before the actual RDP interruption. No finish marker appeared.

The separate worker-ledger harness bypassed Host result caching. Both duplicate
identifiers returned exit code 125 at the existing-tombstone check without
sending a new SSH command. Independent target counters remained unchanged.
The report therefore distinguishes one interrupted start from a successful
completion. Indeterminate status was not converted into completion.

### RC rollback, stop and protection

- The RC worker stopped in 29.497 seconds before rollback.
- The verified Beta 7 wheel was reinstalled into the same Host environment.
- All 65 restored runtime files matched the baseline.
- Configuration and independent pins remained unchanged.
- Existing Beta 7 and RC records remained readable through the Beta 7 CLI.
- The current Host database was preserved without restoring the old backup.
- The durable worker ledger retained both tested transaction tombstones.
- A manually attached baseline worker passed fresh attestation.
- Repeated access to both test IDs caused zero additional target executions.
- A new 1 MiB round trip matched all three sizes and SHA-256 values.
- Baseline push took 10.109 seconds.
- Baseline pull took 7.485 seconds.
- Final stop completed in 27.584 seconds within the 60-second budget.
- Fresh stopped telemetry and exclusive lease access confirmed termination.
- The worker remained stopped in a subsequent observation after ten seconds.
- One `clean` call completed in 1.447 seconds with zero errors.
- Cleanup removed 79 zeroed IPC files.
- Cleanup preserved the interrupted 135168-byte request.
- Cleanup preserved a prior 416-byte nonzero response.
- Host journal and worker ledger remained available.
- KES retained 28 running protection components.
- Both observed Kaspersky event logs recorded zero new events.
- Protection policy was not weakened.

The operator left Host on Beta 7 with the test worker stopped and its lease free.
The route remained available. No second worker or hidden autostart was left.

### RC evidence limits and retained attempts

This record summarizes an operator-supplied report. Underlying field receipts
and raw logs remain private and were not independently inspected here.

Original observer/setup failures were retained. They concerned archiving over
RDPDR and attachment-readiness timing. A helper parser-name collision was fixed
before the actual RDP disconnect; the real reconnect scenario then passed.
These were not reported runtime defects. The interrupted operation above was
the sole new intentional indeterminate outcome.

The optional additional disconnect during a partially consumed chunked transfer
was not run. This acceptance does not qualify other Host platforms or other
execution profiles. Background supervisor reconnect was not exercised.
No release or tag was published by the field run.

Final `0.3.0` artifacts had separate exact-artifact checks and hashes.
The later installed-release entry above provides its own field result.
RC acceptance remains bound to its exact tested revision.

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
