# MCP transfer diagnostics for 0.4.0rc1

This unpublished Standard operator candidate adds Host-side observations.
Attested step budgets are unchanged. Automatic retries are not added. Agent
bytes and worker attestation version `0.3.0` remain unchanged. The
[earlier field result](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-development-block-040dev0)
applies to its original development cohort, not this candidate.

## Retained observations

Completed chunked-copy results include `diagnostics`. Failed calls include the
same structure in error data. The journal retains it. A repeated completed ID
returns the original result. A repeated indeterminate ID returns the retained
observations without publishing another copy request.

`diagnostics.copy_progress` contains bounded structural observations:

| Field | Meaning |
| --- | --- |
| `direction` | Push or pull |
| `action` | Last attempted copy protocol action |
| `file_size_bytes` | Total size after metadata is known |
| `blocks_total` | Expected data parts |
| `blocks_verified` | Parts whose receipts Host verified |
| `bytes_verified` | Bytes covered by those verified receipts |
| `block_index` | One-based part ordinal; zero for metadata/commit |
| `offset_bytes` | Exact last-action byte offset |
| `length_bytes` | Requested part length |
| `steps_started` | Copy actions started by the executor |
| `request_publications` | Stream append attempts, including uncertain acknowledgements |
| `attestation_attempts` | Fresh verification guard calls for the copy |
| `attestation_retries` | New periodic challenges after a transient timeout |
| `step_budget_ms` | Selected step budget before local dispatch |
| `published_budget_ms` | Last envelope budget after local preparation |
| `step_elapsed_ms` | Last step's elapsed monotonic time |
| `max_step_elapsed_ms` | Highest step elapsed time |
| `control_kind` | QGA or another control implementation |
| `response_reads` | Response-read API attempts |
| `empty_response_reads` | Empty response observations |
| `read_timeouts` | Timeouts propagated by observed read calls |
| `connection_losses` | Connection errors propagated by observed read calls |
| `state_reads` | Worker-state observations |
| `response_bytes_received` | Frame bytes observed for the last action |
| `response_read_outcome` | Last copy-response read outcome from a fixed label set |
| `destination_committed` | Final receipt accepted or Host download atomically published |

Missing fields mean that boundary was not observed. A verified part is not a
whole-file commit. Empty uploads use one zero-byte part. Empty downloads have
no data parts. No deployment paths or identities are added to this structure.

Attestation challenges are read-only and do not increment copy request
publications. After a timed-out periodic challenge, RC3 permits
one new challenge within the original part budget. Each has at most ten seconds.
No data request is published until verification succeeds. Both counters remain
visible in the retained result. Trust failures and cancellation are not retried.
This behavior is outside the original RC2 wheel identity.

The last-read label is reset for each copy action. Its possible values are:

- `not_observed`: no copy-response observation finished.
- `open_failed`: QGA rejected opening the response slot.
- `empty`: the read returned no bytes.
- `data`: a read returned frame bytes without asserting completion.
- `complete`: a complete receipt passed validation and cleanup.
- `timeout`: the response read raised a timeout.
- `connection_lost`: the response read raised a connection error.

An open failure alone cannot distinguish an absent file from an exclusive
writer or a permissions error. Raw QGA errors are not copied into diagnostics.
Read counters accumulate across the copy. The last-read label applies to the
current action. A worker-state observation does not overwrite that label.

QGA binary-response polls in the working source read at most 64 KiB before
returning progress to the decoder. Each poll retains its three-second cap.
A final EOF observation precedes acknowledged erasure. This prevents a bounded
read ending on the payload boundary from accepting trailing response bytes.
The original part deadline still applies to every read and to cleanup.

`diagnostics.timings_ms` contains cumulative Host observations:

- `vfs.preflight`: performed readiness checks.
- `attestation`: performed fresh identity checks.
- `vfs.upload_slot`: upload-slot writing.
- `vfs.publish`: request append.
- `vfs.stream_exchange`: publication through result handling.
- `vfs.response_read`: response-read API calls.
- `vfs.state_read`: worker-state read calls.
- `vfs.poll_sleep`: explicit polling sleeps.
- `vfs.erase`: acknowledged-span cleanup.

These measurements are inclusive and nested. Do not sum them as disjoint phases.
`vfs.upload_slot` precedes `vfs.stream_exchange`; it is not inside that timer.
QGA committed reads can include validation and erasure. Their duration does not
isolate QGA wire latency from a blocked guest filesystem read. Response waiting
does not independently measure the VPN or RDP network. Ordinary `timings_ms`
may contain additional operation timings.

Local fixtures use a controlled clock to model late reads. They verify deadline
retention and no replay, not WAN performance. A two-part download fixture also
exercises an interrupted partial frame through the actual QGA file algorithms.
Read recovery retains the cursor without another publication. Stopped-worker
and late-frame cases preserve the prior destination and remove the owned
temporary download. A fresh read-only probe uses its own response slot after
the late outcome without consuming the retained failed frame.

## Offline block reconciliation

Analyze a copied private worker-ledger snapshot without contacting a deployment:

```sh
python scripts/qualification/copy_ledger.py \
  --ledger /private/ledger-snapshot \
  --operation-id <EXACT_PRIVATE_OPERATION_ID> \
  --output /private/new-offset-analysis
```

The result separates protocol action counts from unique data offsets. It shows
gaps and repeated offsets. Incomplete records remain visible. Input filenames
and hashes stay in `private-inputs.json`; do not publish that file. Review the
structural `result.json` before sharing it.

Data ordinal is `copy_offset / 1048576 + 1`. Metadata adds a ledger record without
adding a data block. An IPC response filename uses the aligned request-stream
position divided by 4096. That slot number is not a data ordinal. Neither record
count nor highest observed offset alone proves which block failed. The
[saved field observations](../contrib/qualification/FIELD_ACCEPTANCE.md#follow-up-review-of-saved-attempt-3-evidence)
now include the raw ledger snapshot. Matching the error's exact inner request
identity establishes data block 74 at offset 76546048. Its target request
completed in 400 ms. The earlier block-123 annotation is incorrect.

## Current field boundary

The [RC1 field record](../contrib/qualification/FIELD_ACCEPTANCE.md#incomplete-candidate-acceptance-040rc1)
retains six incomplete pulls. Last successful SSH replies were received in
394–2243 ms. Five last worker outcomes were indeterminate. One was completed
with a response observed after the step cap and no reported RDP disconnect.
Thus a stopped-worker case and a late-response case require separate analysis.
Host read-stage errors alone do not prove a QGA defect. Transport events do not
prove which network component caused an interruption. The earlier idle-policy
attribution is withdrawn; recorded policy limits were zero and the operator
reported more than 60 minutes of input-free connection continuity.

The [bounded investigation prompt](../contrib/qualification/MCP_REVERSE_PATH_PROBE_RU.md)
starts from existing evidence before allowing a small diagnostic transfer.
Do not repeat full acceptance blindly or extend budgets without isolating the
delay. The original observations alone do not establish a transfer-runtime fix.

Worker `failure_stage: ssh` also covers final durable-record writing and
response sending after SSH returns. A completed ledger record precedes response
publication. Neither field independently measures response visibility on
Appliance. The saved records narrow the five indeterminate failures to after
the SSH helper returned, without resolving which publication failed.

The subsequent bounded 8 MiB probe completed. Its request-to-response-visible
intervals do not independently isolate `Send-OperatorFrame`. The calibrated
Appliance offset was approximately 17 seconds behind Host. See the
[probe record](../contrib/qualification/FIELD_ACCEPTANCE.md#subsequent-bounded-reverse-path-probe)
for the measured uncertainty and interpretation limits. A separate clock fix
in the working source does not establish a transfer fix or qualify the original
candidate again.

The exact RC2 subsequently passed its
[clock field program](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-clock-verification-040rc2).
One `heal` corrected the initial −17539 ms offset. The independent 300-second
sample reported −3 ms with a 1 ms uncertainty. RDP continuity was preserved.
This closes the measured clock gate for that source. It does not close the
128 MiB transfer gate or establish a cause for the earlier reverse-path delay.

The subsequent [RC3 field record](../contrib/qualification/FIELD_ACCEPTANCE.md#incomplete-transfer-verification-040rc3)
includes a successful first-attempt push and an incomplete pull. At block 30
the Host observed no response bytes before the 45-second deadline. The exact
worker record was completed with an SSH reply time of 372 ms. That record
precedes response publication and does not establish when the slot was readable.
There were no reported QGA read timeouts or connection losses. Earlier counters
did not distinguish open failures from empty files. The saved evidence therefore
does not isolate the physical delay further.

A separate local regression exposes an additional Host-side defect: reading
an entire MiB inside one three-second QGA exchange can discard an accumulated
prefix when a later wire read times out. Bounded polls correct that defect.
This synthetic failure includes QGA timeouts, unlike the saved field result.
It must not be presented as a confirmed explanation or field fix for block 30.

The exact RC4 later passed the
[operator-reported 128 MiB round trip](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-transfer-verification-040rc4)
on the first attempt in each direction. Both outcomes were retained without
new copy dispatch after MCP restart. The final response-read label was
`complete`. Read-fault counters were absent in that reported program. This
closes the transfer gate for RC4's exercised route while preserving the
unresolved physical cause of the earlier RC3 delay. It does not qualify a
forced RDP reconnect. Remaining stable gates are in the
[0.4.0 readiness review](STANDARD_OPERATOR_040_READINESS.md).

## Approved RDP session continuity

Read the effective idle-session limit and active-session limit before a long
transfer. Establish policy precedence using approved resultant-policy or
deployment tools. A registry value alone may not establish effective policy.

[Microsoft RDS guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/troubleshoot-unexpected-rds-session-locks-or-disconnections)
distinguishes input-idle limits from total session-duration limits. The
[Terminal Services policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver)
describes idle time without user input and Computer Configuration precedence
when both policy levels configure the same setting.

Use the approved operating mode. Do not add synthetic pointer automation or
alter policy as part of this candidate. If approved conditions cannot cover the
transfer, retain that limitation instead of claiming unattended acceptance.
These diagnostics do not automatically read or change session policies.

The [targeted field prompt](../contrib/qualification/MCP_RELIABILITY_FIELD_PROMPT_RU.md)
defines the remaining operator checks. Production policy evidence cannot be
inferred from local fixtures.
