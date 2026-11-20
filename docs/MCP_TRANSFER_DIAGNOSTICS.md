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
| `destination_committed` | Final receipt accepted or Host download atomically published |

Missing fields mean that boundary was not observed. A verified part is not a
whole-file commit. Empty uploads use one zero-byte part. Empty downloads have
no data parts. No deployment paths or identities are added to this structure.

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
QGA committed reads can include validation and erasure. Their duration does not
isolate QGA wire latency from a blocked guest filesystem read. Response waiting
does not independently measure the VPN or RDP network. Ordinary `timings_ms`
may contain additional operation timings.

Local fixtures use a controlled clock to model a 61.7-second read. They verify
deadline retention and no replay, not WAN performance. A late download must
preserve its previous destination and remove only its own temporary file.

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
count nor highest observed offset alone proves which block failed. The old
field discrepancy remains unresolved until its private records are examined.

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
