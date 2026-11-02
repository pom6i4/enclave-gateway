# Extended runtime qualification — 2026-11-02

Status: PASS for the source-bound ten-role execution `extended-final-v3`, its mandatory cleanup and independent postflight. Earlier failures remain recorded below; this is prepared-fixture functional acceptance.

Source commit: `1eb710badac45363714a4a490695b06dc8a1bcf7`. This follow-up covers the three requested extensions: both current Windows source suites, one source-bound extended runtime profile, and generated security cases. Hosted Actions were neither queried, dispatched nor changed. All accounts, credentials, certificates and data were disposable; no customer/provider environment or production key was used.

## Implementation and actual corrections

- Add `source_suite.py`, executed case receipts and a mandatory ten-role extended plan, plus optional integration into the full installation entry. Exact source hashes, expected source test count, platform, explicit skips and observer/tool identities bind each run. Old receipts cannot satisfy a new execution; nested tampering, missing roles, short soak, failed cleanup and drift fail acceptance.
- Load configuration, access policies and isolation maps with UTF-8 BOM support. The real Windows fixture first exposed that PowerShell-produced UTF-8 files were rejected.
- Merge only explicitly configured environment values into a selected Windows user's own environment for native `run-as`. The real before-fix probe returned a missing explicit value while correctly excluding ambient broker state. Corrected native probes preserve Unicode values and source imports, still exclude ambient broker state, and reject duplicate case-insensitive names, malformed keys, NULs and invalid values before command launch. SID/standard-account checks and noninheritance remain enforced; the temporary unmanaged environment block is cleared.
- Keep unsigned source immutable while exercising a separately signed lab worker whose body must match that source. Reject extra executable text around a signature comment block. Native binaries come from the current independently built package, not an older retained helper.

## Validation

| Check | Observed result |
| --- | --- |
| macOS Python 3.10.22 / 3.11.17 / 3.12.15 / 3.13.16 / 3.14.5 | 170 tests each; one Windows-only skip; actual optional PowerShell/.NET and dedicated askpass |
| Ordinary default suite | 170 tests; 12 explicit optional/platform skips |
| Linux current source | 170 tests; 13 explicit optional/platform skips |
| Windows ARM64 and x64 source suites | 170 tests and 24 explicit skips each; actual PowerShell/.NET/askpass; ARM64 15.075 s, x64 TCG 383.553 s; recorded parser observer 240 s, checkpoint observer 30 s / 120 s |
| Generated security cases | 3600 cases across paths, destination grants, RPC, HTTP, fragmented proxy input and mux half-close/drain, plus fixed/concurrent/recovery checks |
| Existing generated/crash regressions | Three seeds × 200 cases × three models; four actual journal crashes and eight VM-publication crashes |
| Unsigned build comparison | Two isolated builds; 20 identical final files; 29-component CycloneDX 1.6 SBOM validated against its declared draft-07 schema |
| Extended profile | All ten newly executed roles PASS, mandatory cleanup PASS, independent source/input/report/resource postflight PASS |
| Current installed packages | macOS ARM64, Linux ARM64, Windows ARM64 and x64: sdist → wheel → clean environment; both entry points and installed provisioning; matching current product source maps |

The actual RDP fixture stages 64 MiB + 1 byte in 1025 blocks. The source-bound root run disconnected after two remotely consumed blocks (1023 remained), then verified a different worker instance, preservation of the previous complete destination and rejected replay. The interrupted operation remains indeterminate; reconnection does not relabel it completed. Its owned task/client cleanup is checked separately.

## Final runtime evidence

The source-bound run passed both Windows ordinary suites, actual two-SID and two-UID isolation, QGA acknowledgement/restart faults, worker/trust-host kill and corrupt replies, ENOSPC/journal recovery, actual RDP disconnect/reconnect, all six generated models and the full long soak. Windows suite skips are explicit platform/optional fixtures, including POSIX process/UID cases, QEMU disk tools and separate native runtime cases; they are not silently counted as native runtime passes. Separate role receipts cover the listed actual runtime scenarios.

| Final soak measurement | Observed value |
| --- | --- |
| Requested / elapsed duration | 7200 / 7207.729 seconds |
| Open streams | 128 fast + 32 silent/slow |
| Mixed mux operations | 62802 |
| Maximum observed fast I/O | 947 ms; observation, not a latency gate |
| Sampled working-set / thread / handle growth | 4648960 bytes / 1 / 7 |
| Original growth bounds | 256 MiB / 64 / 64 |
| Native resource cleanup cycles | 94 |
| Final mux/transaction queues | Empty |

Growth uses the original sample baseline after 120 seconds of warmup, not cold-start allocation. The load also checks periodic byte-exact file round trips and command execution. Finite samples do not establish absence of intermittent or longer-term leaks.

The final inventory binds 100 nested reports/logs with SHA-256 `8a0004eaf260c01acb83d2277e4aa262e659f6cc33e36803856986168b46dc24`. Independent postflight rehashed every entry, checked every pinned input and current source, validated all ten receipts and confirmed all three owned VMs and both software TPMs stopped. Exact original profile bytes were restored; only the newly created lab signer, its private key and its temporary Root/TrustedPublisher trust were removed. Retained fixtures and earlier trust were preserved. Filled plans, raw logs, guest images and credentials remain private local evidence.

The matching unsigned release SBOM is [unsigned-1eb710b.cdx.json](qualification/unsigned-1eb710b.cdx.json), SHA-256 `3d51bd22e1293592f5528c8cb15e782da1643cddce0904ee5d69ff3decd9232c`. It describes the compared unsigned release files and recorded NuGet materials, not an operating-system inventory, production signature or customer deployment.

## Preserved failures and fixture provenance

The first ARM64 source suite exceeded the unchanged ten-second helper startup observer on its first empty-input .NET invocation. Its original failed report remains. An independent identical replay returned code 2 in 0.026 seconds without output; a subsequent whole suite passed. This does not establish a ten-second cold process-launch guarantee.

Two x64 TCG source runs failed the default 30-second PowerShell crash-checkpoint observer. The observer now reports that cause directly, reaps its owned process and retains the default. The explicit TCG profile uses a recorded 120-second checkpoint observer and 240-second parser observer; native ten-second nonce, product execution and single 120-second cold security gates are unchanged. Passing longer fixture observation does not qualify default-time performance.

Earlier Windows account previews retained an old helper/interpreter/state combination. The embedded interpreter's fixed `_pth` imported an older checkout despite PYTHONPATH; a hash-approved standard distribution now honors the selected source. Existing state ownership failed the current private-directory guard; fresh SYSTEM-owned state and separate read-only per-SID configuration were provisioned instead of weakening that guard. Exact original profile bytes were backed up for restoration; existing journals/tombstones were preserved.

Read-only large-stdin SSH previews also exceeded their unchanged 120-second operation budget and remain indeterminate. Separate traced probes recorded successful signature/native/child execution; those diagnostics do not replace qualifying case results. The final profile is functional acceptance on prepared fixtures and does not claim cold SSH startup or isolated hardware latency. Read-only diagnostics overlapped early stages of the first complete root attempt; they are not a cold-start proof.

The initial seedless restart of the existing Debian fixture did not expose SSH/QGA and failed a graceful stop observer. Exact QMP/disk ownership was verified before stopping only that idle lab VM. Reattaching its original virtio seed restored the pinned identity. Missing guest-agent materials were installed only after Debian archive signature and package SHA-256 verification. Strict SSH host-key verification was retained.

Initial private controller setup/argv/encoding errors and the schema validator's wrong-draft attempt remain labelled failures or invalid observers, not product passes. No failed case or old source receipt was silently promoted.

The first complete root run passed all ten roles, including its full 7207.987-second / 62784-operation soak and empty final queues, but correctly failed overall on its cleanup observer. Directly querying an absent scheduled task with `-ErrorAction SilentlyContinue` returned exit code 1; a subsequent successful enumeration confirmed both recorded owned tasks were absent. Exact replay reproduced that observer-only exit without a remaining task. Original profile/certificate restoration and all VM/TPM shutdown checks had passed. Its failed root report and pinned inputs are preserved. A new pinned controller enumerates tasks with errors enabled, checks exact identity before any stop/unregister, verifies absence afterward and records every task check.

A second attempt at the complete profile passed both source suites and confirmed the corrected cleanup, but its first principal sync was still pending when the unchanged 900-second whole-account observer expired. That failure remains. Separate stack-instrumented new-directory and existing-file replacement diagnostics completed, and the unchanged whole two-principal scenario subsequently passed in 204.766 seconds under the original 900-second observer. Those diagnostic passes do not establish the cause of the intermittent stall or erase it.

The third complete execution passed all ten roles and cleanup using another separate nonexportable signer, fresh receipts and the original deadlines; no prior pass was imported. The result qualifies the observed prepared fixture, not an absence of intermittent SSH stalls.

## Boundaries

This standalone extended run does not claim a new blank-disk installation. Earlier installation/PKI records retain their original source identities. Finite models, resource samples, process crashes, temporary signing and emulated guests do not establish indefinite leak freedom, controller-cache/physical power-loss durability, hardware TPM trust, production CA/TSA trust, accelerated x64 performance or licensed-provider interoperability.

Native Windows-host managed TPM remains unavailable with the tested QEMU executable: its actual `-tpmdev help` probe rejected that option. The fail-closed guard remains. A Windows guest using POSIX-hosted software TPM is separate evidence and cannot qualify that missing backend.
