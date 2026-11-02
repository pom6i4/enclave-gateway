# Autonomous closure of Windows preparation, PKI, lifecycle and migration

Status: **passed within the isolated functional/emulation and disposable-PKI scope**. All four agreed items have completed acceptance; no client or production qualification is inferred.

The tested product scripts are `5443d33a274267cd0735b8becba896db3f5cbd41`, following `3b221fe721a4685859d5df1eefafe43d752ad95a`. The final public lifecycle runner is `2acb86f6e553e9ba9307dcd64ed12ef331b426a9`; that follow-up changes only a qualification variable name and adds a whole-flow test. Product/preparation/installer bytes are unchanged from `5443d33`. No client environment, production keys, hosted workflow changes, dispatches or CI acceptance were used.

## Implemented behavior

Preparation flushes an atomic generation journal before task removal and publishes readiness atomically last. Source-pinned QGA recovery never enters MSI/driver enumeration. Only ObjectNotFound means task absence; other lookup failures block readiness. Recovery rejects mismatched generations, reparse paths, changed installed code, unfinished Setup and concurrent/running preparation; its stdout is JSON only.

The public `disposable_windows.py --full-lifecycle` command binds disk/media/source evidence before boot, checks the installed source and completed Setup, requests firmware/TPM once per boot, fully stops VM/TPM, boots without installer media, compares unchanged preparation files and performs scoped cleanup. It records working-tree hashes and the Git base independently.

The disposable authority creates nonexportable Windows CNG keys and issued code-signing certificates, loopback CRLs with critical IssuingDistributionPoint scopes, OCSP and a legacy Authenticode TSA. Offline chain flags distinguish actual Revoked, unknown revocation status and NotTimeValid. Cache and signer expiry occur after real guest time passes a five-minute lifetime. Native nonce deadlines remain ten seconds.

Migration authenticates a new v2 CMS package in a separate directory. Dry-run changes no installation files/ACLs; unsigned v1 metadata supplies no executable paths, pins, channel or release ordering. Atomic v2 staging preserves the old generation; repeated Migrate resumes a matching interrupted target. MigrateRollback atomically withdraws selection, retains files and high-water state and never activates unsigned legacy code.

## Completed checks

| Gate | Observed result | Private evidence under the current run |
| --- | --- | --- |
| macOS interpreter matrix | Python 3.10.22 / 3.11.17 / 3.12.15 / 3.13.16 / 3.14.5: 146 tests per interpreter, one explicit skip, including the complete qualifier success/failure/cleanup flow; strengthened nonterminating scheduler-error regression also passed on all five | `matrix-lifecycle-cleanup/`, `task-query-focused-matrix.json` |
| Windows ARM64 exact final source | 145 tests, 16 explicit skips, 18.332 seconds | `arm-source-exact-final-v2.json` |
| Windows Server x64 exact final source | 145 tests, 26 explicit skips, 393.676 seconds; same per-test deadlines after an explicitly recorded environment restart | `x64-core-final-v4.json` |
| Crash-safe finalization | Actual SYSTEM task deletion followed by child kill, and actual readiness-file sharing failure, recovered without MSI on both Windows architectures | `arm-source-exact-final-v2.json`, `x64-preparation-final-evidence.json` |
| Task-query failure | Previous source incorrectly published readiness for a nonterminating ResourceUnavailable error; fixed source blocks it and preserves the previous record | `task-query-regression.json` |
| Issued PKI | 12 cases on ARM64 and x64; independent Revoked for CRL/OCSP, Unknown+Offline for stale/cache, NotTimeValid for expired timestamped signer | `arm-pki-final-evidence.json`, `x64-pki-final-evidence.json` |
| Native PKI nonce timing | Nine probes per architecture, ARM64 141–239 ms and x64 1168–1442 ms; ten-second limit unchanged | same PKI evidence |
| CMS certificate rotation | New pin required; overlapping pins allow upgrade; retired pin cannot select the old generation or alter current selection | same PKI evidence |
| v1 migration | Nine cases under SYSTEM on ARM64 and x64, and under a dedicated standard SID on ARM64; actual staging crash, resume, rollback and unchanged legacy bytes | `migration-system-v3.json`, `migration-standard-v2.json`, `x64-migration-final-evidence.json` |
| Versioned installation regression | Eight upgrade/rollback/crash/tamper cases and twelve CMS/order/channel cases on x64 | `x64-upgrade-final-evidence.json`, `x64-release-policy-final-evidence.json` |
| Installed artifact | sdist → wheel → clean venv outside checkout; both entry points and installed provisioning passed; wheel recovery/preparation bytes equal final source | `installed-package-final/result.json`, `closure-pending.json` |
| New blank-disk lifecycle | Passed, including final cleanup; first cold request 31.570 s, next cold request 40.951 s, one 120-second attempt per boot, unchanged preparation records | `fresh-cli-final-v1/` |

Windows skips represent unavailable optional fixtures or a POSIX-only managed TPM backend; they are not a broader platform pass. The retained runtime payload is unchanged native product code from the preceding accepted cohort, verified by exact artifact hashes; this task changes preparation/release scripts and qualification tools.

## Preserved failures and observer boundaries

Original failed and invalid reports were retained. They include a migration directory rename rejected under an open deployment lock (fixed by atomic selection withdrawal), recovery stdout contamination (fixed by suppressing informational output), unscoped lab CRLs sharing cached issuer data (fixed by explicit scopes), and a scheduler lookup falsely treated as absence (fixed with an independently reproduced regression).

The first x64 source run retained a 60-second recovery-fixture timeout while other workloads were active. A later launcher exited with an AccessViolation in stock PowerShell TypeTable initialization before any tests ran. The same stock initialization crash recurred during a read-only certificate-store cleanup check after the PKI suite had passed. Independent read-only WinCrypt enumeration verified all 20 exact owned certificate thumbprints absent from LocalMachine Root/My, after which the owned VM/TPM stopped successfully. Independent memory inventory showed 3.1 GiB available and no native test hosts. A full owned VM/TPM restart restored stock PowerShell initialization; the identical final source suite then passed with the same limits. This records an environment recovery, not proof that every future TCG/PowerShell initialization is crash-free.

Premature archive/readiness launchers, the Windows encoded-command length limit and a large-file transfer deadline remain invalid observer records. A hash-checked short loader and a separate 600-second file-transfer budget corrected those observers; native nonce and cold-security deadlines were not relaxed. Earlier installation candidates were explicitly stopped before their security gate when source changed; their disks/logs remain aborted and are not counted as passes or final-source failures.

The preceding `5443d33` blank-disk run passed installation, first cold security (38.045 s), full VM/TPM poweroff, unchanged preparation records and next cold security (38.754 s), each on one 120-second request. Its overall public-command result remains **failed**: a local PowerShell string shadowed the imported cleanup function. The correct callable subsequently stopped that exact VM/TPM. Commit `2acb86f` fixes the shadowing; a whole-flow regression covers success, post-install failure and cleanup failure. The earlier failed report was not relabelled or used as the final whole-command pass.

Only public installation ISO bytes were relocated to external media after full flush and uncached SHA-256 verification; the original entry paths remain usable. VM disks, software TPM state, seed media, credentials and certificate/key state stayed local. Stopped aborted images were compressed only after full logical-sector comparison; original failure logs remain. No evidence was discarded to free space.

## Final blank-disk lifecycle

A new standalone 32 GiB qcow2 was proved empty before its first boot. The public command ran from clean committed source `2acb86f6e553e9ba9307dcd64ed12ef331b426a9`. Source/media/driver hashes were bound before boot; the seeded and installed preparation script both matched SHA-256 `5c0a57a96da316894cbaa09d43379616b8ce7fd6470f2bd2e5eca37ecf77111b`.

The completed report has `status=passed`, `phase=complete` and `cleanup=passed`. Setup completed, readiness revision 2 was present, the SYSTEM preparation task was absent, native-MSI QGA was running, autologon was not configured and guest answer files were removed. Secure Boot and TPM-present/ready checks passed on their first cold request in **31.570 seconds** at the unchanged 120-second deadline.

The runner fully stopped the actual QEMU and software-TPM processes, then booted the installed disk without installer media. The boot identity changed; preparation source, readiness/progress hashes and modification times remained identical. The next cold security request passed in **40.951 seconds**, again one attempt at 120 seconds. The entire public command, including its owned-resource `finally`, passed. Final VM/TPM state is stopped; images and diagnostics are retained privately.

Two optional read-only QGA file observers were unavailable before readiness (connection refused and a runtime error); neither ran a guest process nor queried TPM. Their records remain separate from acceptance. The public runner alone made the two security requests; there was no TPM warmup or hidden retry.

A frozen private inventory indexes **189 reports/logs**, including preserved failures, with SHA-256 `9421ea8cfd5ada8ac40621f949d77208da8a1f71cb616c443c7f303f336ce7f7`. It excludes VM data, seed material and credentials. Raw evidence, keys and installation binaries are not published in the repository.

A later documentation-publication check initially ran in a host sandbox that denied local TCP/Unix socket operations (`EPERM`), producing four failures and six errors. Its log is retained separately from the frozen inventory above. An intermediate opt-in invocation then supplied the generic runtime artifact in place of the dedicated askpass helper, causing two helper-fixture failures. Final publication checks use a separately rebuilt `native/askpass` artifact, real PowerShell/.NET and local-socket access. These invocation corrections did not change product code or acceptance limits. All attempts are retained separately in `publication-validation.json`.

## Scope

These are isolated functional/emulation and disposable PKI results. Physical TPM attestation, hardware/EDR/WDAC acceptance, WHPX performance, production CA/EV/HSM trust, TSA clock accuracy, production certificate-service availability and proprietary licensed provider interoperability remain outside this task. CMS and native policy still require a currently valid signer even when an Authenticode timestamp preserves OS signature validity. No production signing or client/provider acceptance is inferred.
