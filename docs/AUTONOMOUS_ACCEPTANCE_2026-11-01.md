# Isolated acceptance record — 2026-11-01

This record covers the local acceptance, signed release metadata, native trust-host and startup-task changes following parent commit `6a5a69e`. All guests and accounts were disposable. No client network, proprietary provider installation, client keys or production signing keys were used. Hosted Actions were not invoked or modified.

## Results

| Check | Observed result | Scope |
| --- | --- | --- |
| macOS Python 3.10–3.14 | 140 tests per interpreter; 1 platform skip | Real optional PowerShell/.NET checks enabled separately from the standard local plan |
| Linux source suite | 140 tests; 11 optional/platform skips | Isolated ARM64 guest |
| Windows ARM64 source suite | 140 tests; 14 optional/platform skips | Native Windows PowerShell 5.1, AllSigned |
| Windows Server x64 source suite | 140 tests; 24 optional/platform skips | Actual x64 guest under TCG; final source export and binary provenance checked |
| Installed distributions | PASS on macOS, Linux and Windows ARM64 | sdist → wheel built from extracted sdist → clean venv outside checkout → both CLI entry points and actual installed `egw init`; resource hashes checked |
| Local plan runner | PASS | New private output, failed-step retention, deadline reaping and owned disk/NVRAM/TPM checks; actual new-VM cleanup also exercised |
| Native provider comparison | 5 checks passed | Stock signature/hash agreement, Unicode, tampered/unsigned files and runtime image identity |
| Native framing | 6 checks passed on ARM64 and verified x64 | BOM, Unicode, modification after initialization, malformed/oversize input and one-shot mode; actual trust policy asserted |
| Revocation failure | 3 checks passed on both Windows architectures | Otherwise valid issued lab chain without revocation data; strict startup and nonce both reject it; fixture keys nonexportable and temporary certificates removed |
| Mixed workload | 2000 transactions passed | 200 native commands and 1800 mux operations, plus transfer/restart/cancellation/fault checks; original deadlines and fairness bounds retained |
| Post-warmup resources | +12 handles, +0 threads, +2543616 bytes | Sampled parent-worker bounds; not an indefinite leak-freedom guarantee |
| Worker faults | 4 checks passed | Actual worker kill after an effect, native trust-host ownership, corrupted execution reply and corrupted child stdout; no replay |
| Signed release policy | 12 checks passed | Authenticated CMS metadata, downgrade/sequence/channel rejection, rollback high-water retention and rejection preserving selection |
| Versioned installation | 8 checks passed as SYSTEM and 8 as a standard SID | Upgrade, rollback, payload/publication corruption, actual staging-process crash and deployment exclusion |
| Cold ARM64 system worker | 0.333 s, 0.311 s, 0.302 s | One new OS boot after VM/TPM-process poweroff; three new workers, exactly first nonce and sequence 1 for each, unchanged 10-second deadline |
| Cold redirected RDP worker | 0.505 s | A separate full VM/TPM-process poweroff, new pinned RDP connection, standard SID/session and redirected spool; exactly first nonce, sequence 1, unchanged 10-second deadline |
| Verified x64 first worker nonce | 4.685 s | New signed worker with current policy; startup reported separately, not a 10-second process-launch guarantee |
| New Server installation | 4600.9 s; first security request 103.466 s / 120 s | Actual public CLI disk/media/installation flow, SYSTEM startup-task path, no SetupComplete hook or automatic logon; Secure Boot and software TPM present/ready |
| Final preparation cleanup | PASS | Readiness revision 2 published after actual SYSTEM-task self-deletion; matching completed generation recovered without media/MSI or agent restart; survives reboot |
| Post-finalization security | 27.571 s / 120 s, one request | Secure Boot and software TPM readback after that reboot |
| Owned resource cleanup | PASS | Linux, Server x64 and ARM64 VMs stopped; managed TPM backends quiesced; own RDP client exited |

The full fresh Server installation used the startup-task implementation before the readiness-ordering correction. The final correction was then qualified through actual SYSTEM-task execution/self-deletion and reboot on that same installed disposable OS, plus real-PowerShell conflict/deletion-failure tests. The complete installation was not repeated from a blank disk after that correction. This is composed evidence, not a claim that one final-source end-to-end installation transcript covers every change.

## Trust policy and failed attempts

Earlier candidates exceeded the challenge deadline during Windows trust-provider work. Diagnostic observers with extended deadlines were retained as diagnostics and were not counted as ten-second acceptance. The final resident host performs online initialization, then fresh file hashes, Authenticode verification and strict current-time/code-signing chain validation for each nonce using cached revocation material. Missing or expired material fails closed. Independent `X509Chain` validation is mandatory because a flags-only WinTrust candidate accepted an unknown revocation status under the OS offline publishing policy; that candidate failed the negative test and was not promoted. No successful signature result is substituted from startup.

An earlier x64 observer unpacked an old archive over a newly uploaded runtime. Those records are marked `invalid-observer-*` and excluded. The replacement checks the new archive digest, unsigned runtime SHA-256 and PE architecture before signing, then verifies the signed package and asserts the actual nonce policy. Cold passes have one first nonce per instance, with no attestation warm-up or hidden retry. Startup and challenge time are separate; neither the passing sample nor cached URL retrieval establishes a real-time latency guarantee for arbitrary hosts.

## Provenance and private evidence

Final code inventory SHA-256: `5e083dc044c7be227ae68f13d266476eb28f98136bab2535f57c2ed50236aa35`. The inventory is the canonical sorted JSON mapping of repository-relative `.py`, `.ps1`, `.cs`, `.csproj` files under `src`, `scripts`, `tests`, `native`, excluding `bin`, `obj`, `__pycache__`. The private inventory stores each file hash. Final allow-listed evidence index SHA-256: `fe3b3fdf23ef556f478a3a2d07edce14ff5ce59d0abc800dad14097cc20b7312` (`evidence.final.json`).

- ARM64 signed runtime: `113aba5dd1ddde3fa2a94f29b0391684e5f15b4d990e1a0b9b5c5bd3243e72c3`.
- x64 unsigned runtime checked before signing: `e2aa9f9cdc23642057acef495feb660da451870d59c63103570c06ae5d5fb11c`.
- x64 signed runtime: `281b44b8fd0892f22e350066fda21a2e6a647f22d9819ca4490d35de2800d941`.
- Verified x64 source/runtime archive: `7135128aa181580eab1e707a93943e58e31d3873d6cd02cc60718c5984fa9888`.

Private records remain below `build/final-autonomous-20261101/`: `matrix-closure-verified`, `local-run-closure-verified`, `sources.final.json`, distribution records, `worker-loopback-strict.json`, `worker-faults-strict.json`, `release-policy-strict.json`, `upgrade-strict.json`, `standard-upgrade-strict.json`, cold poweroff/nonce records, `x64-verified-*`, preparation/reboot records and cleanup records. Logs, VM images, seed/answer media, generated credentials, certificate stores, packages and binaries are excluded from Git. Earlier failed/invalid observer records are retained privately.

## Remaining boundaries

Native Windows-host managed TPM is **OPEN**. The tested Windows QEMU rejects `-tpmdev`; the checked upstream [QEMU build configuration](https://github.com/qemu/qemu/blob/master/meson.build) excludes Windows TPM emulation. Capabilities report this and provisioning rejects it before seed/disk mutation. Providing this feature requires another backend or an upstream port; it was not implemented or accepted here.

The startup-task mechanism avoids SetupComplete dependency, but a particular OEM edition/licence/activation service was not qualified. TCG and software TPM results establish functional emulation, not WHPX performance or physical TPM attestation. Issued production PKI, successful production CRL/OCSP retrieval and renewal, actual revocation/expiry rollover, trusted timestamp services, EV/production signing and client/provider acceptance remain outside this isolated lab. CMS metadata and native chain policy require a currently valid signer. Legacy revision-1 installations require explicit migration as described in [the guide](LOCAL_ACCEPTANCE.md).
