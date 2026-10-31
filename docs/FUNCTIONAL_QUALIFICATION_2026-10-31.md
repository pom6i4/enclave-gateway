# Functional qualification: 2026-10-31

This record covers the six mechanisms in [the functional hardening guide](FUNCTIONAL_HARDENING_2026-10-31.md), including the final UTF-8 retention fix. It supplements the earlier qualification record for the parent commit `df7dc18`.

## Executed on macOS ARM64

The explicit interpreter matrix ran with the local PowerShell 7.6.9 and .NET 10.0.403 fixtures enabled. Every interpreter ran the entire suite, including real PowerShell parsing, a real SSH stdin wrapper against a fixture executable, the native credential helper on macOS, local authenticated HTTP, POSIX owned process cancellation, rooted file synchronization, private backend process/environment/RPC, retention and provider plan/staging fixtures.

| Actual Python | Tests | Skips | Elapsed seconds |
|---|---:|---:|---:|
| 3.10.22 | 110 | 0 | 5.84 |
| 3.11.17 | 110 | 0 | 5.661 |
| 3.12.15 | 110 | 0 | 6.211 |
| 3.13.16 | 110 | 0 | 5.61 |
| 3.14.5 | 110 | 0 | 5.88 |

The required plain command `PYTHONPATH=src python3 -m unittest discover -s tests -v && python3 scripts/verify_hygiene.py` also passed: 110 tests with six optional runtime-fixture skips. Those same six checks passed without skips in the explicit matrix. This is macOS interpreter coverage; it does not establish Linux or Windows runtime coverage.

The real portable PowerShell worker passed 10,000 transactions in 190.527 seconds using disposable files and loopback sockets. Fresh evidence verification and request/response instance binding were enabled. The run included script execution, fairness during a blocked read, binary/striped/empty-file transfer, half-close, restart without replay, cancellation, remote timeout, malformed envelopes and refused connections. Fast mux I/O during the blocked read took 77 ms. Across 101 samples, post-warmup growth was 14,958,592 bytes and 0 threads. The final sample had zero active jobs, pending mux operations and streams. macOS does not supply the Windows handle count. These sampled bounds do not prove indefinite leak freedom.

Local evidence (ignored build artifacts):

| Evidence | SHA-256 |
|---|---|
| `build/qualification/autonomous-qualified-matrix/matrix.json` | `dea728c13ba4d85e03437e59bc039ae0e68c0644103b673139b62fb1e92778f3` |
| `build/qualification/autonomous-bound-worker-10000.json` | `d69a0c0ce8a9d4025883eda583754a633e7fc0c5c29c2a765bac1487f06f12cd` |
| Qualified worker source | `169a47a306392bfef9e3daab4fdfbea5106de063b336fabda625620ed4320531` |

The matrix records SHA-256 values for 72 source/test/script/native files and for each command log. All recorded source hashes were compared with the final working tree. Earlier `autonomous-*` experiments are superseded by the two reports above.

## Built and inspected, not executed on Windows

The new runtime and existing credential helper were cross-published as self-contained Windows x64 and ARM64 executables. Native runtime builds completed with zero warnings/errors. The complete allow-listed packages were prepared under `build/release-complete-x64` and `build/release-complete-arm64`, each containing both executables, four agents and two release scripts. Manifest hashes and PE machine types were read back and verified. Every manifest says `unsigned` and `qualified_windows: false`.

| Runtime | SHA-256 |
|---|---|
| Windows x64 | `5133a578f670199fa4dc4d3f0f42f8f2a233034a063a7ee18257363e17f465c8` |
| Windows arm64 | `b9b6eddc12b0fc96f711c675d74d92ce1fca9b08a0866ef4c5767698524dbc52` |

`native_windows.py` prepares a runnable isolated Windows check for handle-relative I/O, hardlink/traversal rejection, optional symlink rejection, and descendant termination using a retained process handle. The Windows worker fixture now requires the runtime and an explicit unsigned-lab flag. These Windows checks were not executed here.

## Acceptance boundaries

- No customer contour, real provider connection, VPN key container, signing certificate/private key, OS account creation or production deployment was used.
- Windows native API behavior, cross-account UID/SID launch, real Windows PowerShell 5.1/OpenSSH/EDR/WDAC, Authenticode trust/signing, QGA/RDPdr and VPN drivers remain unqualified on this machine. The backend process fixture uses the current UID and is not a cross-UID acceptance result.
- All four provider lifecycle actions have the plan/approval/staging/controller execution mechanism. Controller execution was simulated; an administrator-reviewed, vendor-documented recipe for the exact product/version is still required. Generic recipes do not establish ViPNet/Kontinent support for every version or architecture.
- Scoped sync is a per-file atomic merge of regular files, without deletion of extra destination files or an atomic whole-tree commit. Arbitrary execution retains the selected remote account's OS capabilities. Journal tombstone identities are never expired to permit replay; a full namespace refuses new dispatch.
- Repository hygiene and whitespace checks passed. Hosted Actions configuration and billing are unchanged. Publication uses `[skip ci]` while hosted CI remediation remains deferred.
