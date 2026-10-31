# Local qualification, 31 October 2026

Scope: macOS ARM64, disposable files and loopback. This records local runtime checks, not production or cross-platform acceptance. Hosted workflow configuration was unchanged; the publication commit requests CI skipping while Actions remediation is deferred.

| Runtime/check | Result | Tests | Duration |
|---|---|---|---|
| python-3.10.22 | passed | 86 | 3.695 s |
| python-3.11.17 | passed | 86 | 3.711 s |
| python-3.12.15 | passed | 86 | 3.724 s |
| python-3.13.16 | passed | 86 | 3.703 s |
| python-3.14.5 | passed | 86 | 3.746 s |
| hygiene | passed | — | 0.087 s |

Native/parser fixtures were enabled for every interpreter run, with no skipped tests: .NET helper execution using synthetic input, real PowerShell parsing, helper environment restoration, PE architecture checks, durable transaction/restart/conflict cases, cancellation including queued stdio requests, policy denials and real HTTP credential ownership. The suite includes the earlier control-channel, transfer, proxy and filesystem regressions.

## Real worker workload

PowerShell 7.6.9, actual `bastion_worker.ps1`, 10,000 soak transactions plus functional cases. Final worker SHA-256: `bf0efe017c144d1da4a0f7412ef921cda76fe997a3170f9dd62354c740b020f8`.

- Result: **passed**; soak duration **181.213 seconds** with eight Host request threads and four worker runspaces.
- Fast stream response during a concurrent slow read: **52 ms**, against the fixture limit of 800 ms.
- Post-warmup sampled working-set growth: **10944512 bytes**; thread-count growth: **0**.
- Final active command jobs, pending mux operations and mux sessions: **zero**.
- Binary I/O, delayed response after half-close, striped file sizes 0/65,536/131,072/131,073 with Unicode/apostrophes, restart without replay, cancellation, remote timeout, malformed envelope and refused connection: **passed**.

Windows handle accounting is **not verified**: .NET returned zero on macOS, which the harness explicitly treats as unsupported. Sampled resource growth under a finite workload does not prove indefinite leak freedom. This final run includes flushed metadata/response publication and the 100,000-record tombstone capacity guard.

## Release and lab artifacts

.NET SDK 10.0.403 built the native helper with zero build warnings/errors. The helper ran locally through .NET; its unsigned self-contained `win-x64` and `win-arm64` outputs were cross-compiled and their PE machine types checked. This does not establish execution on either Windows architecture.

Separate allow-listed release packages were prepared for x64 and ARM64. Both have `status: unsigned` and `qualified_windows: false`. The temporary artifacts stay under ignored `build/`; no executable, key container, installer or environment file is tracked. Certificate-store access, signing, Windows installation/startup and signature-policy enforcement were **not performed**.

Synthetic VM seeds were prepared for both guest architectures with a custom provider, loopback addresses and no VPN key/installer. No disk or running Windows guest was created. VM seed preparation is **prepared_only**, not guest, QGA, RDPdr or driver acceptance.

## Retained evidence and open boundaries

Local machine-readable records: `build/qualification/final-matrix/matrix.json` (source inventory and log SHA-256), per-interpreter logs in the same directory, and `build/qualification/worker-10000.json` (worker hash and resource samples). Build/release/lab artifacts are local and ignored. Reproduce them using [the hardening guide](HARDENING_AND_QUALIFICATION.md).

Unverified: Linux runtime; Windows x64/ARM64 runtime; Windows PowerShell 5.1; real redirected drives and RDP reconnects; VPN provider version/driver behavior; code-signing certificate and enterprise execution policy; crash/power-loss durability beyond the exercised worker restart; external process/side-effect termination after cancellation. No customer environment, ViPNet key or signing certificate was accessed, imported or transferred.
