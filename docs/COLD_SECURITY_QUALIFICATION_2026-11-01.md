# Cold Windows security readback — 2026-11-01

This follow-up addresses the first-use security observer timeout retained in the [expanded qualification record](AUTONOMOUS_QUALIFICATION_2026-11-01.md). That historical failure remains a failure; its later warm repeat is not cold acceptance.

## Change and acceptance gate

The disposable Windows fixture now executes `windows_security.ps1` once, with the existing 120-second QGA deadline. It retains `Confirm-SecureBootUEFI` for the firmware check. TPM presence comes from the local `Win32_Tpm` instance, and readiness requires its successful `IsReady` method result. [Microsoft defines this result](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-tpm-isready) as full TPM/system provisioning; activation or ownership flags alone are insufficient. A nonzero provider return code, missing device, false readiness, ambiguous instances or malformed evidence fails closed.

This avoids the wider [`Get-Tpm` inventory](https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm?view=windowsserver2025-ps), which also exposes authorization, lockout and self-test fields. No TPM initialization, ownership change, key extraction, registry substitute for firmware state, warm-up request or automatic security-query retry was added. Stage timings are returned with the evidence. The fixture persists completed setup/post-install checkpoints before the cold gate, so a late failure no longer discards them.

The candidate source inventory contains 97 source/test/qualification files; its canonical SHA-256 is `a5575a9f006eb2f0b5d3c8e23fe15b5d4bfb4349f95765a9638af2ef96eb0441`. The first-install gate uses a new empty disk, fresh UEFI variables and fresh software TPM state with the same x64 TCG configuration (two CPUs, 4 GiB RAM). QGA readiness polling reads setup flags and the machine-stage marker. It does not query TPM or Secure Boot before the single security attempt.

## Evidence

Private evidence is retained under `build/cold-security-20261101`; no image, installer, credential or key is committed. The inventory binds 19 evidence files and the 97 source files; `evidence.json` SHA-256 is `3bae6b7890108ac5177de03a9e4281a49eeea418d458910c995d8ff77a91b322`. Final shutdown was verified: the VM is stopped and its software TPM quiesced.

| Check | Result | Evidence |
|---|---|---|
| Python 3.10–3.14 with real optional PowerShell/.NET fixtures | Passed, 132 tests collected per interpreter with platform skips recorded | `matrix-v2/matrix.json` |
| Windows ARM64 / Windows PowerShell 5.1 | Passed, 132 tests, 14 skips; AllSigned retained | `windows-arm64-suite-v2.{json,log}` |
| Previous algorithm on a cold power-on of the retained OS | Diagnostic only: 44.870 seconds host time; 4.946 seconds inside the timed guest segment | `legacy-cold-profile.json` |
| Dedicated readiness query on a separate cold power-on of the retained OS | Passed, first attempt, 44.503 seconds host time under the unchanged 120-second deadline | `cim-cold-profile.json` |
| First security query after a new Windows installation | Passed on the first attempt, 69.944 seconds host time within 120 seconds; Secure Boot enabled, software TPM present/ready | `fresh-v11/result.json` |
| Independent stock-cmdlet comparison after the first cold gate | Passed; both firmware status and Get-Tpm present/ready agree | `fresh-v11/post-acceptance-stock-cmdlet-comparison.json` |
| New Windows Server source suite | Passed, 132 tests in 537.873 seconds, 24 skips; synthetic PowerShell cases use the explicit 240-second fixture budget, separate from the unchanged 120-second cold gate | `fresh-v11/source-tests.{json,log}` |
| Two further full-power-off boots, first query per boot | Passed, one attempt each: 73.405 and 60.768 seconds under 120 seconds; VM and software TPM stopped after each case | `fresh-v11/cold-boot-{1,2}.json` |

On the fresh installation, the timed guest segment was 30.114 seconds: Secure Boot 24.570 seconds, device enumeration 3.360 seconds and readiness method 0.671 seconds. The host measurement was 69.944 seconds; remaining cost includes process startup and output handling. These are observations, not a general latency guarantee.

The retained-OS profiles are not substitutes for a fresh-install first-use test. Their guest segment excludes PowerShell startup and output serialization; the host deadline includes those costs. They do not independently localize the earlier fresh-install timeout or establish a universal performance comparison.

The first Windows runtime test used an unsigned temporary script file under AllSigned and failed. The synthetic provider fixture now uses the same in-memory encoded-command entry point as QGA, without changing execution policy or certificate trust. Its failed candidate log remains retained. Negative cases cover disabled Secure Boot, absent/ambiguous TPM, false readiness, provider error and invalid response types.

## Boundaries

All machines, data and accounts are disposable laboratory resources. No client environment, proprietary VPN keys, production signing keys, workflow changes or hosted Actions were used. Firmware enrollment uses the existing vendor template; software TPM results do not establish physical TPM/EK/PCR7 attestation. These finite observations apply to the recorded software-emulation environment, not every hardware or cold-start condition.
