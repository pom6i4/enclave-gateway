# Final-source blank-disk installation acceptance — 2026-11-02

**PASS.** The remaining blank-disk installation check is closed for product source commit `44a3af137815a07a6329ff5104ee8fe62b1566cd`. A new isolated Windows Server 2025 Standard Evaluation x64 installation completed using the final startup-task/readiness-ordering implementation. No product changes or manual guest intervention were needed.

## Scope and results

The run used QEMU/TCG, two virtual CPUs, 4 GiB RAM, Secure Boot, a new software TPM state directory and restricted user networking. The provider was `custom`, with no provider installer or key path; Bastion was disabled. Existing lab media and approved QGA MSI bytes were reused, while the disk, NVRAM copy, TPM state, runtime directory and controller state belonged to the new run. No client environment, client credentials, production keys, signing service or hosted Actions were used.

| Check | Result |
| --- | --- |
| Empty disk before first boot | PASS: new 32 GiB qcow2, no backing file, all mapped guest extents zero and without guest data |
| Source identity | PASS: seed and installed `machine_prepare.ps1` match the committed bytes of `44a3af1`; the complete recorded code inventory matches that commit |
| Public provisioning entry | PASS: ordinary `egw init --create-disk` and `egw init --launch-installer --detach-installer`, invoked by the unmodified disposable fixture |
| Full installation through first security readback | PASS in 3699.632 s (61 min 39.632 s), one installation attempt |
| Preparation finalization | PASS: readiness revision 2, `StartupTask`, `completion_task_removed=true`, task actually absent and phase `complete` |
| Hook and account state | PASS: no SetupComplete hook, no automatic logon or persisted autologon password, no preparation failure marker |
| First TPM/Secure Boot readback | PASS in **29.137 s**, one request, unchanged **120 s** deadline; Secure Boot enabled, TPM present and `Win32_Tpm.IsReady=true` |
| Full poweroff | PASS: guest OS shutdown, QEMU stopped and the identified TPM backend process exited before the next start |
| Next boot | PASS: changed OS boot identity, task/hook absent, same installed script, readiness and progress hashes **and modification times unchanged** |
| First security request after power cycle | PASS in **44.775 s**, one request, unchanged **120 s** deadline; Secure Boot and full TPM readiness confirmed again |
| Power-cycle verification step | PASS in 222.536 s, including checks, shutdown, new boot and security readback |
| Final cleanup | PASS: owned VM/TPM stopped; temporary host sleep assertion released automatically |
| Local source regression suite | 140 tests in 10.984 s, one Windows-only skip; optional real PowerShell/.NET checks enabled |

The installation-readiness observer allowed up to 7200 seconds for slow TCG setup. That observer limit did not change either security request's 120-second deadline. No security warm-up, hidden retry, snapshot restore, readiness-file repair or manual task deletion was performed. Read-only phase diagnostics were not used to declare acceptance; the ordinary fixture and live QGA readback supplied the final checks.

The final-source run exercises the actual first-generation path: the initial disk was blank, so a previous readiness record could not select completed-generation recovery. SYSTEM-task cleanup finished before revision-2 readiness was published. Absence of the task on both boots and unchanged preparation records support that preparation was not automatically rerun after the power cycle.

## Provenance and retained evidence

- Source commit: `44a3af137815a07a6329ff5104ee8fe62b1566cd`.
- Code inventory SHA-256: `5e083dc044c7be227ae68f13d266476eb28f98136bab2535f57c2ed50236aa35`, matching the earlier final code inventory.
- Committed, seeded and installed preparation script SHA-256: `d6c349e505ed1a4a17975b7691b67448f418deec74b84bb2f51966ce870bbfbf`.
- Closure record SHA-256: `007b71d989525ce26525ad0f19aa098eb5b357cf5a0e2a905b86f9a339b3f641`.

Private records are under `build/fresh-final-20261101/`. `closure.json` indexes the two-step runner result, step logs, blank-disk/source proof, first-boot state, full-poweroff record, post-boot state, security responses and lifecycle result, together with observer hashes. `plan.json` and `observers/` retain the exact local invocation and checks. The installer, source suite and power-cycle steps completed successfully; no failed candidate was substituted for this pass.

The runner checked the generated configuration, VM name, actual attached disk and owned disk/NVRAM/TPM paths before cleanup. Separate host verification confirmed that the VM, its TPM backend and its temporary sleep assertion were no longer running. Credentials, answer/seed media, VM images, NVRAM, software TPM state, logs and binaries remain private and are excluded from Git.

## Boundaries

This closes the specific final-source blank-disk gap in the [previous acceptance record](AUTONOMOUS_ACCEPTANCE_2026-11-01.md). It is functional qualification of the tested Server evaluation image on a POSIX virtualization host with TCG/software TPM. It does not establish acceptance of another OEM edition/licence, WHPX performance, physical TPM attestation, native Windows-host TPM, production PKI/signing or a client/provider environment. Those existing boundaries remain unchanged.
