# Disposable Windows qualification, 2026-11-01

This record covers separate Windows guests created for qualification. No client environment, existing VPN account, key container or production signing key was used. Hosted Actions and workflow configuration were unchanged. The earlier local/functional qualification records describe their own earlier source revisions.

## Isolation and provenance

The ARM64 guest runs Windows 11 Pro 26H2, build 26300.9457, on QEMU 11.1.2/HVF with four virtual CPUs and 8 GiB RAM. A second guest runs Windows Server 2025 Evaluation x64 under single-threaded TCG on the ARM64 host, with two virtual CPUs and 4 GiB RAM. TCG measurements are emulation results, not native x64 performance measurements.

Both guests have distinct disks, firmware state, TPM backends, QMP/QGA sockets and loopback-only forwarded ports. QEMU user networking uses `restrict=on`; no bridge, host VPN interface, route or client network is configured. RDP redirects only a dedicated disposable directory. Test accounts, SSH credentials and code-signing certificates were newly generated. Certificate private keys remain nonexportable inside the respective guest. Public lab trust is installed only inside that guest.

Windows media came from Microsoft; Python and .NET runtimes from their official distributions; VirtIO/QGA and WireGuard from their official publishers. The ARM64 Windows ISO SHA-256 is `8992f2d2cfd2fa647e579e9eb31fc21f34da8333c29b6170fde17d2ed6623e9c`, matching the published Microsoft value. Python 3.14.5 embedded ARM64 SHA-256 is `0c078f7646c3b13c2dce0bb690994e431ed5269788803deffb459ee9e78b684e`. Download inventories and other distribution hashes remain with the private local evidence.

UAC, Defender antivirus and real-time protection remained enabled on the ARM64 guest. Resident scripts and executables were signed with the disposable certificate and exercised with `AllSigned`. No Defender exclusion was added. Temporary unattended-login credentials were removed after setup. Private account configuration/state directories have separate ACLs.

## Defects exposed by Windows execution

- Handle-relative rename now uses `NtSetInformationFile` with the retained destination handle. Parent handles permit file writes while denying ancestor deletion; delete opens include read-attributes access. The variable-length rename buffer includes the native structure's minimum size, including one-character destinations.
- Native argv quoting preserves ordinary MSI switches and still round-trips empty arguments, quotes, spaces, Unicode and trailing backslashes. Native failures expose a numeric OS code without exception text.
- Windows principal backends retain required system environment variables regardless of spelling/case. Signature verification uses an absolute system PowerShell path.
- Host spool reads explicitly share read/write/delete access. Only missing files and sharing/lock violations are deferred; ACL denial remains an error.
- The worker derives transaction identity from the claimed filename, reads actual stream length, returns canonical failures for invalid envelopes and rejects mismatched payload IDs. Sharing violations during reading are retried only before journal dispatch or payload execution. Unrelated transaction responses remain unchanged.
- Native process creation, pipe writes and execution wait outside the dispatcher in bounded runspaces. Attestation has a separate bounded pool, preserving mux service while commands run. Completed pipelines explicitly dispose caller-owned input/output buffers, wait handles, processes and completed stream tasks. A standalone Windows PowerShell 5.1 experiment reproduced 761 additional handles with implicit buffers versus 16 with explicit buffers over 150 invocations, before collection. A separate 150-process experiment retained 50 additional handles with process-only disposal versus zero with explicit reader disposal.
- The supported VFS block maximum is 4 MiB, matching the nested Base64/envelope/stdin limits. The default remains 4 MiB; larger configurations fail validation.
- HTTP rejection now half-closes the response before draining at most 64 KiB of unread TCP input for at most 100 ms. Server x64 exposed a reset before the client received status 415; malformed-body/auth limits remain enforced.
- URI/JWT/PEM secret heuristics avoid repeated unbounded prefix matching on large scripts. Regression cases include long malformed candidates, actual credential redaction and registered fragments that overlap structured-secret delimiters; real 100 KiB SSH scripts run under both isolated accounts.
- Bootstrap forwards an explicit runtime path to immediate and registered startup and verifies it before registration. Relative paths resolve against the PowerShell working directory and persist as absolute paths, including Unicode paths. Registered launch uses the absolute system PowerShell path. An actual new logon exposed a 375-character Run command beyond its documented limit. Persistent startup now uses a SID-specific interactive task on logon and RDP reconnect with limited privileges, no stored password, ignored duplicate instances and unlimited resident execution time. UTF-8 parameters live beside the signed bootstrap; registration starts only the managed task and returns a requirement for fresh health attestation; successful registration removes the legacy Run value. Persistent startup waits for its redirected share.

## Recorded checks

The final evidence inventory below distinguishes OS execution, architecture emulation and deployment acceptance. The private `qualification-evidence.json` records the final source inventory and SHA-256 hashes for the referenced evidence. Binary packages and runtime logs remain ignored under `build/windows-lab-20261031`; private credentials, VM images and certificates are never committed.

| Check | Observed result | Private evidence relative to `build/windows-lab-20261031` |
| --- | --- | --- |
| Required macOS source suite | 119 tests, OK, 7 platform/opt-in skips; hygiene passed | `host-required-final-v2.log` |
| Python 3.10.22 / 3.11.17 / 3.12.15 / 3.13.16 / 3.14.5 | Each 119 tests, OK, one Windows-only skip; real PowerShell/.NET fixtures enabled | `../qualification/windows-lab-119-final-v2/matrix.json` |
| Windows 11 ARM64 source suite | 119 tests, OK, 13 platform skips; Windows PowerShell 5.1 and .NET helper enabled | `egw-windows-checks-result.json` |
| Signed native runtime, ARM64 and x64 PE on Windows ARM64 | Filesystem, Unicode/stdin/argv and descendant cancellation passed at default timing | `egw-final-native-result.json` |
| Windows Server x64 source suite | 119 tests, OK, 17 platform/opt-in skips; parser cap explicitly 240 s; suite 112.630 s | `x64/egw-x64-unit-check-result.json` |
| Signed native x64 runtime on Server x64/TCG | Functional cases passed with explicit `--time-scale 8`; signature stage cap 120 s | `x64/egw-x64-native-run-result.json` |
| Signed native x64 Askpass on Server | Unicode stdout passed; empty/multiline inputs rejected without stderr leakage | `x64/egw-x64-askpass-result.json` |
| Signed resident worker, 10,000 mixed iterations | 1,000 native exec + 9,000 mux I/O; 369.342 s; max exec 4,740 ms | `worker-final-10000.json` |
| Post-warmup resident resources | Working set growth 6,475,776 bytes, thread growth 0, handle growth 7; original bounds retained | `worker-final-10000.json` |
| Dispatcher fairness and envelope handling | Fast mux during native launch 80 ms / slow read 62 ms; pre-dispatch sharing retry and filename identity passed | `worker-final-10000.json` |
| Actual redirected RDP filesystem | 4,194,305 bytes, exact SHA-256 round trip; fresh signed session evidence | `rdp-unicode-final/before.json` |
| Persistent startup and actual RDP reconnect | Same session 3, changed worker instance, previous transaction rejected, side effect remained one `x`; relative Unicode runtime normalized to absolute path | `startup-reconnect-final.json`, `rdp-unicode-final/after.json`, `egw-task-startup-readback-result.json` |
| Two standard-user SIDs, SSH and scoped sync | Actual MCP router, own-data access and cross-account denial passed; 100 KiB SSH scripts; binary/empty/excluded sync cases | `accounts-final.json`, `accounts-final-status.json` |
| QGA binary transfer and clock | 1,048,577 bytes, exact SHA-256; UTC readback skew 297 ms | `qga-roundtrip-final.json` |
| Signed packages / installation / tampering | Both architectures verified and installed with AllSigned; modified worker rejected | `egw-final-package-check-result.json` |
| WireGuard lifecycle through provider API | Clean install, connect, fresh synthetic-key import and disconnect each completed with code 0; no reboot requested | `provider-install.json`, `provider-connect.json`, `provider-import_key.json`, `provider-disconnect.json` |
| Actual Windows WireGuard kernel data plane | 1,048,577 application bytes, exact SHA-256; host has no TUN/routes | `wireguard-dataplane-final.json` |
| Server x64 Secure Boot / software TPM | Secure Boot true; TPM 2.0 initialized and ready for storage; attestation unavailable | `x64/egw-native-cert-state-result.json` |
| Native Server QGA/VSS freeze-thaw | 3 volumes frozen; status frozen; 3 thawed; final status thawed; explicit TCG freeze cap 300 s | `x64/vss-freeze-thaw.json` |

The signed worker tested in the soak and RDP restart has SHA-256 `425813ebd8f447be3354f82ade903fa664dd495041127fb9d14e07ce08517641`. Its ARM64 runtime has SHA-256 `67007ac681ba7d3c0c5c7c61b2c62c269bab24fb0324edb044bff9d6c0eec84b`. These identify disposable signed copies; source packages remain unsigned.


Native runtime cases include Unicode stdin and paths, 128,000-byte file content, cross-directory atomic replacement, wrong-digest preservation, single-character rename, deletion, enumeration, traversal/hardlink/symlink rejection, argv preservation and owned descendant termination using a retained process handle. Both ARM64 and x64 executables passed on Windows 11 ARM64; the x64 executable there used Windows emulation.

The two-account fixture exercises the actual MCP principal router and native SID-checked backend. Each standard account reads its own canary through SSH, fails to read the other account's files/private environment and the broker environment, rejects a mismatched expected SID and cannot invoke controller tools. Scoped Windows sync checks binary files, empty directories, exclusions, preserved extra destination files and denial of the other account's root.

The QGA binary round trip transferred 1,048,577 random bytes with exact SHA-256 equality. `guest-set-time` was followed by actual UTC readback (297 ms observer skew). On ARM64, the official x64 QGA service ran under Windows emulation as SYSTEM after administrative extraction; its MSI VSS registration did not qualify on ARM64. VSS freeze/thaw is outside that ARM64 result; the native x64 QGA/VSS result is listed separately.

WireGuard 1.1.1 ARM64 installed its actual Windows kernel driver. A separate host user-space WireGuard peer used a private in-memory network stack, with no host TUN or routes. Because restricted user networking did not return forwarded UDP packets, the fixture carried encrypted packets over a dedicated loopback TCP framing bridge. The Windows kernel tunnel exchanged 1,048,577 random application bytes with exact SHA-256 equality. This establishes that laboratory topology's data plane, not deployment throughput or proprietary-provider compatibility.

Lab signature verification, managed installation of both package architectures and rejection of a modified worker copy passed. Public packages built from source remain `unsigned` / `qualified_windows: false`. A lab certificate is not a publicly trusted production release or timestamp qualification.

## Reproduction and retained failures

Public entry points are `scripts/qualify.py`, `scripts/qualification/windows.ps1`, `native_windows.py`, `windows_accounts.py` and `rdpdr.py`. The latter two consume explicitly provisioned disposable accounts or an already redirected spool; they neither create accounts nor log into a configured deployment.

The mixed soak uses `--transactions 10000 --exec-every 10`: 1,000 native command iterations and 9,000 persistent mux I/O iterations, plus functional cases. Command deadlines are the normal Windows 120 seconds; maximum observed duration is retained. Resource acceptance retains the original post-warmup bounds: 256 MiB working set and 64 threads/handles. It is a finite sampled workload, not proof of indefinite leak freedom.

The Server/TCG native fixture exceeded the normal 15-second signature-verification cap twice; functional acceptance used an explicit scale of eight, without changing production defaults or the operation-wide deadline. The Server parser also exceeded its normal 30-second fixture cap; its later run explicitly sets `EGW_TEST_POWERSHELL_TIMEOUT_SEC=240` (allowed range 30..240). Normal caps passed on the ARM64 guest and host. The native Server VSS freeze also exceeded a 90-second observer deadline. Its mandatory cleanup thawed three volumes and confirmed `thawed`. A separate subsequent run with an explicit 300-second freeze cap observed three frozen volumes, `frozen`, three thawed volumes and final `thawed`. These adjusted waits establish functional emulation results, not x64 timing acceptance.

The ARM64 setup environment unexpectedly initiated an OS reconfiguration reboot through CloudExperienceHostBroker. Test attempts during that recovery are retained separately. An official signed VirtIO display driver and ordinary console setup recovery restored a completed OS state; final checks ran after OOBE/system setup flags were zero, with UAC and Defender enabled. No password was saved to enable recovery autologon.

Earlier failures are retained as evidence: native rename/delete errors, malformed Windows environment, lost or sharing-locked spool requests, implicit pipeline-buffer handle growth, a slow scrubber on large SSH input, the initial guest clock offset and a failed restricted-UDP test topology. Observer failures caused by sandbox socket denial, a fixture variable shadow and concurrent QGA lock contention are not relabeled as product passes. Corrected workloads were rerun.

## Acceptance boundaries

- These checks use synthetic keys/accounts and a private test certificate. Production CA/EV signing, timestamping, enterprise WDAC/AppLocker/EDR approval and organization policies require their own acceptance. A manually constrained runspace guard test does not establish enterprise WDAC enforcement.
- Server Secure Boot and a ready software TPM do not establish physical hardware trust: the emulated TPM has no EK attestation certificate, reports not ready/capable for attestation, and cannot bind PCR7.
- ARM64 Secure Boot/TPM acceptance is not established: available secure firmware did not boot reliably and the running ARM64 guest's TPM query failed. Application attestation does not become hardware attestation.
- ViPNet/Kontinent installers, approved proprietary lifecycle recipes and their actual drivers are unavailable to this stand. Their functional compatibility is not inferred from WireGuard or a generic recipe executor. No real keys are required or requested to preserve that boundary.
- Linux execution, Windows-host WHPX/Unix-control-channel portability, physical hardware and client-environment acceptance are outside this record. Native x64 performance is not inferred from TCG or Windows ARM64 emulation.
- RDP restart duplicate rejection is not a distributed exactly-once or abrupt-power-loss guarantee. Cancellation does not roll back prior effects or stop an external service merely because its launcher exited.

## Retained stand

Both disks, firmware/TPM state and private evidence remain under the ignored `build/windows-lab-20261031` directory. Its private `manage_lab.py` supports `status`, `start` and `stop` for `arm64` or `x64`, checks exact QMP identities and keeps restricted networking. Start excludes installation/answer media and starts no VPN or autologon. ARM64 was shut down, restarted through this script and checked again: setup complete, no Winlogon password, UAC/Defender enabled and AllSigned retained. Temporary RDP, console and encrypted-packet bridge clients are stopped after qualification. Both guests were then gracefully powered down and their stopped state was confirmed. No qualification process is left consuming guest CPU.

## Primary references

- [WireGuard Windows enterprise deployment](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md), including `DO_NOT_LAUNCH` and tunnel service commands.
- [Windows PowerShell BeginInvoke](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.powershell.begininvoke), for explicit input/output buffer ownership.
- [NtSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsetinformationfile) and [file rename information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information).
- [Run/RunOnce command limits](https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys).
- [Windows file sharing modes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
