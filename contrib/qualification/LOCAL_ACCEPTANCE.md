# Local acceptance and release policy

The [full reproducible acceptance entry point](REPRODUCIBLE_ACCEPTANCE.md) adds
explicit tool/media approval, independent unsigned builds and SBOM, generated
crash models and a complete disposable Windows PKI/migration/preparation suite.

Run a complete local plan without hosted workflows:

```sh
python scripts/qualification/local_acceptance.py --plan contrib/qualification/plans/local-acceptance.json --output build/acceptance/run-001
```

Use a new output directory for every attempt. The runner preserves failed reports, hashes the source inventory and logs, enforces step deadlines, stops on the first failure and writes an evidence inventory. It does not infer a broader platform pass from a partial plan. Plan commands are explicitly supplied trusted local commands, executed as argument arrays without a shell. Keep plans and logs private when they contain installer locations or account metadata. The runner does not publish artifacts or invoke hosted workflows.

`{python}`, `{repo}` and `{run_dir}` expand to the current interpreter, checkout and new private output directory. The default example builds a source distribution, builds the wheel from that distribution, installs into a clean venv outside the checkout, checks both entry points and generates a provisioning bundle with installed resources. It also runs the ordinary local source suite and hygiene checker. The build interpreter needs setuptools satisfying `pyproject.toml`; no runtime dependency is added. A separately supplied `--pip-wheel` supports offline venv bootstrapping on distributions without ensurepip. Its SHA-256 is recorded.

Additional plan steps can invoke the existing disposable Windows provisioning, cold worker, native trust, versioned upgrade, release-policy, worker/QGA/storage failure, RDP disconnect, host and soak fixtures. Supply only disposable media, accounts and lab signing certificates. RDP steps require the existing fixture's explicitly redirected test session. These checks remain separate evidence classes.

For a new VM, put its fixture `--output` below `{run_dir}` and list its generated `config.json` in `managed_vm_configs`. In `finally`, the runner checks the laboratory name, restricted user networking, custom provider without installer/key material, owned disk/NVRAM/TPM state paths, QMP identity and actual attached disk before graceful shutdown and TPM quiescence. An absent config means the resource was never created. Ambiguous ownership or cleanup failure makes the entire run fail and preserves its state. Previously existing VMs are not accepted as owned resources. Stop only the runner's child processes and their process groups on a step deadline.

## Automated installed MCP check

The installed-package checker now includes a fresh local MCP smoke test:

```sh
python scripts/qualification/installed_package.py --output /private/new-installed-check
```

To verify an already installed private test environment against its exact wheel:

```sh
python scripts/qualification/mcp_installed.py \
  --python /path/to/venv/bin/python \
  --wheel /path/to/enclave_gateway.whl \
  --output /private/new-mcp-check
```

On Windows, select the environment's `Scripts/python.exe`. The checker preserves
the interpreter symlink rather than resolving it out of its virtual environment.
It rejects editable packages and runtime differences from the supplied wheel.
The expected version comes from that wheel's metadata.

The server uses a new private configuration with Bastion disabled and no targets.
Inherited deployment environment variables are not passed to the child. An
audited Python guard rejects socket and child-process events. Actual socket
creation and DNS probes must fail. An actual subprocess probe must also fail.
This is an accidental-I/O guard for trusted test code, not an OS sandbox.
The original `0.3.0` receipt below used a separate OS sandbox.

The client waits for initialization before sending further requests. It checks
the expected server version and local smoke responses. It closes only its own
server's stdin and requires exit zero. Failure cleanup may kill that newly
created test child only. No existing IDE process is inspected or stopped.
The bounded private receipt retains failure status and protocol output.

## Periodic copy attestation recovery

`tests/test_copy_attestation_recovery.py` exercises the actual MCP copy engine
through local QGA file algorithms. A synthetic worker validates upload-slot
hashes and emits framed replies. Host processing ages the normal 30-second
verification window so that periodic attestation occurs after 38 verified MiB.
A controlled read timeout interrupts that challenge before part 39 is published.
The old source stops at that boundary. The correction completes a 128 MiB
upload after a new nonce verifies, without duplicate data requests.

A new MCP handler and engine reopen the same journal after completion. With the
original source path absent, the unchanged transaction returns its retained
result without remote dispatch. Failed renewals are also retained across a new
handler and engine without another copy request.

The failed challenge's late frame remains distinct from the new proof. Tests
reject its nonce if it is presented as the new answer. Two timed-out checks
stop before part 39. A retained transaction cannot dispatch again. Negative
verification cases cover the pinned hash and current file hash separately.
They also cover the account pin and policy pin. Version checks remain enforced.
Signature checks remain enforced. A changed worker instance invalidates the
session. Parent deadlines and cancellation prevent another challenge.

These fixtures model a specific failure boundary. They do not reproduce the
physical cause of the real RDP delay or qualify field transfer reliability.

## QGA clock repair verification

`tests/test_qga_clock.py` models delayed lock acquisition before time setting.
It verifies that an implicit timestamp is sampled after that wait. An explicitly
supplied timestamp retains its exact value. Read-only guest time observations
exclude lock waiting from their uncertainty window. An excessive offset cannot
pass verification. Excessive uncertainty also fails. A Host wall-clock step
invalidates the sample. Malformed guest timestamps are rejected.

QGA-backed `heal` verifies the clock after initialization. Failed verification
returns a nonzero exit code with a structural receipt. Repeating that same
transaction returns its retained result without another repair. Cancellation
remains observable. These are controlled local regressions, not proof that the
field Appliance has been synchronized or that transfer delays are fixed.

## Partial download and late-response regressions

`tests/test_pull_read_budget.py` runs a 128 MiB MCP pull through the QGA file
algorithms against local files. The block-30 response remains exclusively
unavailable for 38 simulated seconds. Subsequent wire reads take more than
three seconds in total. The previous whole-MiB poll loses its prefix on each
local timeout and exhausts the unchanged 45-second step budget after 29 parts.
Bounded reads retain progress and complete all 128 parts without republishing
any request. A new MCP server reopens the journal and returns the saved result
with the destination absent and no dispatch. A response unavailable beyond the
original deadline preserves the prior destination and rejects replay.

`tests/test_stream_poll_recovery.py` also rejects a byte after a binary frame
ending exactly at a QGA read boundary. An EOF-read timeout preserves the
unacknowledged response. Invalid receipt identity is rejected. A transaction
mismatch is rejected. A block-hash mismatch is rejected. These failures do not
erase evidence or return download bytes. The fixtures do not qualify real RDP
publication latency. The saved RC3 field result reported no QGA read timeout;
the slow-reader reproduction cannot establish its physical cause.

`tests/test_copy_diagnostics.py` exercises a two-part MCP download through the
actual QGA file algorithms against local files. One injected connection loss
after a partial frame recovers at the original cursor. No copy request is
republished. The completed download matches its full content hash.

Separate cases model stopped-worker telemetry and a read crossing the original
step deadline after the first block was verified. Both retain indeterminate
state with the original diagnostics. The prior destination is preserved. Only
the owned temporary download is removed. An unchanged repeated transaction
cannot publish again. After a late result, a fresh read-only probe receives its
own response without consuming the failed response or changing the retained
journal outcome. These checks do not run a real Windows guest or contact a
deployment. They do not reproduce the field RDP fault or qualify network timing.

## Local rollback between v0.3.0 and 0.4.0rc4

**PASS / УСПЕХ** for the installed package and Host journal cycle on macOS
arm64 with Python 3.14.5. One isolated environment ran the full sequence
`v0.3.0 → 0.4.0rc4 → v0.3.0 → 0.4.0rc4` using verified offline wheels.

| Package | Source commit | Wheel SHA-256 |
| --- | --- | --- |
| `v0.3.0` | `29dad2ea643e5eed7fffc1a795827aa485ab1b85` | `23f0d4852749ec587ce16c589a76b55802183042961c49836266fae7c9a00fbd` |
| `0.4.0rc4` | `a46529825a87e80e6e218d39cfa2a40089d5fb68` | `a8697dee4e8ff770ae8ffa79d9a89ffba4ac5f965fc66d2d49014d03d8b682fd` |

Each installation matched all 65 runtime files in its wheel. The CLI and
fresh stdio MCP servers reported the expected version. The installed MCP and
journal code ran against a local transport fixture. A Python audit hook denied
socket operations and subprocess launches inside the server and passed its
denial probes. The journal and all test payloads were synthetic.

- The same SQLite file, configuration and journal namespace persisted through
  the cycle. No backup was restored. All four online backups passed SQLite
  `integrity_check`.
- The final journal contained eight entries. Six were completed. Two were
  indeterminate. One completed result was stored in the archive. Existing rows
  and the archived payload stayed unchanged across version changes.
- Completed requests returned retained results after MCP restart and version
  changes. Indeterminate requests stayed blocked. The fixture recorded zero
  additional dispatches for repeated transaction identities. RC4 diagnostics
  were still available after returning from `v0.3.0`.
- After rollback, `v0.3.0` rejected both RC4 chunked requests as invalid
  arguments before dispatch. An ordinary 64 KiB round trip matched SHA-256.
- An injected lost reply after 1 MiB of verified pull progress preserved the
  previous destination and removed the partial download file.

This result covers installed package compatibility and Host journal behavior
in the local fixture. Field RDP reconnect, the deployment journal and live
worker behavior remain within the separate field program. Raw fixture receipts
are retained privately. See the
[0.4.0 readiness review](../../docs/STANDARD_OPERATOR_040_READINESS.md).

## Installed v0.3.0 local MCP verification

Result: **PASS / УСПЕХ** for a newly launched local stdio server from the
installed `0.3.0` package. This was a direct local check with an isolated test
configuration. The real deployment configuration was not loaded.

- Release tag: `v0.3.0`.
- Release source: `29dad2ea643e5eed7fffc1a795827aa485ab1b85`.
- Published wheel SHA-256:
  `23f0d4852749ec587ce16c589a76b55802183042961c49836266fae7c9a00fbd`.
- CLI version: `enclave-gateway 0.3.0`.
- Installed distribution metadata version: `0.3.0`.
- Imported module version: `0.3.0`.
- Import location: the selected launcher's installed `site-packages`.
- Editable installation: false.
- Runtime files compared with the published wheel: 65.
- Runtime mismatches: zero.

The actual installed launcher started a separate server in a new private test
namespace. Its configuration disabled Bastion and contained no targets.
It used `--read-only`. No working credentials or deployment state were supplied.

Network access was denied by an operating-system sandbox. A preliminary
loopback probe confirmed the denial before the MCP server started. Standard
input and output carried the test protocol without opening a network listener.

The fresh `initialize` response contained:

```json
{
  "result": {
    "protocolVersion": "2025-03-26",
    "serverInfo": {
      "name": "enclave-gateway",
      "version": "0.3.0"
    }
  }
}
```

Further results on that same test connection:

- `ping`: passed.
- `tools/list`: 18 tool definitions returned.
- Local `enclave_capabilities`: passed.
- Bastion disabled in the returned capabilities: confirmed.
- Shutdown: the test client closed its own server's stdin.
- Server process exit code: zero.
- Manual operating-system signals: none.
- Existing IDE sessions touched: none.

The private receipt and protocol transcript were retained outside Git. Public
documentation omits local paths and process identifiers. The result verifies
the installed package and a fresh local server. It is not a benchmark or a
verification of resident modules in previously opened IDE sessions.

This check required no connection to QGA or the real enclave. It did not start
an Appliance or change VPN/RDP state. It did not launch or stop a Bastion worker.
Old IDE connections can be reconnected through their own controls when idle.
Their individual migration is operational maintenance rather than a remaining
gate for the accepted Standard operator release.

## Fresh Windows preparation

`egw init --completion-mode StartupTask` is the default. During specialize, machine preparation stages its script/media policy under the administrative machine directory and registers a SYSTEM task. The task starts immediately, waits for all Windows Setup/OOBE flags to clear, and has a startup trigger for recovery across setup reboots. It installs drivers/QGA, verifies deletion of its own matching task and only then publishes readiness revision 2. A completed generation can finish interrupted cleanup without reinstalling MSI or requiring the removed media; the existing agent process is preserved. The disposable checker requires the selected completion mode, the final readiness revision and actual task absence. No user password is stored in the task and no automatic logon is configured. A conflicting task is rejected. Only an ObjectNotFound task-query error establishes absence; scheduler or permission failures block readiness and retain diagnostics. A failed or timed-out task leaves diagnostic phase records for operator inspection.

Finalization writes a flushed, atomically replaced `machine-prepared.json` journal before deleting the task, then atomically publishes readiness last. The journal binds architecture, selected media approval, QGA mode, completion policy and the exact preparation script. It is retained as commit intent, not readiness. If the process stops after task deletion, `egw -c <lab-config> --state-dir <private-state> init --recover-machine-preparation --arch x86_64` finishes the matching generation through QGA. Recovery requires completed Setup, the controller's exact installed source, a matching journal/media policy and an already running guest agent. `-RecoverOnly` cannot fall through to driver enumeration or MSI. No remaining boot task is claimed in that interruption window: recovery is controller-driven. A new controller version does not silently execute an older script. `machine_prepare_faults.ps1` exercises an actual child kill after actual task deletion and a readiness-file sharing failure, retaining both failures and recovery results in a new disposable workspace.

A complete installation lifecycle now has a public entry point, without private observer patches:

```sh
python scripts/qualification/disposable_windows.py \
  --output build/acceptance/windows-001 --full-lifecycle \
  --windows-iso /path/to/lab/windows.iso \
  --virtio-directory /path/to/lab/Drivers \
  --guest-agent-msi /path/to/lab/qemu-ga-x86_64.msi \
  --firmware-code /path/to/lab/OVMF_CODE_4M.secboot.fd \
  --firmware-vars /path/to/lab/OVMF_VARS_4M.ms.fd \
  --tpm --secure-boot --deadline-sec 7200
```

Use a new directory and matching licensed media. `--full-lifecycle` proves the standalone qcow2 has no guest data before first boot, hashes media/drivers and source files, compares seeded/installed preparation bytes, performs one unchanged 120-second security request per boot, fully stops VM/TPM, boots without installer media, and checks unchanged readiness/progress hashes and modification times. Its `finally` checks ownership and stops only that run's VM/TPM; disks and private failure evidence remain. Working-tree hashes are authoritative: the recorded Git base does not imply a clean or committed tree. Ambiguous ownership and cleanup failures fail the run and preserve state. The default fixture without this flag retains its existing staged-plan behavior.

`--completion-mode SetupComplete` retains the explicit hook integration for media where it is available. The startup-task path does not depend on OEM product-key handling of that hook. This mechanism is tested separately from acceptance of any particular OEM edition, licence or activation service.

## Worker trust readback

Windows process-isolated workers use the signed native runtime's resident `attest-server` mode for current hash and Authenticode verification. It uses `WinVerifyTrust` generic Authenticode policy and extracts the signer chosen by the trust provider, including script SIPs. It explicitly requires revocation checking for the chain excluding the trusted root. An independent `X509Chain` check enforces code-signing usage, current certificate validity and `NoFlag` error handling; this prevents WinTrust from accepting an unavailable revocation status under a system offline soft-fail policy. Provider-selected intermediates are supplied as extra certificates, without creating custom trust anchors. This also requires a currently valid signer even when an older Authenticode timestamp would otherwise preserve signature validity. Startup can retrieve trust/revocation material online. Resident nonce checks use `WTD_CACHE_ONLY_URL_RETRIEVAL` with that revocation requirement: missing, expired or revoked material fails closed; it is never converted into `Valid`. This bounds network retrieval to startup, rather than permitting it to consume the ten-second challenge deadline. A cache-expiry failure requires explicit restart with reachable trust services; there is no implicit online retry during a nonce. The one-shot `attest` command uses the online policy. These flags follow the [Windows trust-provider contract](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data). Open file handles deny modification/replacement during hash and trust checks. A dedicated native trust host authenticates the configured worker/runtime hashes and signatures before advertising readiness. Script SIP initialization belongs to startup, with its timing exposed separately. Control frames use bounded ASCII/base64 lines containing UTF-8 JSON, including Unicode paths; managed redirected streams consume a UTF-8 preamble without changing the shared console code page. The OS-selected SIP type for each of the two configured paths is retained after startup through the documented `WINTRUST_FILE_INFO.pgKnownSubject` field. Provider discovery is not repeated for each challenge. Every later nonce still performs full fresh WinVerifyTrust checks; no signature result is substituted from startup. The native host retains an actual owner-process handle and exits if that owner dies. Cancellation/deadline failure kills the trust host and requires a worker restart; there is no hidden retry. No new PowerShell interpreter or CLR process is started for each probe. Non-isolated lab workers keep the PowerShell path.

The caller still verifies the fresh nonce, pinned worker/runtime hashes, version, immutable SID, loaded/current signer and process-isolation model. `worker_cold.py` issues exactly one first challenge per newly started worker at the existing ten-second deadline and requires probe sequence 1. It records startup and launch-through-first-response times separately. The Windows mixed-load fixture uses a 120-second readiness observer for service initialization; this is not a ten-second launch guarantee. `native_attestation.ps1` compares the provider result with the stock cmdlet and checks tampered/unsigned files, Unicode paths and runtime identity. `native_revocation.ps1` creates an isolated issued code-signing chain without revocation material, checks that the chain is otherwise valid, and requires both signed startup and the cache-only nonce to reject it. Its fixture keys are nonexportable and its temporary certificates are removed. `native_framing.py` checks BOM-prefixed initialization, first challenge, modification after initialization, malformed/oversize frames and Unicode one-shot requests. `pki_lab/PkiLab.csproj` builds a Windows-only disposable authority with nonexportable machine keys, loopback CRL/OCSP and a legacy Authenticode timestamp endpoint. `pki_acceptance.ps1 -PkiLab <built-exe> -Worker <approved-package/worker> -Runtime <approved-package/runtime> -SignScript <approved-signing-source> -Workspace <new-directory>` requires an already approved complete package and an administrative isolated VM. It tests issued chains, fresh/stale/revoked CRLs, actual good/revoked OCSP, cache expiry without nonce network fallback, timestamped signer expiry, fresh signer identity and authenticated CMS pin rotation. Critical [Issuing Distribution Point scopes](https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.5) prevent a fresh CRL from satisfying another scenario. Independent offline chain flags must establish Revoked, unknown revocation status or NotTimeValid as appropriate. Cache/signer lifetimes are five minutes; tests wait for actual guest time to pass expiry. Native nonce replies retain the ten-second deadline and record their elapsed times. The fixture verifies termination of all its native hosts, removes only its own root/My certificates and CNG keys, and stops its own listener. Never run this CA fixture in an existing client environment. Its finite passing sample does not establish production PKI, TSA time accuracy or a latency guarantee for every trust provider or host.

## Signed metadata and release ordering

`sign_windows.ps1` now requires a positive `-ReleaseSequence`, supports a lowercase `-Channel` (default `stable`), signs each executable/script, then signs the exact manifest bytes with detached SHA-256 CMS in `signature-manifest.p7s`. `verify_windows.ps1` authenticates metadata before consuming its file identities: one signer, SHA-256, valid CMS, OS certificate-chain/code-signing trust and an administrator-supplied thumbprint are required. Payload allow-list, hashes and individual Authenticode checks remain mandatory. Protect and authenticate the verifier/installer entry point through the approved execution policy.

```powershell
./scripts/release/sign_windows.ps1 -PackageDir ./build/release -CertificateThumbprint $thumbprint -TimestampServer $timestampServer -ReleaseSequence 1
```

Omitting timestamping requires explicit `-AllowUntimestampedLab`; it records the missing production timestamp qualification. CMS metadata has no independent trusted timestamp, so its signer must pass current OS chain validation. Production certificate expiry/rotation and timestamp-service acceptance require their own qualification.

New installation selections use revision 2 and atomically retain `max_sequence`, `highest_release` and channel along with current/previous generation. Normal installation rejects lower sequences, different releases reusing the highest sequence and implicit channel changes. Explicit `-Action Rollback` can select the verified previous generation and preserves the high-water mark; the same approved highest release can be installed again after rollback. This does not defend against an administrator deleting or replacing the protected installation state, nor order releases across independently created installation directories.

Revision-1 manifests/selections are not silently promoted to authenticated metadata. The approved installer offers a migration wizard with separate source and destination directories:

```powershell
./install_windows.ps1 -Action Migrate -LegacyDir ./legacy -InstallDir ./managed-v2 -PackageDir ./release -TrustedThumbprints $thumbprint -DryRun
./install_windows.ps1 -Action Migrate -LegacyDir ./legacy -InstallDir ./managed-v2 -PackageDir ./release -TrustedThumbprints $thumbprint
./install_windows.ps1 -Action MigrateRollback -LegacyDir ./legacy -InstallDir ./managed-v2 -TrustedThumbprints $thumbprint
```

Dry-run verifies the new CMS package before changing installation files or ACLs. It can refresh the OS trust cache. The old unsigned selection supplies no executable paths, pins, sequence or channel: its revision and byte hash establish only source preservation. Overlapping directories and reparse paths are rejected. Actual migration holds the old selection read-only against concurrent replacement, records a private durable journal, and uses the normal verified/atomic v2 staging path. Repeating Migrate resumes a matching interrupted target. Use Recover afterward to remove its abandoned stages. An unrelated existing destination is rejected.

MigrateRollback atomically withdraws `installation.json` into `migration-withdrawn.json` under the deployment lock. Both generations and the high-water mark remain. Normal installation/status rejects a withdrawn selection; explicit Migrate can resume while retaining release-order checks. It does not activate or authenticate the unsigned legacy generation. Existing concrete pinned paths still refer to their files. Explicitly update trusted runtime/agent paths and hash pins before approved startup, and explicitly review legacy trust before choosing any legacy activation. The wizard never launches workers, restarts sessions or changes VPN state. `windows_migration.ps1` covers tampering, wrong pins, overlap, untrusted legacy fields, dry-run, rollback, resumed migration and an actual process crash during staging under SYSTEM and a standard account.

## Windows TPM host boundary

The upstream [QEMU build configuration](https://github.com/qemu/qemu/blob/master/meson.build) explicitly excludes TPM emulation on Windows. The tested native Windows QEMU also rejects `-tpmdev` as an invalid option. Managed TPM remains available on POSIX virtualization hosts; it is not implemented for the Windows QEMU backend. Capabilities expose the limitation and provisioning rejects it before seed or disk mutation. Native Windows support requires an alternative backend or an upstream port, including its state, cancellation and ownership semantics. Software-emulation evidence does not establish physical TPM attestation.

The [isolated acceptance record](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/AUTONOMOUS_ACCEPTANCE_2026-11-01.md) lists observed results, failed observers, provenance and remaining boundaries.

The [final-source blank-disk acceptance](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/FRESH_INSTALL_ACCEPTANCE_2026-11-02.md) closes the subsequent full-installation check for the final readiness ordering, including actual task absence on first boot, full VM/TPM poweroff, unchanged preparation records on the next boot and one security request per boot at the existing deadline.

The [four-item autonomous closure](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/AUTONOMOUS_CLOSURE_2026-11-02.md) records crash-safe preparation recovery, disposable issued PKI, v1 migration and the final whole-command blank-disk lifecycle with cleanup, including retained failures and qualification limits.
