# Preparing an unsigned release candidate

The candidate assembly procedure creates a source-bound bundle for review. It does not publish a
tag, upload packages, change repository visibility or establish Enterprise signing
trust. Hosted workflows are not needed for these steps.

## Published Standard operator release

Package `0.3.0` is published as
[`v0.3.0`](https://github.com/pom6i4/enclave-gateway/releases/tag/v0.3.0) at
`29dad2ea643e5eed7fffc1a795827aa485ab1b85`.
The tag and original eight assets remain immutable. All six source CI jobs
passed for that exact release commit. GitHub Private Vulnerability Reporting
is enabled.

Installed `0.3.0` subsequently passed operator-reported field acceptance.
First-attempt 128 MiB push took 996.247 seconds. Immediate pull took 688.846
seconds with matching size and SHA-256. Three `heal` calls retained the worker
and synchronized clock. Stop released the lease in 32.223 seconds. KES
`21.3.10.1001` stayed active with zero new events. See the
[installed-release record](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-installed-release-v030).

The prior RC at `33fbcdecfba01ea8ed995379d39d8bc49886f706` independently covered
actual RDP reconnect and upgrade/rollback. Its report remains bound to that RC.
Final runtime differs only in the package version. Agent bytes and the worker
attestation contract remain unchanged.

The post-release `V030_FIELD_ACCEPTANCE.md` supplement has its own
`V030_FIELD_ACCEPTANCE.sha256`. The original `FIELD_ACCEPTANCE.md` and manifest
retain the initial build-time records. Their original `SHA256SUMS` remains
valid. Adding later evidence does not replace those assets or move the tag.
The [release gates](STANDARD_OPERATOR_CANDIDATE.md) retain applicable platform
boundaries for future releases. The
[RC field prompt](../contrib/qualification/STANDARD_OPERATOR_FIELD_PROMPT_RU.md)
is retained as the historical RC lifecycle program.

The release cycle is complete for the accepted Standard operator scope.
The [local MCP verification](../contrib/qualification/LOCAL_ACCEPTANCE.md#installed-v030-local-mcp-verification)
confirmed installed `0.3.0` and the fresh server's `serverInfo.version`.
It used an isolated configuration with operating-system network denial.
Existing IDE sessions were not restarted. Their later client-side reconnect
is operational maintenance, not a remaining release gate.
See the [scope-bound closure](STANDARD_OPERATOR_CANDIDATE.md#release-cycle-status).

## Unpublished 0.4.0 development field acceptance

Installed `0.4.0.dev0` at `363d8f72dc2c3ab1eebf9d60a3a95215cba468b3`
has an [operator-reported functional field acceptance](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-development-block-040dev0).
Fresh MCP initialization passed. The fourth attempt completed a 128 MiB round
trip. Deduplication across MCP restart passed. An intentionally cancelled copy
was retained as indeterminate and could not dispatch again.

The first three pulls failed and remain in the record. The successful program
used external RDP input activity. The old idle-timeout attribution is withdrawn.
Raw ledger reconciliation establishes historical block 74; the earlier block-123
annotation is incorrect. This is not unattended reliability
acceptance or a stable release. Keep the field-built wheel identity separate
from published release materials. No version or agent bytes change as part of
recording the report. Stable `v0.3.0` remains unchanged.

## Unpublished 0.4.0rc1 field gate

The exact candidate at `a8d9cf0fa60219220e5363d33bd2423ec90e2818` remains
**INCOMPLETE / ПРОВЕРКА НЕ ЗАВЕРШЕНА**. Its installed runtime matched the wheel.
Fresh MCP initialization passed. One 128 MiB push completed on its second
attempt, but none of six pulls completed. Diagnostic reconciliation passed.
No-replay checks passed. Final worker stop released the lease without respawn.
Protection remained active. See the
[RC1 record](../contrib/qualification/FIELD_ACCEPTANCE.md#incomplete-candidate-acceptance-040rc1).

No code defect causing the reverse-path delay is established. The next step is
bounded observation of the delayed boundary, not publication or increased
timeouts. Do not rewrite the original RC1 candidate bundle with later evidence.
This documentation and its local regression tests do not create a new candidate
build or move stable `v0.3.0`.

The `0.4.0rc2` clock changes are outside the original RC1 wheel identity.
Their local package checks do not replace that bundle. Assemble the exact new
source-bound candidate before running the short clock field program. Neither
the successful bounded 8 MiB probe nor the clock correction closes 128 MiB
round-trip acceptance.

## Unpublished 0.4.0rc2 clock candidate

Exact candidate source is `18b43df51ca7360534447bde67953a819e5cb8cc`.
Its installed clock field program passed according to the
[operator report](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-clock-verification-040rc2).
One `heal` corrected the initial −17539 ms offset. Independent checks through
300 seconds passed the interval gate. The worker and RDP connection were
retained. Final stop released the lease without respawn. Protection stayed
active. This acceptance does not close the required 128 MiB round trip.
The candidate manifest and original artifacts retain their build-time bytes.
The result is recorded separately in documentation. No release is published.

Build this candidate from a clean committed source export. Its private
`candidate-manifest.json` must identify the full source commit and wheel SHA-256.
Deliver the filled `FIELD_PROMPT_RU.md` from the same bundle. The tracked clock
prompt is a preparation template and must not be sent directly to an operator.
Verify every bundle checksum before delivery. Keep original RC1 artifacts
unchanged. No Git tag or GitHub Release is created by candidate assembly.

## Unpublished 0.4.0rc3 transfer candidate

RC3 permits one new read-only periodic challenge after a transient timeout.
Each challenge retains its ten-second budget. Both attempts and data publication
remain bounded by the original part deadline. Trust failures are not retried.
No copy request is replayed. Worker bytes and attestation version remain unchanged.

Assemble from clean committed source. Deliver a private manifest with the exact
wheel hash and a filled 128 MiB field prompt. The preparation template is
`contrib/qualification/MCP_128_FIELD_PROMPT_RU.md`. Local regression and hosted CI
do not establish real-route acceptance. Keep earlier candidate artifacts intact.
No Git tag or public Release is created by preparation.

## Beta release history

The last Beta package version was `0.3.0b7`. Its Git release tag is
`v0.3.0-beta.7`. The previously published `v0.2.0` tag remains immutable at
`2d0167f2402a923f7eb95e4e752559cea250eaef`.

Beta 7 published the foreground `structured_only` profile as experimental. See
[endpoint-policy qualification](ENDPOINT-POLICY.md#qualification-status) for the
historical tested scope. Its source and Python prerelease stays immutable.

- Beta 2 recorded 24 of 24 ordinary 1 MiB uploads in 5.07–11.49 s on the isolated
  KES 14.1 RDP route. Target hashes matched and no new KES events were logged.
- Beta 3 adds chunked copy up to 512 MiB. The isolated Windows Server 2022 x64
  RDP lab with KES 14.1.0.423 verified 3 MiB and 65 MiB in both directions.
  All 136 blocks met the 15 s limit, with a 2.692 s maximum and no new KES events.
- Beta 4 adds the Standard operator path for a non-administrator SID. Its
  unsigned adapter mode requires an independent policy pin, an adapter pin
  and mandatory SID-bound attestation. The earlier signed KES measurements
  apply to the earlier qualified builds.
- Beta 5 adds bounded long operator commands, a manual CMD attachment script,
  stopped-worker IPC cleanup and explicit managed QEMU endpoints. The published
  tag passed [isolated Appliance/QGA acceptance](ENDPOINT-POLICY.md#beta-5-applianceqga-acceptance)
  with KES 14.1, including 3 MiB and 65 MiB transfers in both directions.
- Beta 6 preserves the field-tested operator adapter and Linux peer. It fixes
  timeout budgeting, cold readiness and operator-safe `heal`. The final
  Appliance changes preserve milliseconds in clock sync and allow up to five
  seconds of forward skew in Stream heartbeat timestamps. See the
  [reported field acceptance](ENDPOINT-POLICY.md#beta-6-field-acceptance).
- The post-tag `0.3.0b6` source
  `65e1fb9abf7a609955aa0dafabf42fdae47f096d` passed operator-reported field
  acceptance under KES `21.3.10.1001`. The first-attempt 128 MiB round trip
  retained the worker instance and matched SHA-256. See the
  [source-bound acceptance record](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-source-65e1fb9)
  for recovery checks and qualification limits.

Beta 7 packages the application code accepted at
`65e1fb9abf7a609955aa0dafabf42fdae47f096d`. Its runtime source change is the
Python package version declaration. Agent bytes and protocol identities remain
unchanged. The earlier field report stays bound to its tested commit; the release
manifest binds the versioned artifacts and their build/install checks separately.

The installed Beta 7 wheel subsequently passed operator-reported acceptance at
`bcafbb1ae71bd044ed6ec4a8a0cf7fafbefd7f44`. All 65 installed package files
matched the release. Both first-attempt 128 MiB directions matched SHA-256.
The run verified clock-preserving `heal` and controlled QGA recovery without
application-request replay. Stop released the worker lease within 60 seconds.
KES `21.3.10.1001` stayed active with zero new events. See the
[installed-release acceptance record](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-release-beta-7)
for scope and evidence limits.

The Release's post-release `BETA7_FIELD_ACCEPTANCE.md` supplement has a separate
`BETA7_FIELD_ACCEPTANCE.sha256`. Its original six assets retain their bytes.
The original manifest and checksum set continue to describe the initial build.
The tag remains bound to the original release commit.

The earlier tags retain their original source revisions and artifacts.

- `v0.3.0-beta.1` points to `abd2db8396b559585385c7f04f2b8306c221d771`.
- `v0.3.0-beta.2` points to `a3b2fa76abd847b9523114b67e715cf8f4361290`.
- `v0.3.0-beta.3` points to `5fe6c83c03bb117eb6151e6379a379c7a7cab35e`.
- `v0.3.0-beta.4` points to `bd25064994f0efe3e04fb7cdcf07b365fbb28b76`.
- `v0.3.0-beta.5` points to `89640f7b892ef8309ac523758cc6c49c6fd5c100`.

Deployment under a particular endpoint policy requires its own acceptance.
The interactive SSH bridge through QGA remains unavailable. Direct Host SSH
and RDP TCP mux are separate explicitly configured routes.

A source/Python Beta may be distributed with those limitations. Its clean-install
receipt must bind the exact wheel and source. This does not establish acceptance
of Windows native helper distributions. A full unsigned candidate assembled
below still requires all specified platform receipts. Missing receipts must not
be waived or replaced with cross-compilation evidence.

The earlier `0.3.0b1` wheel and fresh self-contained x64 helpers have passed
the Windows artifact checker on native Windows Server 2022 with Python 3.14.5.
The run used timing scale 1 and the existing 15-second signature cap. Its
temporary signing key and trust were removed; original trust stores were
preserved. This additional receipt does not replace the other platform receipts
or assemble/publish a full native distribution. The source/Python release assets
and its tag remain unchanged.

## Source baseline

The historical pre-release `0.2.0` Beta performance baseline is
`49c3cc216473524e52f13d554cf4cabf619c47ee`. This identifies the code exercised
by the latest cold-start checks. Build and artifact receipts must still bind
the exact source revision used to assemble the candidate.

On an isolated Windows ARM64 Standard worker with a local Stream spool and
40 ms of added SSH round-trip delay, three series after worker restart on
already-running Windows passed all 90 TargetNode calls on the preceding
revision `bed7e87`. On the frozen revision, the final cold Windows series
passed 29 of 30 calls. The first call took 1,032 ms. A separate instrumented
first call took 1,071 ms and completed successfully. The cold-start gate
was not met at 800 ms per call. For this Beta, 800 ms for the first cold call is
an optimization target rather than a release blocker. These lab runs did not exercise RDP drive
redirection, a customer WAN or Enterprise process isolation.

Retain the complete cold and warm receipts, including failed samples, in
private qualification storage. A Beta source freeze does not publish a
package, sign release artifacts or establish production Enterprise trust.

## Component compatibility

| Component | Contract | Validation boundary |
| --- | --- | --- |
| Python CLI/package | `0.3.0`, Python 3.10 or newer; the release matrix exercises 3.10–3.14 | Pure Python has no mandatory third-party runtime dependencies. Record exact Python patches and platform for each run. |
| Windows native helpers | `net10.0`, self-contained `win-x64` and `win-arm64` | Use the exact pinned SDK/runtime and both helper projects. Cross compilation and PE inspection do not prove Windows execution. |
| Worker identity | Attestation version `0.3.0`, fresh nonce, approved hashes/signer/SID when required | This is an independent worker contract, not the Python package version. Deploy matching approved scripts/runtime together. |
| Legacy worker journal and telemetry | Revision 2, Bastion-local journal with protected spool binding | Preserve transaction identities across restart, migration and backup reconciliation. |
| Foreground worker ledger | `.structured-transactions` in the redirected spool for `spawn`, or the approved local NTFS state for `operator` | Preserve its independent binding and interrupted outcomes; no legacy adoption or automatic restart. |
| Optional stream framing | Descriptor revision 3, 4 KiB request alignment | Host and worker must both select `stream`; no automatic replay or protocol downgrade. |
| Enterprise distribution | Authenticode plus signed CMS metadata and release ordering | Unsigned candidate binaries cannot satisfy production Enterprise installation. |

Standard requires no custom worker executable for ordinary runspace/key-based SSH.
Host OS support, native acceleration, Windows sharing, RDP policy and proprietary
VPN drivers are separate platform contracts; a Python matrix does not qualify them.
Use [SECURITY.md](SECURITY.md) and the [qualification guide](../contrib/qualification/README.md)
for their prerequisites and evidence limits.

## Validate the source and Python matrix

The development CI matrix runs Python 3.10 through 3.14 on all three hosted
operating systems. Each job also builds and installs the distribution, then
checks a fresh isolated stdio MCP server against the exact wheel. This remains
separate from native-helper or hypervisor qualification. See the
[post-0.3.0 roadmap](ROADMAP.md).

Start from clean committed source. Keep reports, toolchains, virtual environments,
installers, credentials and built binaries outside the public checkout. Preserve
failed attempts under different output names.

Run the ordinary suite on each exact Python 3.10, 3.11, 3.12, 3.13 and 3.14
interpreter. For each interpreter, create a private build venv with recorded
setuptools/wheel versions, then run:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/qualification/installed_package.py --output /private/new-installed-check
```

Use that venv's `python`; it is not necessarily the Host's default interpreter.
The installed check builds sdist → wheel, creates another clean venv outside the
checkout and exercises installed entry points, configuration, agent resources,
diagnostics and provisioning. Capture all skips and reasons. Repeat with approved
PowerShell/native fixtures for the boundaries they exercise; do not convert a skip
into acceptance. Finally run hygiene and `git diff --check` on the committed tree.

## Review the Git history without rewriting it

```sh
python3 scripts/release/audit_history.py --output /private/new-history-audit.json
```

This read-only scanner includes every stored blob and commit, even unreachable
objects, plus paths in stored commits. It detects repository policy violations,
binary/oversized objects needing review and selected credential patterns. It emits
object identities, line numbers and match hashes, never matched values. Reports
use private permissions and refuse overwriting. Git inventory changes fail the run.
Complement it with an independently pinned local secret scanner covering all refs.
Run external scanners with full redaction and without repository-wide exclusions.
Do not upload the repository or findings to a third-party analysis service.

Synthetic fixtures still require review. A private review JSON must contain exactly
`revision: 1`, the report's `inventory_sha256` and a `decisions` list. Each decision
has an exact finding `id`, a nonempty `reason` and one of
`synthetic-test-fixture`, `documentation-placeholder`, `public-test-vector`.
Apply only individually verified decisions with `--review <private-file>
--review-sha256 <reviewed-file-sha256>`. Unknown, duplicate or stale decisions fail;
unreviewed findings leave the audit incomplete. A review is not a waiver for a real
credential. Discovery of real sensitive material requires a maintainer decision
before public publication; this procedure never rewrites history or rotates keys.

Pattern scans and fixture review are evidence with limits, not a proof that every
possible secret or ownership issue has been recognized.

## Build two independent unsigned candidates

Use the build-only manifest described in
[reproducible acceptance](../contrib/qualification/REPRODUCIBLE_ACCEPTANCE.md).
Pin tool executable hashes, exact Python/build-package/SDK/runtime versions, a
fixed source epoch and both `win-x64` / `win-arm64` targets. Use private caches,
explicit public feeds and no inherited credentials. Then run:

```sh
python3 scripts/release/reproducible_build.py \
  --manifest /private/toolchain.json --output /private/new-release-comparison
```

The two final artifact trees must match byte-for-byte. Keep the raw sdist receipts;
only container metadata is canonicalized. Inspect both PE machine values, exercise
host-native helper behavior separately and validate `sbom.cdx.json` against the
pinned CycloneDX 1.6 schema. Restore/audit failures must remain failures.

## Execute the exact artifacts on Windows and Linux

Use a disposable Windows x64 VM, a disposable Windows ARM64 VM and an isolated
Linux environment. Match OS architecture to the delivered native helper target;
process emulation is recorded separately from the native OS architecture. Keep
network access disabled or restricted and do not attach customer shares or keys.
Use an approved full Python installation with `venv`; an embedded Python with
custom `_pth` entries is not a clean client installation.

Run the following on each Windows VM, replacing paths with that VM's matching
artifact directory from the successful comparison:

```powershell
python scripts/qualification/artifact_acceptance.py `
  --wheel C:\Acceptance\enclave_gateway-0.3.0-py3-none-any.whl `
  --pip-wheel C:\Acceptance\pip-approved-py3-none-any.whl `
  --runtime C:\Acceptance\egw-runtime.exe --askpass C:\Acceptance\egw-askpass.exe `
  --allow-unsigned-lab --work-dir C:\Acceptance\new-client `
  --output C:\Acceptance\new-result.json
```

The explicit unsigned flag is laboratory-only. Run with permission to create and
remove a temporary, nonexportable machine code-signing key. The checker retains
the original trust-store inventory, adds only its own temporary certificate,
checks the installed signature verifier and AllSigned positive/negative cases,
then removes its own key and trust entries. It must leave the original stores
unchanged. Do not use a shared or production machine. No certificate is exported.
Native checks run without SDK discovery, at timing scale 1 and the existing
15-second signature cap. They exercise filesystem containment, binary/Unicode
round trips, argument quoting and descendant cancellation. The cancellation
handshake uses a small Python parent and a real PowerShell descendant; it measures
Job cancellation without waiting for two PowerShell interpreters to initialize. An absent symlink
privilege is an incomplete acceptance, not a passing skip.

On Linux, use the same wheel and checker in a fresh offline container or VM
with `pidfd_open` support (Linux 5.3 or newer) for PID-safe cancellation checks:

```sh
python3 scripts/qualification/artifact_acceptance.py \
  --wheel /input/enclave_gateway-0.3.0-py3-none-any.whl \
  --pip-wheel /input/pip-approved-py3-none-any.whl \
  --work-dir /work/new-client --output /work/new-result.json
```

`--pip-wheel` runs an approved local pip wheel directly without network access
or installing build tools into the client; omit it only when the approved Python
already supplies `ensurepip`. The product
wheel always installs with `--no-index --no-deps` in a new venv. Linux checks run
the installed CLI, descriptor-relative filesystem, link/traversal denials,
owned-process cancellation and MCP read-only denial. Container results qualify
that Linux userspace/kernel environment, not physical hardware or a proprietary
provider. Failed logs and reports remain under their original names. Reports publish
atomically with a bounded Windows sharing-conflict retry. Read them after the
checker exits, or use an observer that permits file deletion/replacement.

## Assemble and verify with the public local command

Install the optional build-time schema validator (`pip install '.[release]'`) in
your private build venv. The ordinary CLI still has no required third-party
Python dependencies. Fill the private manifest from
[the assembly example](../contrib/qualification/plans/candidate-assembly.json).
Pin every input file by absolute path and SHA-256; placeholder zero hashes are
unusable. Use the exact clean source commit, the passed two-build comparison,
its pinned toolchain, three locally approved CycloneDX 1.6 schemas, and passed
artifact receipts. Require both delivered Windows architectures and at least
one Linux architecture. Keep qualified platform scopes explicit.

```sh
python scripts/release/assemble_candidate.py assemble \
  --manifest /private/candidate-assembly.json --output /private/new-candidate
python scripts/release/assemble_candidate.py verify --candidate /private/new-candidate
```

Assembly binds every build input to committed Git bytes, including cases hidden
by ignore rules or index flags, and takes delivered notices/guidance from that
commit. It fails closed on dirty/uncommitted source, stale build inputs, missing
platform checks, mismatched artifact or qualifier hashes, changed dependency
archives, invalid SBOMs and extra/linked package files. It requires complete
Windows laboratory trust cleanup. Optional evidence identifiers export only
hashes; private input paths never enter distributable provenance.

The command assembles Python sdist/wheel, an exact-commit source archive,
unsigned Windows x64/ARM64 ZIPs, project/runtime licenses and notices, CycloneDX
SBOM, compatibility table, changelog, README, sanitized provenance and
`SHA256SUMS`. Runtime notices come from the hash-verified NuGet archives. SDK
and build-only tools are not shipped. Output directories must be absolute and outside the source, build and dependency
cache trees. New output directories preserve previous attempts. The verify subcommand checks the exact delivered inventory and rejects
changed, missing or unlisted files. Both commands work locally without hosted
workflows, tags, uploads or repository-setting changes.

Checksums establish integrity; they do not authenticate an untrusted download or
replace approved publisher signing. A signed package needs newly computed
signed manifests and independent production signing acceptance. These platform
checks do not establish RDP/WAN performance, proprietary VPN behavior, real keys,
production PKI or physical TPM qualification.

## Verify an actual RDP reconnect

Use two disposable Windows machines with distinct machine identities, synthetic
accounts and isolated networking. Connect the Appliance to Bastion with native
`mstsc.exe`, redirect only the laboratory drive, validate the server certificate,
and retain NLA. A local spool, injected exception or revoked SMB handle exercises
regression paths but does not qualify actual RDP reconnection.

### Foreground profile

For `structured_only`, record the approved worker and policy hashes. Run the
signed foreground command explicitly in the ordinary Bastion user's session.
Wait for a fresh running heartbeat and nonce attestation before dispatch.
Interrupt the owned RDP connection during an operation with a unique observable
side effect. Retain the Host timeout and the durable transaction record.

After reconnect, require events 24 and 25 for the same Windows session. The old
foreground worker must not relaunch itself. Start a new instance explicitly and
verify its fresh attestation. Reconcile the original remote effect. Remove an
owned cancellation marker only after preserving it and confirming the previous
worker exited; resend the same transaction ID with a fresh deadline to prove
the durable ledger itself rejects replay. Check a completed ID as well. Neither
request may repeat the remote effect. End with acknowledged stop and cleanup
that preserves the ledger. This profile has no bootstrap supervisor or autostart
acceptance path. See [the qualification scope](ENDPOINT-POLICY.md#qualification-status).

### Legacy Stream supervisor

Stage the exact candidate agents, start the local bootstrap inside the ordinary
Bastion user session, and record its Windows session ID, SID, PID, worker hash,
instance ID, storage binding, fresh attestation and startup invocation count.
Any initial logon task must have no reconnect trigger or restart policy.

Interrupt only the owned laboratory RDP connection and let the same native client
reconnect automatically. Require Windows LocalSessionManager events 24 and 25
for the same session, a new ready IPC descriptor, unchanged SID/bootstrap PID,
unchanged startup invocation count and task LastRunTime, the original journal
binding, fresh nonce attestation and successful command execution. Do not manually
launch a worker to make this check pass.

Repeat with an in-flight side effect. Preserve the failed/indeterminate request,
reconcile its effect, and resend both completed and interrupted transaction IDs:
neither may execute again. Require exactly one side effect for each. End with
acknowledged stop/autostart removal and confirmed process exit without respawn.
Exercise repeated autostart registration as the normal user too: creation alone
does not cover updates to an existing protected installation.

Include a backlog from several retired IPC instances before recovery. Require
the same startup/readiness deadline and successful execution without any startup
history pruning. After a confirmed stop, verify explicit local Appliance cleanup:
retired empty placeholders and heartbeats disappear, while latest-instance files,
nonempty outcomes, requests and the journal remain. Locked files must be deferred,
links preserved, and an invalid descriptor must not authorize deletion. Test this
on local Windows storage; redirected-drive deletion is intentionally absent from
worker startup and recovery.

Keep failed attempts, event records, source hashes and receipts outside Git.
These checks qualify recovery on the tested Windows/RDP environment; they do not
establish WAN latency, production PKI, Enterprise isolation or proprietary VPN
acceptance. Preserve all existing readiness, attestation and performance gates.

## Maintainer publication decisions

Version/tag, repository visibility, package registry upload, a working private
vulnerability-reporting channel and production code-signing identity are explicit
maintainer decisions. Keep the candidate unsigned and unpublished until those
decisions are made. Do not silently advertise a developer/lab signer as a trusted
publisher or claim proprietary VPN/PKI/physical-TPM qualification from this kit.
