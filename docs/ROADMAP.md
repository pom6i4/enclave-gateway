# Roadmap after 0.3.0

## Accepted baseline

The stable baseline is `v0.3.0` at
`29dad2ea643e5eed7fffc1a795827aa485ab1b85`.
Its [Standard operator release cycle](STANDARD_OPERATOR_CANDIDATE.md#release-cycle-status)
is complete for the exercised route. Historical acceptance remains bound to its
exact package and deployment scope. The original tag and assets are immutable.

The working version is `0.4.0rc2`. It is an unpublished Standard operator clock candidate.
Installing it is not required for continued operation of the accepted release.
Confirmed maintenance defects can be addressed separately in `0.3.x`.

Clock field verification of the exact RC2 at
`18b43df51ca7360534447bde67953a819e5cb8cc` passed according to the operator's
[source-bound report](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-clock-verification-040rc2).
One `heal` corrected the measured offset. Checks through 300 seconds passed.
The worker and its RDP session were retained. This closes the clock program
for that candidate, while 128 MiB round-trip acceptance remains incomplete.

## First 0.4.0 block

The following changes are implemented at
`363d8f72dc2c3ab1eebf9d60a3a95215cba468b3`. Local checks passed.
The exact source also passed all 15 hosted CI jobs. The
[operator-supplied field record](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-development-block-040dev0)
reports functional acceptance under explicit session-continuity conditions.
It does not establish unattended reliability or a published release.

### P1: large transfers through MCP

- Add explicit `chunked` to `node_transfer`.
- Add a finite positive `timeout_sec` up to 86,400 seconds.
- Retain ordinary copy as the default.
- Reuse the existing operator chunked-copy engine and its 512 MiB limit.
- Require the approved worker's fresh chunked-copy capability.
- Preserve authorization and read-only restrictions.
- Preserve stable transaction identity across cancellation or a lost reply.
- Reject unsupported routes instead of switching copy modes.
- Exercise 128 MiB in both directions with SHA-256 verification.

The ordinary source suite includes a 128 MiB MCP/engine/journal wrapper test with
a local backend substitute. The opt-in portable PowerShell fixture exercises
MCP through the worker and persistent Python peer using local pipes. Neither
test establishes real RDP or endpoint-policy compatibility. The separate field
receipt covers the exercised real route. Its full round trip passed on attempt
four. Failed attempts remain part of the evidence.

### P1: installed-package MCP acceptance

- Build sdist to wheel outside the checkout.
- Install into a fresh noneditable environment.
- Compare all installed runtime files with that exact wheel.
- Compare wheel metadata with the imported module version.
- Verify both installed console entry points.
- Start a separate read-only stdio server with an isolated configuration.
- Disable Bastion and provide no targets or forwards.
- Strip inherited deployment environment variables.
- Deny Python network and subprocess audit events during the MCP smoke test.
- Verify the guard with actual denied probes.
- Require the expected `initialize` server version.
- Require successful local smoke calls.
- Close only the test server's stdin and require exit zero.

The portable audit guard prevents accidental I/O in trusted Python code. It is
not an OS sandbox or hostile-code isolation. Existing IDE sessions are outside
this check. The [checker](../scripts/qualification/mcp_installed.py) never
restarts them or contacts a deployment.

### P1: continuous checks

- Run the ordinary suite on Python 3.10 through 3.14.
- Run each interpreter on Ubuntu.
- Run each interpreter on macOS.
- Run each interpreter on Windows.
- Run installed-package and fresh MCP acceptance in each of the 15 jobs.
- Retain explicit skip reasons for optional fixtures.
- Give the workflow read-only repository permissions.

Hosted CI qualifies only the actual runner environment. It does not qualify all
Host architectures or hypervisor acceleration. Local passing results alone do
not establish a hosted result. The linked CI receipt applies to the exact
implementation commit above; later documentation does not qualify new runtime.
The macOS Python 3.10 cell explicitly uses `macos-15-intel`. Other macOS cells use
`macos-latest`. The official [Python build manifest](https://github.com/actions/python-versions/blob/main/versions-manifest.json)
has newer 3.10 patches for Intel than ARM64. The explicit
[Intel runner label](https://github.com/actions/runner-images#available-images)
avoids qualifying that cell with an older ARM64 patch.

### P1: maintainable qualification instructions

- Use the selected stable release as the next candidate's upgrade baseline.
- Keep the old release's original receipts as historical evidence.
- Compare runtime and agent changes before selecting regression scope.
- Keep private receipts and filled configurations outside Git.
- Publish only an anonymized result after the applicable checks finish.

## Later priorities

The candidate adds [Host-side transfer observations](MCP_TRANSFER_DIAGNOSTICS.md).
Local late-read regressions preserve deadlines and no-replay behavior. The
[offline analyzer](../scripts/qualification/copy_ledger.py) maps ledger counts
to data offsets without a deployment connection. These tools do not establish
the cause of the real-channel delay. A
[saved-evidence review](../contrib/qualification/FIELD_ACCEPTANCE.md#follow-up-review-of-saved-attempt-3-evidence)
verified the field wheel against all 65 Git runtime files. It distinguishes the
ledger counts from the earlier block-123 annotation. The later raw ledger
snapshot establishes block 74 at offset 76546048 through exact request identity.
The old annotation is incorrect.

The [RC1 field program](../contrib/qualification/FIELD_ACCEPTANCE.md#incomplete-candidate-acceptance-040rc1)
is **INCOMPLETE / ПРОВЕРКА НЕ ЗАВЕРШЕНА**. One 128 MiB push completed on its
second attempt. None of six pulls completed. Diagnostics and no-replay checks
passed. Agent bytes remain unchanged. A completed late response without RDP
loss must be investigated separately from worker-indeterminate outcomes. No
transfer-runtime correction is justified until the delay boundary is isolated.

The later bounded 8 MiB probe passed without completing long-transfer acceptance.
Its calibrated Appliance offset was approximately 17 seconds behind Host.
A separate local clock review found implicit timestamps sampled before QGA
lock waiting. RC2 corrects that ordering and verifies the clock after QGA-backed
`heal`. Its short clock field program passed through 300 seconds. This does
not establish the defect as the cause of the earlier pull delay. Preserve that
remaining investigation separately from the completed clock program.

### P2: operator transfer performance

The current field evidence leaves specific follow-up work:

- Preserve the reconciled historical offset and all six RC1 failed outcomes.
- Separate target execution from worker publication and Host response visibility.
- Correlate disconnect events without assuming they explain every timeout.
- Isolate the late response without an RDP break before changing timeout gates.
- Preserve the approved policy; withdraw the unsupported idle-timeout diagnosis.
- Use the [bounded reverse-path probe](../contrib/qualification/MCP_REVERSE_PATH_PROBE_RU.md) before another full run.
- Measure first-attempt long-transfer reliability under those normal conditions.

The historical 61.7018-second interval comes from response-file timestamps;
it does not independently measure request latency. The RC1 operator also
reported a late response beyond the attested 45-second step budget.
Increasing the whole-copy timeout does not extend that step budget.
Do not add automatic mutating retries to conceal an indeterminate result.

Measure time spent at each boundary on the accepted route before optimizing.
Keep first-attempt failures and uncertainty in the results. The historical
800 ms cold-call target is not a current operator SLA. Preserve integrity and
no-replay behavior when improving throughput.

### P2: additional deployment qualification

Select one requested Host platform or endpoint-policy cohort at a time. Bind
installation and actual route acceptance to the exact candidate artifacts.
Do not infer VPN-driver acceptance from a green Python matrix.

### P3: background recovery

Qualify the [legacy Stream supervisor](RELEASING.md#legacy-stream-supervisor)
separately with actual RDP disconnection and reconnection. Require unchanged
session ownership and no repeated side effect. Verify acknowledged stop without
respawn. Do not add implicit autostart to the manual operator profile.

### P3: native Enterprise distribution

Obtain production signing approval before promoting native packages. Require
exact-artifact Windows x64 execution and Windows ARM64 execution. Exercise the
production metadata trust lifecycle separately from disposable laboratory PKI.
Keep native Windows-host managed TPM unsupported until its backend is qualified.

## Next candidate gate

Use `v0.3.0` as the stable upgrade/rollback baseline for the first 0.4.0 candidate.
Run the [candidate checklist](STANDARD_OPERATOR_CANDIDATE.md#qualification-checklist-for-future-candidates)
against the new source and exact wheel. Field acceptance of the MCP addition
at `363d8f7` covers a 128 MiB push and pull through the changed tool. It includes
controlled cancellation and no-replay checks. Preserve all failed attempts and
the qualified acceptance scope. New runtime changes require their own regression.
Broaden the lifecycle regression when deployment components or runtime behavior
change. The [targeted candidate field prompt](../contrib/qualification/MCP_RELIABILITY_FIELD_PROMPT_RU.md)
requires approved session-continuity evidence and the new observations.
The RC1 program did not complete its required round trip. Existing functional
acceptance alone does not close stable promotion. No next release is authorized
by this roadmap alone.
