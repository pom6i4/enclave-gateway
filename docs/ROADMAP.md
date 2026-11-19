# Roadmap after 0.3.0

## Accepted baseline

The stable baseline is `v0.3.0` at
`29dad2ea643e5eed7fffc1a795827aa485ab1b85`.
Its [Standard operator release cycle](STANDARD_OPERATOR_CANDIDATE.md#release-cycle-status)
is complete for the exercised route. Historical acceptance remains bound to its
exact package and deployment scope. The original tag and assets are immutable.

The working version is `0.4.0.dev0`. It is unpublished development code.
Installing it is not required for continued operation of the accepted release.
Confirmed maintenance defects can be addressed separately in `0.3.x`.

## First 0.4.0 block

The following changes are implemented for local verification. They are not a
field acceptance or a published release.

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
test establishes real RDP or endpoint-policy compatibility. The changed MCP
path still needs a source-bound field receipt before release promotion.

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
Host architectures or hypervisor acceleration. Local passing results do not
establish a hosted CI result before these workflow changes are pushed and run.
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

### P2: operator transfer performance

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
must cover a 128 MiB push and pull through the changed tool. Include interruption
and no-replay checks. Broaden the lifecycle regression when deployment components
or runtime behavior change. No next release is authorized by this roadmap alone.
