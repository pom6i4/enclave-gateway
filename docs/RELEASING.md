# Preparing an unsigned release candidate

The release candidate is a source-bound bundle for review. It does not publish a
tag, upload packages, change repository visibility or establish Enterprise signing
trust. Hosted workflows are not needed for these steps.

## Component compatibility

| Component | Contract | Validation boundary |
| --- | --- | --- |
| Python CLI/package | `0.2.0`, Python 3.10 or newer; the release matrix exercises 3.10–3.14 | Pure Python has no mandatory third-party runtime dependencies. Record exact Python patches and platform for each run. |
| Windows native helpers | `net10.0`, self-contained `win-x64` and `win-arm64` | Use the exact pinned SDK/runtime and both helper projects. Cross compilation and PE inspection do not prove Windows execution. |
| Worker identity | Attestation version `0.3.0`, fresh nonce, approved hashes/signer/SID when required | This is an independent worker contract, not the Python package version. Deploy matching approved scripts/runtime together. |
| Worker journal and telemetry | Revision 2, local journal with protected spool binding | Preserve transaction identities across restart, migration and backup reconciliation. |
| Optional stream framing | Descriptor revision 3, 4 KiB request alignment | Host and worker must both select `stream`; no automatic replay or protocol downgrade. |
| Enterprise distribution | Authenticode plus signed CMS metadata and release ordering | Unsigned candidate binaries cannot satisfy production Enterprise installation. |

Standard requires no custom worker executable for ordinary runspace/key-based SSH.
Host OS support, native acceleration, Windows sharing, RDP policy and proprietary
VPN drivers are separate platform contracts; a Python matrix does not qualify them.
Use [SECURITY.md](SECURITY.md) and the [qualification guide](../contrib/qualification/README.md)
for their prerequisites and evidence limits.

## Validate the source and Python matrix

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
  --wheel C:\Acceptance\enclave_gateway-0.2.0-py3-none-any.whl `
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
  --wheel /input/enclave_gateway-0.2.0-py3-none-any.whl \
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
