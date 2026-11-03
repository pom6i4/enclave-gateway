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

Assemble the reviewed kit from the matching artifact tree:

- Python sdist and wheel, and a separate exact-commit source archive containing
  native sources, tests, configuration and maintainer tools.
- Unsigned Windows x64/ARM64 packages with their unsigned manifests.
- Project MIT license and the embedded runtime packages' license/notices, copied
  from the hash-verified dependency archives. SDK/build-only tools are not shipped.
- CycloneDX SBOM, component compatibility table, changelog and candidate README
  stating that signing, Windows execution and production acceptance are separate.
- `SHA256SUMS` covering all delivered files and a provenance receipt naming the
  source commit, artifact hashes, toolchain and test/history-audit evidence hashes.

Reject symlinks and unlisted files when checking the final kit. Verify every listed
hash again after packaging. Record private machine paths only in private build
reports, never in the distributable provenance. Checksums establish integrity;
they do not authenticate an untrusted download or replace the approved signing
procedure. A later signed package needs newly computed signed manifests/hashes.

## Maintainer publication decisions

Version/tag, repository visibility, package registry upload, a working private
vulnerability-reporting channel and production code-signing identity are explicit
maintainer decisions. Keep the candidate unsigned and unpublished until those
decisions are made. Do not silently advertise a developer/lab signer as a trusted
publisher or claim proprietary VPN/PKI/physical-TPM qualification from this kit.
