# Reproducible local acceptance and unsigned releases

The full local entry point combines tool checks, two independent builds,
ordinary tests, installed-package checks, generated fault models, a new Windows
installation and disposable Windows PKI/migration/preparation acceptance:

```sh
python scripts/qualification/full_acceptance.py \
  --manifest /path/to/private/full-acceptance.json \
  --output build/acceptance/full-001
```

Start with [the manifest example](plans/full-acceptance.json). Its zero
digests are deliberately unusable. Supply approved local tool/media paths,
actual SHA-256 values, exact tool/build-package versions, an explicit .NET
runtime patch and a fixed source epoch. The example versions identify one
qualification cohort; they are not an automatic upgrade policy. The Python
entry must refer to the build venv, including its pinned setuptools and wheel.
The executable entry is preserved when that venv uses a symlink to base Python.
Keep the filled manifest and outputs private. Trusted local tools and manifests
are operator inputs, not a sandbox for executing untrusted tool binaries.

Full acceptance currently requires a POSIX QEMU host, qemu-img, software TPM,
matching UEFI/media and an ISO mastering tool. Windows runs inside a newly
created restricted-network VM with a custom provider and no Bastion/provider
installation/key material. No hosted workflow is consulted or invoked.

Use `--host-only` for the host portion; the report explicitly retains
`scope=host-only`. This does not claim Windows installation or PKI acceptance.
The simpler [local plan](LOCAL_ACCEPTANCE.md) remains available separately.

## Preflight and failure behavior

Preflight checks local TCP/Unix sockets, executable digests, exact Python,
PowerShell and SDK versions, and Python build-package versions. It builds the
dedicated askpass and runtime from fresh exports, tests Unicode and invalid-input
behavior, and requires the generic runtime to fail the askpass role. This catches
the wrong-artifact invocation before the ordinary suite starts.

Every run uses a new directory. Step failures stop later steps; timeouts reap
only owned child process groups. Failed reports and diagnostics remain. Media
approval hashes are checked before host work and again before installation.
The installer additionally binds source/media/driver hashes before first boot.
The full source inventory must also remain unchanged through terminal acceptance.
Ambiguous VM ownership or incomplete cleanup fails the complete run.

After the complete blank-disk lifecycle and its cleanup, the runner restarts
only that owned VM for the additional Windows suite. Input archives and files
are hash-checked before execution. The suite creates a nonexportable temporary
code-signing key and only its own root trust, signs a fresh laboratory package,
runs actual preparation crashes, v1 migration and issued CRL/OCSP/cache/expiry/
timestamp/rotation cases, then removes its own signer and key. Host verification
requires 2 preparation, 9 migration and 12 PKI checks, causal chain failures,
9 nonce measurements at the unchanged ten-second limit and successful cleanup.
The final VM/TPM cleanup is recorded independently of the earlier lifecycle stop.

Explicit QGA `read_file`/`write_file` transfer budgets support large staged
artifacts. The default remains 30 seconds; this plan supplies 600 seconds.
Dispatch is not replayed after an uncertain acknowledgement. Transfer/readiness
budgets do not change either cold security request's single 120-second budget
or the native PKI nonce's ten-second limit.

## Independent builds and SBOM

```sh
python scripts/release/reproducible_build.py \
  --manifest /path/to/private/toolchain.json \
  --output build/releases/comparison-001
```

The build-only manifest is the `toolchain` object of the full manifest. The tool
exports an allow-list of product inputs into two independent directories;
existing obj/bin files, local credentials, private lab state and workflows are
excluded. Each export pins SDK selection with disabled roll-forward and uses an
explicit anonymous public-feed NuGet configuration. Restore creates a dependency
lock, then must pass locked mode. Runtime download versions are exact; package
SHA-512 and expanded runtime/native payload bytes are checked against the cached
archive before publishing. Restore/audit errors are not suppressed.

Both passes build a source distribution, build the wheel from the extracted
distribution and publish self-contained single-file Windows x64/ARM64 askpass
and runtime packages. The source epoch controls copied source and ZIP dates.
Source tar/gzip container metadata is explicitly canonicalized: sorted member
names, fixed time, neutral ownership and normalized regular-file modes. Member
contents are preserved. Raw intermediate sdist hashes are retained separately;
canonicalization is part of the published archive format. All final archive,
wheel, executable and package-file bytes must match across the two builds.
Mismatch fails the comparison; signing does not participate.

The compatibility `build_helper.ps1` entry also exports only direct project/CS
inputs to a private workspace and requires a new output directory. It records
source/SDK identities, blocks ancestor build imports and private NuGet feeds,
and accepts explicit `-SdkVersion` / `-RuntimeVersion` pins. Its per-component
build manifest does not replace the two-build comparison and SBOM above.

`sbom.cdx.json` uses [CycloneDX 1.6](https://cyclonedx.org/schema/bom-1.6.schema.json).
It records final file hashes, runtime package identities/content hashes, build
tool versions and dependency references. Embedded runtime materials are marked
required; other restore materials are explicitly excluded from runtime scope.
The SBOM describes the unsigned cohort. Signing changes file hashes and requires
new signed manifests; no production signature or acceptance is inferred.

SDK entry hashes and versions, locked materials and two matching builds establish
the observed toolchain/cohort. They do not attest a compromised build OS or prove
that every SDK installation file is vendor-authentic. Reproducibility is checked
with one pinned toolchain; cross-OS compiler equivalence is not claimed.

## Generated cases and installed packages

```sh
PYTHONPATH=src python scripts/qualification/generated_faults.py \
  --output build/acceptance/models-001 --crashes
```

Default seeds are 17, 9173 and 65537, with 200 cases per model per seed. Models
cover fragmented Unicode framing, malformed/oversize/EOF inputs, QGA lost
acknowledgements/status failures, principal/fingerprint conflicts and journal
reopens without replay. Four actual journal-process crashes exercise reserved,
running, pre-result and post-result states. Eight actual VM-state publication
crashes cover commit intent, all resource renames and the final commit boundary.
These fixtures create only small synthetic images and private journals. Process
crash tests do not establish physical power-loss/storage-controller durability.

Framing cases also vary the limit near the largest valid message and retain
serialized counterexamples. This exposed valid coalesced QMP/QGA messages being
charged against one aggregate limit. The reader now applies the unchanged limit
to each complete line, bounds read-ahead to one detection byte and retains QGA
delimiter synchronization. A real-socket regression covers CRLF coalescence,
stale prefix discard and oversized input. See the [QMP framing contract](https://www.qemu.org/docs/master/interop/qmp-spec.html).

Run `scripts/qualification/installed_package.py --output <new-directory>` on each
OS, with `--pip-wheel <offline-wheel>` when ensurepip is unavailable. It builds
sdist → extracted sdist → wheel → a clean venv outside the checkout, checks both
entry points and actual installed provisioning, and records platform plus exact
package-input hashes before/after acceptance. Compare those input hashes with
the final source; an older platform report is not promoted to a new cohort.

`compare_installed.py --report <report> --report <report> --require-platform
<system:architecture> --output <new-receipt>` compares the complete input sets
with the current source, normalizes Windows path separators, rejects ambiguous
paths, failed/stale reports and duplicate platforms, and enforces the requested
platform set. Canonical labels include `darwin:arm64`, `linux:arm64`,
`windows:arm64` and `windows:x86_64`. A full manifest can supply `installed_reports`
(the other OS reports) and `required_installed_platforms`; its host report is
included automatically. This qualifies the requested matrix, not every OS.

The passing sample does not establish indefinite leak freedom, physical TPM
attestation, Windows-host TPM support, production PKI/TSA/HSM trust or proprietary
licensed provider interoperability. Those boundaries remain separate.

The [2026-11-02 qualification report](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/REPRODUCIBLE_QUALIFICATION_2026-11-02.md)
records a completed full run, the four-platform installed matrix, retained
counterexamples, exact unsigned SBOM and acceptance boundaries.

The [extended runtime profile](EXTENDED_ACCEPTANCE.md) adds source-bound Windows
source suites, account isolation, actual fault/RDP cases, generated security
models and the complete two-hour mixed workload.
