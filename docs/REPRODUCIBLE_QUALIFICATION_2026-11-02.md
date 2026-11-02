# Reproducible acceptance qualification — 2026-11-02

Status: **passed**, including all ten full-plan steps, nested evidence verification and final owned-resource cleanup.

Product/qualification source: `346208c71797448ab6621b58572ad2fef026b7fa`, following `7c31ea0`. No client environment, production keys, hosted Actions changes or dispatches were used.

## Implemented improvements

1. A public full acceptance command verifies tool/media identities, builds the dedicated helper, rejects the generic runtime in its role, runs ordinary/installed/generated checks, installs Windows from a blank disk, verifies cold security/powercycle, runs issued PKI/migration/preparation cases, and stops only its own resources. Source changes and missing cleanup fail the whole run. Nested results/inventories are bound without a root hash cycle.
2. The installed-package checker records platform and complete product-input hashes before and after sdist → wheel → a fresh venv outside the checkout, both entry points and actual installed provisioning. The matrix comparator normalizes Windows separators, requires exact current inputs and requested platforms, and rejects duplicate/stale/failed reports.
3. Seeded models cover framing, acknowledgement loss and principal/journal reopens. Four actual journal-process crashes and eight actual VM-state publication crashes exercise durable boundaries. Serialized counterexamples are retained. The strengthened framing model found and reproduced valid coalesced control frames being rejected at an individual frame bound; the reader now bounds each line, preserves delimiter synchronization and rejects oversize input with one detection byte of read-ahead. The default 96 MiB bound is unchanged.
4. The release tool builds independently twice from clean exports, pins SDK/runtime/build tools, blocks ancestor imports/private feeds and verifies NuGet archives plus expanded payloads. Native executables, Python wheel, canonical source archive and unsigned package bytes must agree. Raw sdist intermediate hashes are retained; canonicalization changes container metadata, not member contents. The compatibility PowerShell helper also uses a clean export/new output and pins SDK selection correctly after Set-Location. CycloneDX distinguishes runtime materials from restore-only materials.

## Observed checks

| Check | Result |
| --- | --- |
| macOS interpreter matrix | Python 3.10.22 / 3.11.17 / 3.12.15 / 3.13.16 / 3.14.5: 160 tests each, one Windows-only skip; real PowerShell/.NET enabled |
| Linux final source | 160 tests, 13 explicit optional/platform skips, 5.559 seconds; new Debian ARM64 fixture |
| Current installed package | macOS ARM64/Python 3.14.5; Debian ARM64/Python 3.11.2; Windows ARM64/Python 3.14.5; Server x64/Python 3.14.5; complete current input hashes agree |
| Generated models | Seeds 17 / 9173 / 65537, 200 cases/model/seed; 1800 modeled cases plus malformed-frame checks; 12 actual process crashes |
| Compatibility helper | Actual askpass and runtime win-x64 builds, SDK 10.0.403/runtime 10.0.14; changed PowerShell location, isolated source and fresh output |
| Public Windows suite on ARM64 | 2 preparation, 9 migration, 12 issued-PKI cases; temporary signer/key cleanup passed |
| Full public plan | All 10 steps passed; complete source hashes unchanged through terminal cleanup |
| New blank-disk x64 Windows lifecycle | Standalone 32 GiB disk, no backing or preinstalled guest data; TPM/Secure Boot true; first cold request 29.626 s and next cold request 29.847 s, each once within 120 s |
| Full poweroff and next boot | Actual owned VM/software TPM stopped; boot identity changed; preparation source/readiness/progress hashes and modification times unchanged |
| Public Windows suite on new x64 installation | 2 preparation, 9 migration, 12 issued-PKI checks; all 9 nonces 1035–1226 ms within 10000 ms; required revocation/expiry causal flags present |
| Final cleanup | Temporary lab signer/root/key removed; owned VM and software TPM stopped; prior package fixtures also stopped |
| Independent unsigned builds | 20 matching final files across two clean builds; SDK 10.0.403, runtime 10.0.14, Python 3.14.5, setuptools 81.0.0, wheel 0.48.0 |
| SBOM | 29 components; validated against the official CycloneDX 1.6 schema and its referenced schemas |
| Evidence integrity | All 91 indexed files rehashed, including nested results/inventories; source and media bindings independently checked |

Full public entry: `python scripts/qualification/full_acceptance.py --manifest <private-manifest> --output <new-directory>`. Usage and scope are in [the guide](REPRODUCIBLE_ACCEPTANCE.md). The filled manifest pins media/tools and requires all four installed-package platforms. The SBOM is an unsigned build/material inventory, not a signed production release.

## Evidence identities

The product and executable qualification inputs are those of `346208c71797448ab6621b58572ad2fef026b7fa`. This report and its guide link are documentation added after terminal acceptance. The filled plan, raw logs, lab state and failed evidence remain private; their absence from the repository is intentional.

The final full-plan inventory SHA-256 is `0765c39929c9a65a8d6a4ef2c27c9c0a4a8077af8dc4a0f649a21c61c7a50296`. Independent postflight verification checked every indexed file against the retained bytes and confirmed no owned QEMU/software-TPM process remained.

The exact [unsigned SBOM](qualification/unsigned-346208c.cdx.json) has SHA-256 `9cde63f86770de05f1e624669dcddfa068bb3f9b507b2231762d1caa46aa7d83`. It contains relative artifact names, public package identities and hashes. No executable or signed distribution is published by this report. The reproducible canonical sdist hash is `6eda3785798289d09b95faf16528d700595c4f72920f03e579852bfbbe11264e`; the wheel hash is `1f380bb753171c4d23a6f96c0ab49ff7b0cfc19ca9ee76416b0fc25b483cc5d1`.

Installed-package reports are bound to identical current **source input sets**, not identical package archive bytes across platforms/build environments. Each platform built and installed its own wheel. The separate two-build gate establishes byte equality only within the pinned unsigned build cohort above.

## Retained failures

All failed and invalid records remain private. They include the initial relative-output build error, the old nested-result indexing omission covered by a tamper regression, and the seeded coalesced-frame rejection (seed 17, case 1, four individually valid frames at a 185-byte limit). The failed framing report remains failed; a separate resolution records the fixed source and passing replay/models.

The previous Linux base/profile backing image was unavailable, so it supplied no new acceptance. A new official Debian image was SHA-512 checked before boot. Its initial USB seed attempt failed strict SSH host-key checking; switching the owned seed to virtio let cloud-init identify the NoCloud source and install the preselected lab key. Strict host-key checking was retained throughout. No failed observer was promoted to a pass.

The stopped previous owned Windows image was losslessly compressed locally under its state lock. Full logical-sector comparison succeeded before atomic replacement. No VM, seed, credentials or key state was exported; all current images/evidence remain local and private.

## Bounds

These are finite functional/emulation and disposable-PKI samples. Default frame size, ten-second native nonces and single 120-second cold security requests remain unchanged. Explicit 600-second file staging budgets do not extend those gates. Process crashes do not establish physical power-loss/controller-cache durability. Matching unsigned builds with one pinned toolchain do not attest a compromised build OS, production signing, TSA time accuracy, physical TPM, WHPX or licensed provider interoperability. Optional/platform skips and historical failures remain explicit.
