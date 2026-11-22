# Standard operator 0.4.0 readiness

## Published release and scope

[`v0.4.0`](https://github.com/pom6i4/enclave-gateway/releases/tag/v0.4.0) is
published at `aee21a5ffc1a3aa6a303e6eb06b98dc1b44524f5`. All 15 hosted CI jobs
passed for that commit. The operator confirmed the exact wheel installation,
fresh MCP initialization and preservation of the Host journal. See the
[installation record](../contrib/qualification/FIELD_ACCEPTANCE.md#confirmed-installation-of-v040).

The operator reported **PASS / УСПЕХ** for installed `0.4.0rc4` at
`a46529825a87e80e6e218d39cfa2a40089d5fb68`.
Its [source-bound receipt](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-transfer-verification-040rc4)
closes the 128 MiB MCP round trip for that candidate. Stable `v0.3.0` remains
the rollback baseline.
Its source is `29dad2ea643e5eed7fffc1a795827aa485ab1b85`.

The release scope is limited to:

- Source and pure Python distribution.
- Standard security mode.
- The `structured_only` execution profile.
- The manually attached `operator` backend.
- Stream spool protocol.
- The exercised QGA and approved RDP route.
- One approved Linux Target.
- Independently approved deployment pins.

The installed release's 128 MiB round trip and transfer no-replay check remain
open. The field run stopped before dispatch because the interactive session
was unavailable and the foreground worker was stopped. Field RDP reconnect
remains a separate open check. Earlier candidates retain their own outcomes.

## Gates already supported for exact RC4

- All 65 installed runtime files matched its exact wheel.
- Fresh MCP initialization reported `0.4.0rc4`.
- First-attempt 128 MiB push passed.
- First-attempt 128 MiB pull passed.
- All three copies matched in size and SHA-256.
- Both worker ledgers had complete unique data offsets.
- New MCP sessions returned retained outcomes without new copy dispatch.
- Reported read-only clock intervals passed the tolerance gate.
- Acknowledged stop released the lease without respawn.
- Protection remained active with zero new reported events.
- The adapter bytes match stable `v0.3.0`.
- The independent worker attestation contract remains `0.3.0`.
- Two independent RC4 builds produced identical wheels.
- Canonical RC4 sdists matched across those builds.
- The exact wheel passed installed-package checks on Python 3.10 through 3.14.
- Extracted candidate verification passed on those five interpreters.
- [RC4 CI](https://github.com/pom6i4/enclave-gateway/actions/runs/44972088954)
  passed all 15 matrix jobs.
- Configuration-free MCP schema exports retain the explicit chunked arguments.
- GitHub Private Vulnerability Reporting was confirmed enabled during this review.

The [local rollback receipt](../contrib/qualification/LOCAL_ACCEPTANCE.md#local-rollback-between-v030-and-040rc4)
records **PASS / УСПЕХ** for the exact-wheel cycle between `v0.3.0` and RC4.
The same test journal retained completed and indeterminate outcomes. Its
archived payload remained readable. Repeated transaction identities caused no
additional dispatch. The older MCP schema rejected the RC4 chunked requests
before dispatch. This qualifies the local Host package and journal boundary.

The local optional portable PowerShell launch did not complete in the RC4
candidate run. Its log remains unqualified. Final source runs retained explicit
skips. This limitation is recorded in the immutable candidate's `LOCAL_CHECKS.md`.
It must not be relabelled as a passing optional test.

## Field lifecycle and release checks

### 1. Complete the applicable field lifecycle program

Field RDP reconnect remains open. The RC4 transfer program retained
uninterrupted RDP. The local rollback exercise used a synthetic journal and a
transport fixture. The field lifecycle still needs evidence from the exercised
route and its live worker. Earlier `0.3.0rc1` lifecycle acceptance applies to
its own Host runtime.

- Interrupt only an owned approved RDP test connection during an owned operation.
- Preserve the interrupted operation's transaction identity and original arguments.
- Reconnect through the normal client lifecycle.
- Reconcile the owned remote effect with the retained journal and worker ledger.
- Require a fresh worker identity after an explicit replacement attachment.
- Reject duplicate effects for completed transaction identities.
- Reject replay of the interrupted transaction identity after MCP restart.
- Preserve prior destination contents when a download cannot be committed.
- Retain protection checks and acknowledged stop observations.
- Execute stable-baseline to candidate upgrade with the same configuration.
- Execute explicit rollback to the retained `v0.3.0` wheel.
- Preserve the same journal namespace throughout the cycle.
- Verify the older MCP schema rejects unsupported chunked arguments before dispatch.
- Return to the candidate and verify retained outcomes remain protected.

Never restore an old database over newer transactions to make rollback pass.
Keeping the rollback wheel on disk is not a rollback test. Existing pending
transactions must not be bypassed using new identities. The manual operator
profile does not require or permit implicit supervisor recovery for this gate.

### 2. Qualify exact final 0.4.0 bytes

The published artifact set was prepared separately from the accepted RC4 bundle.
The following checklist records the final build and qualification requirements.

- Set the final package version in both declarations.
- Review package maturity metadata against the limited stable scope.
- Bind the final source to a clean exact commit.
- Compare every final runtime file with accepted RC4.
- Account separately for the version-only difference.
- Repeat applicable field regression if any further runtime behavior changes.
- Confirm all agent hashes and the independent worker contract.
- Build sdist to wheel from two independent committed exports with pinned tools.
- Require equal wheel bytes and equal canonical sdist bytes.
- Run the final source suite on supported Python versions.
- Record actual outcomes for applicable PowerShell fixtures in an available runtime.
- Retain unavailable optional checks as explicit limitations.
- Require all 15 final-commit CI jobs to succeed.
- Install the same final wheel noneditably in the qualification environments.
- Verify packaged resources and installed entry points.
- Require fresh MCP initialization to report `0.4.0`.
- Verify configuration-free schema exports from the final package.
- Bind the accepted field evidence and runtime comparison to the final manifest.

The final source declares version `0.4.0`. The private artifact manifest records
the exact source comparison and checks on the final wheel. A version-only
runtime difference allows the previous 128 MiB result to be cited for RC4.
All 15 hosted CI jobs passed for the final commit. Field reconnect remains open.

### 3. Final publication checklist

- Run repository hygiene on the exact final commit.
- Run the stored-history audit with individually reviewed findings.
- Run a pinned independent secret scanner with full redaction across all refs.
- Scan the exact final distributable payload and release notes.
- Review synthetic findings individually without broad scanner exclusions.
- Reconfirm the private vulnerability-reporting channel.
- Prepare anonymized release notes with the accepted Standard operator scope.
- Keep every earlier tag and artifact immutable.
- Obtain separate explicit authorization before creating the final tag or Release.
- After authorized publication, download the uploaded assets and verify SHA-256.

The initial RC4 history findings match previously reviewed immutable findings.
The independent scanner's findings also match the earlier individually reviewed
set. No new finding was identified in that comparison. This is a limited pattern
review, not proof that every possible secret is absent. Final commit and final
payload checks remain separate from this current-source review.

## Follow-up outside the scoped stable gate

- Historical physical causes of incomplete RC1 and RC3 transfers remain unresolved.
- Longer unattended soak and latency optimization remain separate performance work.
- Additional Host architectures require their own exact-artifact receipts.
- Other endpoint-policy cohorts require their own deployment acceptance.
- Legacy supervisor reconnect is a separate execution-profile program.
- Native Enterprise distribution retains its production-signing gates.
- Native Windows-host managed TPM remains outside this Standard operator release.

These items do not require expanding the proposed source/Python release into
unqualified profiles. New failures on the accepted route can reopen a gate.
