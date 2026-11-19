# Standard operator release gates for 0.3.0

Package `0.3.0` is published as `v0.3.0` at
`29dad2ea643e5eed7fffc1a795827aa485ab1b85`.
The [installed-release field report](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-installed-release-v030)
records PASS / УСПЕХ for the exact published package on the exercised route.
The tag and original release assets retain their published bytes.

RC `0.3.0rc1` at `33fbcdecfba01ea8ed995379d39d8bc49886f706` separately passed
[operator-reported lifecycle acceptance](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-candidate-030rc1).
Actual reconnect and upgrade/rollback are closed for that tested RC route.
Final runtime differs from the RC only in its package version declaration.
Other profile and platform acceptance remains separate.

## Release cycle status

The `0.3.0` release cycle is **complete for the accepted Standard operator
scope and exercised route**.

- The immutable final release is published at the source commit above.
- All six source CI jobs passed for that exact release commit.
- Installed final-package field acceptance passed on the recorded route.
- The RC separately covered actual RDP reconnect and upgrade/rollback.
- [Local installed-package and fresh MCP verification](../contrib/qualification/LOCAL_ACCEPTANCE.md#installed-v030-local-mcp-verification)
  passed without contacting the real enclave.
- GitHub Private Vulnerability Reporting is enabled.

No mandatory correction is identified for that accepted scope by these results.
Normal operation can continue. New failures or changes to runtime/environment
determine the next regression scope. There is no requirement to repeat the
accepted field program solely to reconnect old IDE sessions.

The local MCP result does not certify every existing IDE connection. Those
connections remain under their client owners' normal lifecycle controls.
Broader Host platforms and execution profiles still need their own acceptance.
Native Enterprise qualification is outside this completed release scope.

## Published Standard operator scope

- Source and pure Python distribution.
- `security.mode: standard`.
- `bastion.execution_profile: structured_only`.
- `bastion.structured_backend: operator`.
- `bastion.spool_protocol: stream`.
- One approved Linux Target through system OpenSSH on Windows Bastion.
- Explicit manual worker attachment in the approved RDP session.
- Independently approved adapter and policy pins.
- Fresh worker attestation with the pinned operator identity.
- Existing approved endpoint policy without new protection exclusions.

This release does not promote other execution profiles to stable. It does not
change configuration defaults. It does not deliver native helpers or establish
Enterprise signing qualification. Host installation acceptance is separate from
Appliance or Bastion architecture. A platform is qualified only by an explicit
receipt for the candidate cohort.

## Accepted baseline and compatibility

The rollback baseline is `0.3.0b7` from `v0.3.0-beta.7` at
`bcafbb1ae71bd044ed6ec4a8a0cf7fafbefd7f44`.
Its [field acceptance](../contrib/qualification/FIELD_ACCEPTANCE.md#accepted-release-beta-7)
covers the exercised route under KES `21.3.10.1001`.

Final runtime differs from the accepted RC only in its package version statement.
Agent hashes remain those in the baseline record. The attestation version stays
`0.3.0`. Existing independently approved deployment pins must not be weakened.
Signed deployment bytes require their own approved hashes.

No config or journal migration is introduced. Configuration is validated by the
existing typed models. MCP request schemas retain their existing arguments.
The CLI provides `cp --chunked --timeout`; MCP `node_transfer` does not expose
that chunked-copy interface. No schema change was needed for the final package.

## Qualification checklist for future candidates

Publication requires a source-bound result for every applicable gate. Historical
reports do not become acceptance of new artifacts solely through a version bump.

- Compare every runtime file against Beta 7 and account for the version change.
- Confirm each agent digest and the independent attestation version.
- Run the ordinary source suite on Python 3.10 through 3.14.
- Run the applicable PowerShell fixtures with their actual skip reasons retained.
- Validate schema exports without deployment configuration or credentials.
- Run hygiene and review the diff for private environment identifiers.
- Build the wheel from the sdist in two independent exports with pinned tools.
- Require matching wheel and canonical sdist bytes.
- Install outside the checkout on every proposed supported Host platform.
- Verify installed entry points and packaged resources.
- Record unavailable platform checks as pending.
- Verify actual RDP disconnection and reconnection during a test operation.
- Prove no duplicate effect for completed and interrupted transaction IDs.
- Verify Beta 7 to candidate upgrade in the working Host environment.
- Verify explicit rollback to the retained Beta 7 wheel.
- Preserve the same configuration and journal namespace across that cycle.
- Verify safe stop and lease release before each worker replacement.
- Verify final readiness and fresh attestation after each approved attachment.
- Confirm endpoint protection remains active without new events from testing.
- Retain private receipts and publish only an anonymized summary.
- Confirm a working private vulnerability-reporting channel before stable release.

The [field prompt](../contrib/qualification/STANDARD_OPERATOR_FIELD_PROMPT_RU.md)
defines the completed RC lifecycle program. Its report remains bound to the RC.
Installed final-package acceptance separately covers the 128 MiB round trip.
Repeat the larger regression if runtime behavior or deployment components change.

## Final artifact preparation and publication

The final manifest records the initial build and qualification cohort. Later
field evidence is added as a separate supplement. Future publication remains
an explicitly authorized operation with exact-source checks.

- Verify the package version is `0.3.0`.
- Update its metadata status after acceptance is complete.
- Review the complete difference from the accepted RC.
- Rebuild the exact final artifacts.
- Repeat exact-artifact installation checks.
- Repeat source checks appropriate to the final difference.
- Review current secret-scan findings individually.
- Bind the accepted runtime equivalence and field receipts to the final manifest.
- Create the final tag only after all required results are available.

No arbitrary Bastion command is added for clock measurement. No 800 ms cold-call
SLA is asserted. Background supervisor reconnect is outside this operator scope.
The full native distribution follows its separate gates in
[RELEASING.md](RELEASING.md#assemble-and-verify-with-the-public-local-command).
