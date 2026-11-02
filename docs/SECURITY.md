# Security architecture and Enterprise deployment

## Trust boundaries

The Host operator controls the CLI and QGA/QMP channel. QGA commonly executes as
SYSTEM in the Windows Appliance. A Bastion worker accepts commands through an
RDP redirected spool and executes as the RDP user. SSH grants access to a separate
target account. Treat the control sockets, configuration, credentials, spool and
release material as privileged resources; protect their parents as well as files.

Standard mode trusts that operator, session and all spool writers. Its PowerShell
runspaces share one process, filesystem permissions and environment. Secret
scrubbing and destructive-command confirmations help prevent accidents; they do
not sandbox an adversarial script. Remote/native subprocess lifetime cannot be
proven merely from an in-process pipeline timeout. Standard is appropriate only
when this trust model matches the deployment.

Enterprise is an explicit fail-closed profile: signed helpers/agents, trusted
publisher thumbprints, worker and runtime SHA-256 pins, immutable worker SID,
fresh worker attestation, native owned process jobs and owned SSH commands are
required together. Explicit false/null requirements are rejected. Missing native
runtime, invalid signatures, changed bytes, wrong account or weaker execution
model never trigger a Standard fallback. Intermediate deployments can use Custom
with individually explicit requirements; they do not inherit an Enterprise claim.
Existing configs without `security.mode` retain the prior Custom defaults.

A policy-approved signed in-process deployment is also possible: Standard with
`require_signed_agents: true`, an approved `agent_package_dir`, both script hashes
and trusted publisher thumbprints. This can satisfy script-signing policy without
installing native executables, while retaining Standard's shared-process trust
boundary. It is not an Enterprise isolation claim.

A native owned job terminates its local process tree on deadline/cancellation or
supervisor closure. This is not remote effect rollback: an SSH peer, database or
service may have completed an action before disconnect. Query the transaction
journal and reconcile indeterminate operations instead of blindly replaying them.

## Approve a release on a build workstation

1. Build the native helpers and Python distribution on an approved release
   workstation using `scripts/release/build_helper.ps1` and
   `scripts/release/prepare_package.py` (see each command's help). The Bastion
   needs approved runtime binaries, **not a .NET SDK or compiler**.
2. Use `scripts/release/sign_windows.ps1` with the organization's code-signing
   certificate/service. Verify Authenticode and the signed CMS release manifest
   with `scripts/release/verify_windows.ps1`; configure the expected publisher
   independently. Production trust, certificate revocation, timestamp authority
   and rollover are administrator-owned requirements, not properties conferred
   by a disposable self-signed test certificate.
3. Install the verified matching helper package on each Windows execution hop
   using the approved release procedure. `scripts/release/install_windows.ps1`
   maintains authenticated release ordering. Do not copy unsigned development
   binaries over an installed Enterprise package or bypass downgrade protection.
4. Copy `config/enclave.enterprise.example.yaml`. Fill the exact approved worker,
   bootstrap and runtime hashes, certificate thumbprints and the RDP worker's
   immutable SID. Set `agent_package_dir` to the locally verified signed package.
   Obtain hashes from that approved package, not from an unverified running peer.
5. Run `egw config check`, `egw doctor --preflight` and `egw agents stage`.
   Staging verifies worker/bootstrap pins and checks their Authenticode publishers
   on the Appliance before publishing an immutable bundle. Runtime installation
   and CMS release approval are separate prerequisites; staging does not replace
   the installer or infer certificate trust from the remote response.
6. In the dedicated Bastion RDP session, execute the printed Enterprise bootstrap
   command. Bootstrap checks signatures and runtime before running the worker.
   `egw doctor --probe-targets` requires fresh release/runtime/SID evidence, then
   tests the actual channel. A heartbeat shown by `status` is only liveness.

`bastion_bootstrap.ps1 -Mode Enterprise -RegisterStartup` can register an approved
signed persistent worker for that user. Its runtime, publishers, scripts and
startup paths must be provisioned first. Standard bootstrap is foreground only;
it cannot register unsigned persistent startup. Existing signed Custom startup
settings remain supported. No mode turns off WDAC, AppLocker, ConstrainedLanguage
or domain execution policy. If `.exe` execution is forbidden, native isolation is
unavailable: an administrator must approve it or choose a suitable trust boundary.

## Principals, policies and MCP

For a trusted single local operator, MCP stdio inherits that OS user's trust.
Use `egw mcp --read-only` for a restricted integration. CLI and HTTP authorization
are separate from textual actor names inside tool arguments.

For governed read-only Enterprise service, supply `--policy` and the authenticated
principal. For a mutable Enterprise MCP service, also supply `--isolation-map`:

```sh
egw -c enclave.yaml mcp --policy access-policy.json --isolation-map isolation-map.json
```

Create a backend profile and private state directory for each principal, running
under a distinct dedicated nonadministrative OS account (Windows SID or POSIX UID).
Policies must match the broker grant, use explicit TargetNodes and private rooted
file paths, and deny controller command/file access. `PrincipalRouter` validates
these requirements; an editable username or a per-request `actor` field is not
an authorization identity. Do not share backend credentials, writable VM disks,
spools or target accounts between mutually untrusted principals.

For HTTP, use `--listen` only with an explicit policy, authenticated principal
tokens and the existing HTTP hardening rules. Expose it through an approved TLS
termination layer if crossing a host boundary. Do not publish a local developer
MCP listener to a network as an authentication shortcut. The implementation is
stateless MCP HTTP and stdio with negotiated supported versions, not a claim of
SSE session resumption or every future MCP extension.

`config/access-policy.example.json` is a deliberately narrow read-oriented
starting point. Extend its grants after reviewing the role's needs; it is not a
ready-made policy for arbitrary remote administration. Use the maintainer guide
for exact backend-map constraints and runtime fixtures.

## SSH, secrets and persistence

Keep StrictHostKeyChecking enabled and approve fingerprints out of band. The SSH
client may run on Bastion, Appliance or Host; [GUIDE.md](GUIDE.md#ssh-trust)
distinguishes the corresponding key stores. Base64 is encoding, not encryption.
The native askpass helper keeps passwords out of command arguments and temporary
password files, but privileged OS/process inspection remains in the trust boundary.
Do not put secrets in topology files, command history, release archives or Git.

Use the OS credential store, or a private environment file with appropriate
ownership/ACLs. Keep journals and audit logs private, configure retention and
monitor disk capacity. Transaction identities and retained outcomes prevent
unintended replay; finite retention requires explicit reconciliation when payloads
expire. Public qualification templates contain no filled manifests, credentials,
keys, VM images or proprietary installation media.

## Acceptance boundaries

Source tests, generated cases, emulated guests, temporary signing and local
installation checks support their stated scenarios. They do not establish
hardware TPM trust, physical power-loss durability, a production PKI lifecycle,
indefinite leak freedom or compatibility with every licensed VPN/driver version.
A generic reachable TCP endpoint does not verify a particular VPN provider.
Native Windows-host managed TPM still needs a supported backend. Historical
reports retain their original source identities in Git and do not certify current
source after an onboarding or documentation change.

See [maintainer qualification](../contrib/qualification/README.md) for reproducible
commands and evidence handling. For dependency upgrades, review the trusted tool
chain, runtime behavior and release materials again.
