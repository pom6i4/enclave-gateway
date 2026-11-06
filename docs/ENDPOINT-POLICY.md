# Endpoint policy and the foreground OpenSSH profile

This describes unreleased source changes. It does not change the published
`v0.2.0` tag or certify compatibility with an antivirus product. Deployment on a
managed endpoint requires its administrator's approval. An active security
incident must be resolved through the organization's incident process first.

## Choose an approved route

Use an existing approved SSH or WinRM route when it removes the need for a
Bastion worker. A redirected RDP filesystem alone cannot execute commands.
When RDP is the only route, `bastion.execution_profile: structured_only` selects
an explicit foreground worker with fixed operations.

The foreground worker does not perform these actions:

- Register startup through the Windows registry.
- Register scheduled tasks.
- Install scripts or executables in AppData.
- Evaluate PowerShell supplied in a request.
- Create runspace pools.
- Open raw TCP sockets.
- Launch a custom executable on Bastion.
- Disable command history or endpoint logging.
- Change execution policy or filesystem ACLs.

It launches the Microsoft-signed `ssh.exe` in the system OpenSSH directory.
It ignores per-user SSH configuration through `-F NUL` and prohibits local
commands. It uses approved keys with strict host-key checking. File copies use
that same SSH process with binary stdin/stdout and remote Linux utilities.
The policy cannot supply an executable or arbitrary OpenSSH options.

`structured_only` currently supports only the Files protocol. Stream selection
is rejected rather than downgraded. Performance must be measured separately;
previous Stream latency results do not apply to this profile.

## Administrator preparation

1. Review the exact `bastion_structured.ps1` source and sign the approved bytes.
   Place the signed script in the Host's `security.agent_package_dir`.
2. Verify that Microsoft's system OpenSSH client is installed on Bastion.
3. Provision the executing user's SSH key and verified `known_hosts` file.
4. Review [the policy example](../config/bastion-worker-policy.example.json).
   Set the actual worker SID and explicit local trust-file paths. Approve each
   target independently of Host configuration. Remote shell execution grants
   the target account's permissions; this is not a remote filesystem sandbox.
5. Provision the policy on Bastion under an administrator-owned local directory.
   The policy file must be owned by SYSTEM or Administrators. Only those
   principals may have write or ownership-changing access. Give the worker SID
   read access. The worker validates this policy and never repairs its ACL.
6. Compute the approved policy's SHA-256. Configure its pin on Host.
7. Configure the approved worker hash and trusted signing publisher. Use
   [the configuration example](../config/enclave.structured.example.yaml).
   Its empty pins intentionally prevent use before approval.

Fresh attestation binds the worker to Host's approved policy hash as well as
the signed worker hash. A different policy is rejected before dispatch.
The OpenSSH target endpoint must match Host's configured target. Bastion's
independent policy remains authoritative for the actual key paths.
Password helpers are unavailable in this profile. Root operations require
administrator-approved noninteractive `sudo -n` on the Linux target.

```sh
egw config check
egw doctor --preflight
egw agents stage
```

Run the printed command explicitly in an already open Bastion RDP session.
The signed script runs from the redirected bundle without a local code cache.
Keep its foreground console open. No `ExecutionPolicy Bypass` is generated.
Approval of a signature does not itself override Group Policy.

```sh
egw doctor --probe-targets
egw exec app01 'uname -a'
egw cp ./artifact.bin app01:/tmp/artifact.bin
egw cp app01:/tmp/artifact.bin ./received.bin
egw agents stop
egw clean
```

These commands cannot register startup in this profile:

- `--persist-autostart`
- `--migrate-legacy-state`
- `--execution-policy`

Arbitrary `exec @bastion` is rejected before publication. Direct Bastion file
access is also rejected. TCP mux is unavailable.
Windows TargetNodes and extra SSH jump hops are unsupported. Each transfer is
limited to 64 MiB. Command stdout is limited to 8 MiB. Command stderr is limited
to 1 MiB. The default foreground lease is 900 seconds; the script accepts an
explicit `-LeaseSeconds` between 1 and 3600. Lease expiration interrupts an active
local SSH process and requires reconciliation of its remote effects.

## State and failures

The foreground worker writes protocol files only to the approved redirected
spool. Its durable no-replay ledger is `.structured-transactions`. Its binding is
`worker_structured_storage.json`. It does not adopt or erase a legacy journal.
Protect the Appliance spool and its parents against untrusted writers.

A repeated transaction identifier is rejected, including after restart. Running
or interrupted operations must be reconciled. Disconnect is not remote rollback.
The foreground worker exits on channel failure and does not relaunch itself.
Stopping SSH does not prove termination of a remote background process; this
profile does not make an Enterprise owned-process claim. It is available as a
signed Standard deployment with fresh worker attestation.

Failed or ambiguous file transfers retain their redirected staging file for
investigation. Its name is `structured_<transfer-id>.bin`. Successful transfers
remove their owned stage from the Appliance side. `clean` preserves durable
outcomes and ambiguous evidence. It does not uninstall the worker or erase an
incident's evidence. Stop the foreground process before retiring its bundle.
A synchronous redirected-filesystem call may exceed a script's polling budget;
this profile does not claim a hard OS-level RDPDR cancellation deadline.

## Legacy installations and credential handling

The existing profile remains available as `bastion.execution_profile: legacy`.
Its persistence remains opt-in and emits an endpoint-policy warning. Repeated
Stream recovery is bounded by default:

- `RecoveryTimeoutSec` is 60.
- `MaxRecoveryAttempts` is 5.

A stable worker interval resets the recovery counter. These limits bound retry
logic, not the duration of an individual blocked OS filesystem call.

An offline removal command can be printed without a working worker or config:

```sh
egw agents unregister-autostart-command
```

Review and run that command locally in the original Bastion user's session.
It removes only a recognized `EnclaveGatewayWorker` Run value. Unrecognized
values are preserved for administrator review. It does not terminate processes
or delete files. Preserve incident evidence before any administrator-led removal.

Legacy SSH requests now carry sensitive data separately from interpreter source.
Both interpreter hops must support that channel. A mismatched older worker is
rejected before its SSH process is started. Restage matching approved bytes;
there is no secret-in-script fallback.

RDP credential refresh uses the approved native runtime on **Appliance**, not on
Bastion. JSON data arrives through stdin. The runtime writes Credential Manager
through the Windows API for the managed task's exact SID. Cross-session access
requires SYSTEM and the OS-granted user token. Missing support fails explicitly;
no password-bearing script or `cmdkey /pass` fallback is generated. This new
operation still requires native Windows acceptance before production deployment.

Secret separation prevents automatic insertion into interpreter source. It does
not encrypt the spool or protect against privileged process inspection. Commands
that deliberately include secrets can still expose them in the target's own
logs. Keep endpoint logging enabled and use approved secret-handling facilities.

## Qualification status

The portable fixture executes the actual foreground worker's dispatch logic
with synthetic SSH processes. Only its Windows platform adapters are replaced
in a private test copy. It checks binary transfers and transaction replay denial.

The following acceptance remains separate:

- Microsoft publisher validation on the actual Windows build.
- Administrator-owned policy ACL validation on Windows.
- Real RDP disconnect and reconnect with this new foreground worker.
- Native Windows Credential Manager refresh.
- The exact KES version and corporate protection policy.

A passing portable test is not Windows or KES acceptance. Keep failed runs and
versioned evidence. Do not disable protection or add broad exclusions to obtain
a passing result.

## Platform references

- [Windows Credential Manager writes](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew)
  use the current token's logon session.
- [WTSQueryUserToken requirements](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
  include LocalSystem and the OS-granted privilege.
- [PowerShell execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
  is defense in depth; signature approval does not certify endpoint compatibility.
