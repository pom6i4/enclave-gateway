# Endpoint policy and the foreground OpenSSH profile

This describes the experimental foreground profile in `0.3.0b5` (Beta 5).
It does not change the published `v0.2.0` tag or certify antivirus compatibility. Deployment on a
managed endpoint requires its administrator's approval. An active security
incident must be resolved through the organization's incident process first.

## Choose an approved route

Both policy scenarios are supported through [explicit route selection](ROUTING.md).
For an agentless SSH starter use `egw config init --route ssh`.

Use an existing approved SSH or WinRM route when it removes the need for a
Bastion worker. A redirected RDP filesystem alone cannot execute commands.
When RDP is the only route, `bastion.execution_profile: structured_only` selects
an explicit foreground worker with fixed operations.

The foreground worker does not perform these actions:

- Register startup through the Windows registry.
- Register scheduled tasks.
- Install scripts or executables automatically.
- Evaluate PowerShell supplied in a request.
- Create runspace pools.
- Open raw TCP sockets.
- Launch a custom executable on Bastion.
- Disable command history or endpoint logging.
- Change execution policy or filesystem ACLs.

The default `spawn` backend launches Microsoft-signed `ssh.exe` from the system OpenSSH directory.
It ignores per-user SSH configuration through `-F NUL` and prohibits local
commands. It uses approved keys with strict host-key checking. File copies use
that same SSH process with binary stdin/stdout and remote Linux utilities.
The policy cannot supply an executable or arbitrary OpenSSH options.

The `spawn` backend uses Files. The opt-in `operator` backend uses Stream.
There is no fallback between them. The legacy Stream performance baseline does
not apply to either backend.

## Operator OpenSSH backend

Use this mode when the endpoint owner approves system OpenSSH in a foreground
operator session but does not allow the worker to start it. It requires one
Linux TargetNode. Install Python 3.10 or newer on that target and deploy the
reviewed [Linux protocol peer](../src/enclave_gateway/agents/operator_target.py)
at a root-managed path. Restrict a dedicated SSH key to that command (for
example, an `authorized_keys` entry with
`restrict,command="/usr/bin/python3 /usr/local/lib/egw-operator-target.py"`).
The dedicated SSH session enables OpenSSH compression and disables forwarding.
The default peer invocation is the literal SSH command `egw-operator-v1`.
The dedicated key grants the Linux account's privileges, including its shell
permissions. Apply the target's own account and sudo policy accordingly.

Set these options in the Standard [starter configuration](../config/enclave.structured.example.yaml):

```yaml
bastion:
  execution_profile: structured_only
  structured_backend: operator
  spool_protocol: stream
  lease_seconds: 28800
```

Add `operator_state_dir` to the independently approved Windows worker policy.
Provision that directory on local NTFS with write access limited to the worker
SID and trusted administrators. Use a dedicated spool and state directory;
reconcile outstanding transactions before changing either directory or its
policy pin. The operator may provision the pinned policy in a private local
profile directory. Its `owner_sid` must match the running account in both
deployment modes. Only SYSTEM, Administrators and that SID may have write or
ownership-changing permissions on the policy. The process holds both files
against writes and attestation checks the current adapter digest.

- With corporate signing, set `security.require_signed_agents: true` and pin
  the approved publisher and signed script bytes. The worker verifies its
  signature at startup and on each attestation.
- If endpoint policy permits an unsigned adapter, set
  `security.require_signed_agents: false` and pin the adapter SHA-256, policy
  SHA-256 and `security.worker_account` (Windows SID). Keep
  `security.enforce_worker_attestation: true`. No custom signing certificate
  is required. Microsoft system OpenSSH still requires a valid Microsoft
  signature. This mode trusts the operator and the protected control channel.

Run `egw agents stage` on Host. For initial provisioning, `egw agents stage
--policy-source ./worker-policy.json` can include an independently approved,
hash-pinned policy in the private spool bundle. Its `bastion_copy_command`
installs the policy only if the local file is missing, checks the operator
SID and restricts its Windows ACL. An existing policy must match the pin.
Install the staged `operator_target.py` on the
Linux target and use `target_authorized_keys_prefix` with the real helper path
and dedicated public key. In PowerShell on Bastion, run `bastion_copy_command`
to verify the policy and stage the exact adapter and Linux peer beside it. Then run
`start_command` in that RDP session. For an approved unsigned deployment,
`egw agents stage --execution-policy RemoteSigned`,
`egw agents command --execution-policy RemoteSigned` and
`egw heal --execution-policy RemoteSigned` request RemoteSigned for the current
PowerShell process. Group Policy keeps precedence. In another CMD
console in the same RDP session, run the quoted path to `attach-ssh.cmd` printed
by the adapter. Each start regenerates this file in the operator's private local
state directory for that instance. If the path contains CMD expansion characters,
the adapter prints the OpenSSH command directly. The command starts system
OpenSSH with the fixed target, key and known-hosts file from the
approved policy. The adapter exchanges framed data over two local named pipes
that allow the worker SID and deny network access. It does not launch the SSH
client, run PowerShell from requests, start on logon, or open a TCP proxy.
Host-key checks remain enabled. No SSH password is accepted.
The adapter gives CMD attachment and the authenticated Linux greeting one
shared 90-second startup window, bounded by the remaining worker lease.

When the worker is ready, use the regular CLI:

```sh
egw agent-verify --wait-ready 25
egw exec app01 'uname -s' --timeout 15
egw cp ./artifact.bin app01:/tmp/artifact.bin --timeout 15
egw cp app01:/tmp/artifact.bin ./received.bin --timeout 15
egw agents stop --timeout 15
```

For the `operator` backend, `egw agents stage` and `egw clean` can reclaim
zeroed Stream IPC files on the Appliance after verifying the stopped worker and
its spool binding. They preserve files with data, indeterminate transactions and
the durable journal. An active worker or a failed identity check prevents pruning.

Target exec and ordinary copy default to a 15-second operation cap, including
fresh attestation (at most 10 seconds), staging, remote work and response
delivery. The optional startup wait in `agent-verify` ends before its fresh
attestation begins. For an approved deployment that needs long commands, set
`bastion.operator_exec_max_sec` to a value above 15 and at most 300 seconds
within the worker lease. Install the matching Linux helper, pin the new
adapter hash and restart with the generated commands. The adapter uses
`egw-operator-v2` for that session and advertises its cap in fresh attestation.
The CLI's `--timeout` still bounds the entire request, with time reserved for
the reply. A fully received command timeout leaves the session available for
the next request and records the previous outcome as `indeterminate`.
Reconcile its external effects before retrying.
When attestation advertises `stream_upload_v1`, uploads up to 1 MiB travel
in the existing request stream. An adapter advertising `stream_upload_deflate_v1`
also accepts Deflate when it saves at least one aligned block. The original
size remains capped at 1 MiB. For large raw attachments, the adapter overlaps
redirected reads with SSH writes and withholds the final byte until SHA-256
matches. The Linux peer requires the complete payload before running the
command. The target verifies the staged file before replacing the destination. These bytes count toward the session's stream
capacity. Larger uploads and older workers use a separate staged file.
For copy troubleshooting, the local Bastion journal distinguishes reads
from the request stream or staged file and the exchange over OpenSSH.
Preserve the failed transaction and compare these phases before retrying.
A failure after dispatch can leave the outcome indeterminate; check the
transaction before retrying a command or upload. If the OpenSSH connection
ends, including while idle, the adapter stops advertising readiness and exits.
Start the adapter and OpenSSH again from the approved RDP account. Stop and
restart when the bounded stream fills. Generic Bastion shell access,
interactive SSH, mux and multi-hop SSH remain unavailable in this mode.

## Administrator preparation

These steps apply to the signed `spawn` backend.

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
8. Before a disposable endpoint trial, [preserve the exact signed sample and
   policy on the Host](ENDPOINT-INCIDENT.md#capture-exact-samples-on-the-host).
   Reverify that copy before retiring the VM. A digest alone cannot replace a
   sample removed by endpoint protection.

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

Spawn rejects these options:

- `--persist-autostart`
- `--migrate-legacy-state`
- `--execution-policy`

Arbitrary `exec @bastion` is rejected before publication. Direct Bastion file
access is also rejected. TCP mux is unavailable.
Windows TargetNodes and extra SSH jump hops are unsupported. Ordinary copies
are limited to 64 MiB. Command stdout is limited to 8 MiB. Command stderr is limited
to 1 MiB. The foreground lease defaults to 28,800 seconds (eight hours).
`bastion.lease_seconds` accepts 60–86,400 seconds. Lease expiry interrupts active
operations. Reconcile their remote effects before retrying.

On the managed Windows Appliance, `egw heal` applies `appliance.mtu` (1200
bytes by default) to configured IPv4 adapters and disables RDP over UDP.
`egw doctor` compares the configured MTU with the values it reads from the
VPN and Ethernet adapter names. With nested VPNs, verify the actual route.
For a manual IPv4 DF ping, use an ICMP payload 28 bytes below the desired IP
MTU (1172 bytes for MTU 1200).

### Larger files with the operator backend

Use `--chunked` for files up to 512 MiB when `egw agent-verify` reports
`chunked_copy_slots_v1: true` for the approved adapter. The matching
operator worker also reports the related protocol capabilities.

- `chunked_copy_v1: true`
- `stream_upload_v1: true`
- `stream_upload_deflate_v1: true`

The TargetNode
policy must allow file transfers. The Linux endpoint uses `sha256sum` and
`python3` in addition to its usual shell and core utilities.

```sh
egw cp --chunked --timeout 900 ./artifact.bin app01:/tmp/artifact.bin
egw cp --chunked --timeout 900 app01:/tmp/artifact.bin ./received.bin
```

The CLI transfers 1 MiB blocks one at a time. The request stream carries only
control messages. A single upload slot per worker instance holds the block
data. The worker opens four slot readers at startup and pipelines reads into
OpenSSH. It sends the last byte only after verifying the block SHA-256. A valid receipt lets
the CLI erase and reuse the slot. A lost receipt or interrupted slot cleanup
can leave the slot occupied. Reconcile the transaction and start a new worker
before uploading again. The Host consumes the hashed metadata and download bytes through a single read
handle on the pre-opened response slot (`ipc_res_<instance>_<slot>.bin`). It
verifies the bytes before erasing the response.
The 15-second per-request limit and 10-second attestation limit still apply. For
`--chunked`, `--timeout` budgets the whole copy. The foreground lease must
also cover the copy. The extended command budget applies only to `exec`.

The receiver publishes the destination atomically after verifying the whole
file's SHA-256. A failed upload can leave a private directory named
`<destination>.egw-<transfer-id>.parts` on the TargetNode. Preserve it while
checking the transaction and destination. If the final acknowledgement was
lost, verify the destination hash before retrying.

## State and failures

The foreground worker writes protocol files only to the approved redirected
spool. Its durable no-replay ledger is `.structured-transactions`: it lives
in the spool for `spawn` and in the approved local state directory for `operator`. Its binding is
`worker_structured_storage.json`. It does not adopt or erase a legacy journal.
Protect the Appliance spool and its parents against untrusted writers.

The durable ledger rejects repeated transaction identifiers, including after
restart. Attestation and ping use reserved probe identifiers and require no
durable ledger writes. Attestation verifies the current file hash and, in
signed mode, the signature. It returns the Host's challenge. Probe identifiers cannot execute
SSH or change worker state. The worker atomically publishes its running and
stopped states. Between transitions it refreshes the state file's modification
time, which the Host uses only as a liveness hint. Use matching Host and worker
versions for this heartbeat protocol. When the worker advertises support and
the Host polls the spool directly, read-only probes create a unique reply
without renaming it. The Host waits for a complete response within the
request deadline. Running or interrupted operations must be reconciled.
Disconnect is not remote rollback.
The foreground worker exits on channel failure and does not relaunch itself.
Stopping SSH does not prove termination of a remote background process; this
profile uses Standard trust with fresh worker attestation.

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
operation has passed a current-SID test in a disposable Windows ARM64 VM.
SYSTEM selection of a different ordinary interactive task SID has also passed
there with the native ARM64 helper. The end-to-end refresh took 13,651 ms under
the unchanged 15-second cap. The selected user then used that exact test
credential for the isolated RDP connection. This does not qualify Windows x64.

Secret separation prevents automatic insertion into interpreter source. It does
not encrypt the spool or protect against privileged process inspection. Commands
that deliberately include secrets can still expose them in the target's own
logs. Keep endpoint logging enabled and use approved secret-handling facilities.

## Qualification status

The portable fixture executes the actual foreground worker's dispatch logic
with synthetic SSH processes. Only its Windows platform adapters are replaced
in a private test copy. It checks binary transfers and transaction replay denial.

The reusable [Windows local-spool fixture](../scripts/qualification/endpoint_windows.ps1)
requires an explicitly disposable VM. It creates a one-day synthetic signing
certificate and removes its exact trust entries and nonexportable private key
on completion. It verifies that the owned CNG key no longer exists. Each attempt
requires a fresh evidence directory; failed attempts are retained. Run the
fixture from an approved administrator context. Sign the fixture itself through
the lab's approved procedure before invoking it under `AllSigned`. It never
changes execution policy. Do not run it on a production endpoint: provisioning
synthetic trust is deliberately limited to this disposable platform fixture.
The KES acceptance run must use separately approved deployment trust.

```powershell
.\endpoint_windows.ps1 -Worker C:\EGWLab\bastion_structured.ps1 -Workspace C:\EGWLab\attempt001 -Runtime C:\EGWLab\egw-runtime.exe -DisposableLab
```

The fixture has passed on Windows ARM64 and native Windows x64 with Windows PowerShell 5.1 under
`AllSigned`. It checks these boundaries:

- Valid signed foreground startup using the actual system OpenSSH signature.
- Unsigned worker rejection.
- Pinned policy hash rejection.
- User-writable policy rejection with the expected causal error.
- Fresh attestation binding the policy hash.
- Fixed ping and clean operations.
- Arbitrary PowerShell rejection.
- TCP mux rejection.
- Unapproved target rejection.
- Acknowledged stop with exit code zero.
- Native Credential Manager write for the exact current SID.
- Wrong-SID rejection without changing the owned test credential.

The ARM64 Windows local-spool test runs as SYSTEM. PowerShell runs under
x64 emulation on ARM64; this is not native Windows x64 qualification. The
Credential Manager helper is a native ARM64 build. Its test credential uses a
random fixture-only name and is removed afterward. Portable interpreter tests
add command execution and binary transfer coverage; their SSH process is
synthetic. Native Direct SSH is tested separately with a real SSH jump and TTY.

A separate Windows Server 2022 Datacenter x64 VM exercised the exact
`v0.3.0-beta.1` foreground worker bytes in a local spool. Both Windows and
PowerShell ran natively as x64 in an interactive administrator session. Its
signed startup took 1,077 ms on the first run; the current-SID credential check,
including wrong-SID denial, took 760 ms. The fixture's existing 15-second limits
were unchanged. A repeat also verified private-key deletion and unchanged
trust stores around the signing fixture.

The exact published `0.3.0b1` wheel also passed a clean offline installation on
Python 3.14.5 on that VM. Fresh self-contained x64 helpers passed filesystem
containment and descendant cancellation checks without an SDK, at timing scale
1 and the existing 15-second signature cap. Temporary artifact-signing trust
was removed with the original stores preserved. Microsoft Defender real-time
protection remained enabled; no detections referencing the owned test directory
were reported. This is local Windows qualification, not a KES policy evaluation
or an additional end-to-end x64 RDP transport qualification.

An additional pair of isolated Windows ARM64 VMs exercised the signed foreground
worker in an ordinary user's actual native `mstsc.exe` session. NLA remained
enabled and the server certificate was validated. This run checked:

- Fresh worker and policy attestation.
- Execution through system OpenSSH to a real isolated Linux SSH server.
- Unicode output with a nonzero remote exit status.
- A binary 1 MiB file in both directions with matching SHA-256.
- Rejection of a changed SSH host key before remote command execution.
- Actual RDP disconnect/reconnect with events 24 and 25 for the same session.
- Explicit manual foreground restart with a new worker instance.
- Reconciliation of an interrupted request without repeating its side effect.
- Durable rejection of completed and interrupted transaction IDs after restart.
- Successful cleanup with a running worker and after acknowledged stop.

The disconnected Host request timed out and remains failed evidence. A request
made before the new heartbeat was ready failed preflight without publication;
the subsequent readiness-qualified checks passed. No automatic foreground
recovery or remote rollback is claimed. The test used synthetic trust and keys.
It did not include a proprietary VPN or additional WAN delay. Its Files timings
are not the legacy Stream performance baseline.

A disposable Windows Server 2022 x64 test with KES 14.1.0.423 did **not** pass.
The trial license was active and the definitions were updated. These components
reported running:

- AMSI Protection.
- Behavior Detection.
- File Threat Protection.

KSN was disabled. No product exclusions were added and protection was not
disabled. The signed foreground worker passed local NTFS startup and fresh
attestation, but its first real Linux SSH request exceeded the unchanged
15-second limit. KESCLI reported `PDM:Trojan.Win32.Generic` for that worker
with action `Blocked`. A separate lab PowerShell scenario invoking system SSH
was also reported as blocked. The test stopped and retained the failed evidence.
Signing and the reduced operation set therefore do not establish KES
compatibility.

The actual redirected RDP Files trial separately exceeded the same limit during
attestation and cancelled before dispatch. Reconnecting reached the existing
desktop and the foreground worker exited on the disconnected drive; this is
not successful end-to-end acceptance. Deployment requires administrator review of the detection and an approved route.

### Operator backend under KES 14.1

On an isolated Windows Server 2022 x64 Bastion with KES 14.1.0.423 active,
the `operator` backend passed two series of 12 uploads of 1 MiB each through
real RDP drive redirection to an isolated Linux OpenSSH target. Each series
started a new worker and included six incompressible files. All 24 uploads
finished in 5.07–11.49 seconds within the 15-second limit, and every target
SHA-256 matched. For the incompressible files, the reply after the final byte
took 0.23–0.97 seconds. Both series also passed attestation, command execution,
byte-identical download and acknowledged stop.

AMSI, Behavior Detection and File Threat Protection remained active. The
before and after KES snapshots contained the same event record IDs. No
exclusions were added. KSN was off in the lab. This run used Direct control
mapped to an RDP drive, with disposable signing trust. It qualifies this
specific laboratory route and policy. Appliance/QGA and customer policy
acceptance are separate. Earlier failed samples were retained.

A subsequent chunked-copy run used an isolated Windows Server 2022 Standard
x64 Bastion with the same KES build and active protection components. Each copy
used the real RDP redirected drive and a disposable Linux OpenSSH target.

| Direction | File size | Wall time | Slowest 1 MiB block |
| --- | ---: | ---: | ---: |
| Upload | 3 MiB | 6.751 s | 2.320 s |
| Download | 3 MiB | 4.768 s | 1.709 s |
| Upload | 65 MiB | 117.987 s | 2.692 s |
| Download | 65 MiB | 53.863 s | 1.710 s |

- All 136 data blocks and the auxiliary requests met the 15 s limit. The
  attestation took 0.344 s against a 10 s budget.
- Every file's SHA-256 matched. The KES event log stayed at 10 records before and
  after the run, with zero new events and zero added exclusions.
- The lab covered the Direct-control RDP path. Customer VPN, QGA and other
  corporate KES policies require separate acceptance.

A separate portable PowerShell and Linux fixture transferred 512 MiB in
36.022 s upload and 46.780 s download over local pipes. Its request file measured
5,312,512 bytes (about 5.1 MiB) after the round trip and other fixture operations.

Beta 5 repeated the 3 MiB and 65 MiB transfers in both directions under the
same KES version with a non-administrator local Windows account and a pinned,
unsigned adapter. The adapter was attached using the new local CMD file.
All 136 blocks and auxiliary requests met the 15-second limit, with a maximum
of 3.62 s. SHA-256 matched on each transfer and KES logged no new events.
Fresh attestation was within 10 seconds. A command with an explicitly extended
budget completed, and a separate deliberate timeout returned an indeterminate
outcome while the same SSH session remained available for the next command.
The controller used Direct control with actual RDP drive redirection on an
isolated Windows Server 2022 x64 guest.

### Beta 5 Appliance/QGA acceptance

A separate run at the published Beta 5 tag used macOS, QEMU Guest Agent on a
Windows 11 ARM64 Appliance, and the Appliance's `mstsc.exe` with NLA, server
certificate verification and RDP drive redirection. The Windows Server 2022 x64
Bastion ran the pinned unsigned adapter under a local non-administrator account
and attached system OpenSSH to an isolated Linux target.

| Direction | File size | Wall time | Slowest 1 MiB block |
| --- | ---: | ---: | ---: |
| Upload | 3 MiB | 9.701 s | 2.550 s |
| Download | 3 MiB | 7.149 s | 2.229 s |
| Upload | 65 MiB | 165.940 s | 3.108 s |
| Download | 65 MiB | 156.076 s | 3.554 s |

- All 136 blocks and auxiliary requests stayed within 15 seconds. Fresh
  attestation took 3.513 seconds against a 10-second limit. SHA-256 matched for
  all transfers.
- Staging and `egw exec @appliance` succeeded over QGA. An explicitly extended
  Linux command completed. A deliberate timeout returned `indeterminate`, and
  the next command succeeded on the same worker instance.
- `egw agents stop` received an acknowledgement. Two bounded `egw clean` calls
  removed 154 zero-filled IPC files and retained two IPC files.
- KES 14.1.0.423 logged no new events with AMSI, Behavior Detection and File
  Threat Protection active. No exclusions were added. Customer VPN and the
  deployment's domain and endpoint policies still require their own acceptance.

A passing local-spool test is not RDP or KES acceptance. Keep failed runs and
versioned evidence. Do not disable protection or add broad exclusions to obtain
a passing result. KES acceptance requires a legally available installer with a
valid lab license. Record its build and approved policy. Preserve relevant
endpoint events around each test. An alert or a hung RDP session fails the run
and must be handled through the administrator's incident process.

Use [the endpoint incident procedure](ENDPOINT-INCIDENT.md) to preserve exact
samples before execution and prepare a reviewed support packet after detection.

## Platform references

- [Windows Credential Manager writes](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew)
  use the current token's logon session.
- [WTSQueryUserToken requirements](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
  include LocalSystem and the OS-granted privilege.
- [PowerShell execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
  is defense in depth; signature approval does not certify endpoint compatibility.
