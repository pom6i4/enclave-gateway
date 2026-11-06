# Endpoint detection: preserve evidence before retrying

[English](ENDPOINT-INCIDENT.md) · [Русский](ru/ENDPOINT-INCIDENT.md)

Use this procedure when an endpoint product reports or blocks an `egw` process.
A request timeout alone does not identify an antivirus block. A valid signature
does not establish endpoint compatibility. The experimental foreground profile
has a [failed KES acceptance](ENDPOINT-POLICY.md#qualification-status).

## Contain the failed attempt

1. Stop issuing requests through the affected route. Do not repeat the command
   with a new transaction ID to obtain a successful result.
2. Preserve the Host transaction record and the worker's durable journal.
   A `running` record without an acknowledged outcome requires reconciliation.
   Terminating a local process does not prove its remote effects stopped.
3. Follow the administrator's incident procedure. Do not restore a quarantined
   script or add an exclusion as part of routine troubleshooting.
4. Preserve original events before cleaning the spool or retiring the deployment.
   `egw clean` is not an incident evidence exporter.

Keep the approved protection policy in place. Transport timeouts and endpoint
detections can be separate failures. Retain the original acceptance limits.

## Preserve deployed bytes before execution

Before an explicitly disposable acceptance run, record these artifacts:

- Reviewed source revision and SHA-256.
- Exact signed script and SHA-256.
- Public signing certificate and signature-validation result.
- Independently approved policy hash.
- System OpenSSH version and signature-validation result.
- Windows build and process architecture.
- Endpoint product build and installed patches.
- Definition release time and active protection components.
- Approved policy identity and export, when available.
- Manifest binding those artifacts to the attempt identifier.

Copy the exact signed sample to an approved evidence location outside the
disposable endpoint. Verify its digest there before the first request. A
detection can remove the local file. A path or digest alone is insufficient for
later sample analysis.

Do not export a signing private key. A new certificate produces different signed
bytes even for unchanged source. A newly signed copy needs its own identity;
it cannot replace a missing original in an evidence record.

If policy export is unavailable, record that limitation. Do not change password
protection or enable additional telemetry solely to complete the report without
administrator approval.

## Capture exact samples on the Host

Run `scripts/qualification/preserve_endpoint_samples.py` from the source checkout
before executing the signed worker on the disposable endpoint. It copies only
these inputs:

- The exact approved `.ps1` worker.
- The exact approved `.json` worker policy.

Supply both hashes from the independent approval record. Do not compute a new
approval from a suspect file after detection. Create a private parent directory
on the Host outside the disposable VM and outside any public checkout. The
following example assumes that directory already exists and the shell variables
contain the approved hashes:

```sh
python3 scripts/qualification/preserve_endpoint_samples.py capture \
  --worker /private/approved/worker.ps1 \
  --worker-sha256 "$APPROVED_WORKER_SHA256" \
  --policy /private/approved/policy.json \
  --policy-sha256 "$APPROVED_POLICY_SHA256" \
  --output /private/endpoint-evidence/attempt001

python3 scripts/qualification/preserve_endpoint_samples.py verify \
  --bundle /private/endpoint-evidence/attempt001 \
  --worker-sha256 "$APPROVED_WORKER_SHA256" \
  --policy-sha256 "$APPROVED_POLICY_SHA256"
```

The tool preserves bytes without newline conversion. It checks readback before
completing the manifest. It rejects mismatched hashes and nonregular inputs.
It refuses an existing destination. Failed partial captures remain on disk and
cannot pass verification; use a new attempt directory after investigating them.
Each input is limited to 16 MiB. Reverification requires the independent pins,
so editing a copied file and its manifest together does not satisfy approval.

On POSIX hosts, the parent must be owned by the current user without access for
other users. The tool creates the bundle with mode `0700` and its files with
mode `0600`. On Windows, provision the parent with an approved private DACL;
the tool does not validate Windows ACLs. It never modifies source permissions.

This manifest proves only a match to the supplied hashes. The tool does not
verify Authenticode or establish a KES verdict. Preserve signature evidence
separately. It does not collect keys or contact the endpoint. The policy may
contain private configuration, so this bundle must not be published or sent
unreviewed to support.

## Read-only KES collection

This example assumes an administrator-provisioned private `C:\EGWEvidence`
directory. Use a new child directory for each collection. Original reports can
contain environment identifiers and must remain private. These commands do not
start SSH requests or change KES settings.

```powershell
$ErrorActionPreference = 'Stop'
$evidence = 'C:\EGWEvidence\incident001'
if (Test-Path -LiteralPath $evidence) { throw 'Preserve the previous collection' }
New-Item -ItemType Directory -Path $evidence | Out-Null
$products = @(Get-ChildItem -LiteralPath "${env:ProgramFiles(x86)}\Kaspersky Lab" -Directory |
    Where-Object { $_.Name -like 'KES.*' })
if ($products.Count -ne 1) { throw 'Select the exact installed KES version' }
$avp = Join-Path $products[0].FullName 'avp.com'
$cli = Join-Path $products[0].FullName 'kescli.exe'

[DateTime]::UtcNow.ToString('o') | Set-Content (Join-Path $evidence 'collection-utc.txt')
& $avp STATUS | Set-Content (Join-Path $evidence 'protection-status.txt')
if ($LASTEXITCODE -ne 0) { throw 'KES status collection failed' }
& $cli --opswat GetRealTimeProtectionState | Set-Content (Join-Path $evidence 'realtime-state.txt')
if ($LASTEXITCODE -ne 0) { throw 'KES real-time state collection failed' }
& $cli --opswat GetDefinitionState | Set-Content (Join-Path $evidence 'definitions.txt')
if ($LASTEXITCODE -ne 0) { throw 'KES definition state collection failed' }
& $cli --opswat GetThreats | Set-Content (Join-Path $evidence 'threats.txt')
if ($LASTEXITCODE -ne 0) { throw 'KES threat collection failed' }
& wevtutil.exe epl 'Kaspersky Endpoint Security' (Join-Path $evidence 'endpoint.evtx')
if ($LASTEXITCODE -ne 0) { throw 'KES event export failed' }
```

Check these commands against the installed product's help. Preserve collection
failures too. A status snapshot does not substitute for a policy export. An empty
threat list alone does not qualify a deployment: correlate event history with
the failed transaction and its exact sample hash.

## Prepare a reviewed support packet

Separate observations from hypotheses:

- Report the detection name and recorded response action.
- Match the event's sample hash to the pre-execution manifest.
- Correlate event timestamps with transaction timestamps.
- Identify the operation in progress without claiming an undocumented detection
  rule or a specific blocked API call.
- Identify missing evidence explicitly.
- Separate reconnecting an existing RDP session from a full profile logon.
- State which acceptance cases did not run after detection.

Retain the original event log locally. Prepare a separate reviewed export for
support, excluding credentials and customer configuration. Do not upload an
entire spool: even an unexecuted request can contain a sensitive command.
Submitting a report does not establish a vendor false-positive determination.

[Kaspersky's investigation instructions](https://support.kaspersky.com/common/error/other/15332)
describe additional evidence for a PDM report. Mark a system-information report
or reproduction trace as missing if it was not collected. Obtain approval before
collecting or sharing additional machine data. The recorded trial had KSN
disabled; it does not establish behavior with KSN enabled.

## Resume an approved route

An [agentless SSH route](ROUTING.md#approved-ssh-route) is available when policy
permits it. Select it explicitly and qualify the executing controller under its
own endpoint policy. Removing a Bastion worker does not certify PowerShell or
OpenSSH on a Windows controller against KES.

For RDP-only deployment, keep the failed acceptance open pending administrator
review. Repeat the failed case under the approved policy with exact samples
preserved. Keep the original limits and failed evidence. Run the remaining
cases after that prerequisite succeeds. There is no automatic route fallback.
