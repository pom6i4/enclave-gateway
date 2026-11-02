# Extended isolated runtime acceptance

The extended profile runs current Windows ARM64/x64 source suites, cross-account
isolation, real QGA/worker/storage faults, actual RDP redirected-drive interruption
and reconnect, a two-hour 160-stream soak and generated security cases.
It uses only explicitly provisioned disposable fixtures and lab credentials.
No provider/client environment, production keys or hosted workflows are needed.

```sh
python scripts/qualification/extended_acceptance.py \
  --manifest /path/to/private/extended.json --output build/acceptance/extended-001
```

The full installation entry also accepts `--extended-manifest <private-plan>`.
That runs this profile after blank-disk installation/PKI and before final hygiene.
Standalone extended acceptance does not claim a new Windows installation.
The complete source inventory must stay unchanged until cleanup finishes.

## Manifest contract

Start from [the manifest example](../examples/extended-acceptance.json). Its
placeholder controller and zero digest deliberately cannot pass. Replace them
with the approved fixture controller, actual input hashes and current test count.

Use `revision: 1`, `scope: isolated-extended-acceptance`, an exact current
`expected_source_tests` count, nonempty `inputs_sha256`, `steps` and `cleanup`.
Inputs pin the trusted controller scripts, fixture configurations and other
selected lab inputs. Do not put credentials or a filled manifest in Git.
The manifest is trusted operator code, not a sandbox for untrusted commands.

Each command has `role`, an argument-array `argv` and a bounded `timeout_sec`
(1–14400 seconds). `{repo}`, `{python}`, `{run_dir}` expand to this source checkout,
the invoking interpreter and the new output directory. Shell expansion is not used.
All ten distinct roles below are mandatory:

| Role | Required evidence |
| --- | --- |
| `windows-arm64-source`, `windows-x64-source` | `source_suite.py`, exact current test count, matching architecture and source inventory, explicit skipped test IDs/reasons |
| `windows-accounts` | Two actual SID backends, cross-account/environment ACL denial, wrong-SID rejection and scoped sync |
| `posix-accounts` | Real two-UID router/SSH/environment/ACL/sync cases |
| `qga-faults` | Actual agent restart and lost dispatch acknowledgement, no effect replay |
| `worker-faults` | Actual worker kill, trust-host termination and corrupted replies/stdout |
| `storage-faults` | Real ENOSPC plus journal corruption and no replay |
| `rdp-transfer-disconnect` | Before/after reports, actual partial block consumption, new worker after reconnect and rejected replay |
| `long-soak` | 7200 seconds, 128 fast plus 32 slow streams, original memory/thread/handle bounds, empty final queues |
| `generated-security` | Three seeds, 200 cases per seed/model for all six security models |

Each step writes `<run_dir>/<role>/receipt/result.json` using `case_receipt.py`.
That wrapper actually executes a child command, rejects preexisting output/reports,
captures stdout/stderr, requires exit zero and passing child reports, copies and
hashes those reports, and verifies source hashes before/after execution:

```sh
python scripts/qualification/case_receipt.py \
  --role generated-security --output <receipt-directory> \
  --report <new-case-directory>/result.json --timeout-sec 180 \
  -- python scripts/qualification/generated_security.py --output <new-case-directory>
```

For guest execution, stage the exact source inventory and approved artifacts into
a new private namespace, verify every staged hash, run the wrapper inside that
checkout, then retrieve its receipt and nested reports. The Host requires the
receipt's complete source map to equal the current source. Guest Python and
optional tool identities/skips are recorded by `source_suite.py`. Transfers and
guest execution use bounded staging/observer budgets, without replaying uncertain
mutating dispatches.

The source-suite report also records the PowerShell parser and crash-checkpoint
observer budgets. Defaults remain 30 seconds. Slow TCG fixtures may explicitly
set `EGW_TEST_POWERSHELL_TIMEOUT_SEC` and `EGW_TEST_CRASH_OBSERVER_SEC` within
30–240 seconds. These bound test-fixture parsing/checkpoint observation; they do
not extend product execution, cold-security or native trust-challenge deadlines.
A longer observer is functional emulation evidence, not acceptance of the
default observation time. Original default-timeout failures remain retained.

Cleanup commands always run, including after a failed/timed-out step. Each writes
`<run_dir>/<cleanup-role>/receipt/result.json` with `status: passed` and
`cleanup: passed` only after checking its owned resources. Controllers must verify
actual VM identity/disk and PID ownership before stopping anything. A cleanup
failure, source/input drift, missing role or altered nested report fails the whole
profile. Existing outputs and failed evidence are retained. The root inventory
binds nested results and logs without a root hash cycle.

## Additional generated coverage

`generated_security.py` exercises path containment/Windows path ambiguity,
IPv4/IPv6 destination grants, malformed/denied/concurrent MCP requests, actual
loopback HTTP authentication/header/framing rejection and recovery, fragmented
SOCKS4/5/HTTP CONNECT, and mux drain/half-close/close behavior. Inputs are seeded;
protocol failures retain their actual serialized request or wire bytes. The mux
sequence reducer replays candidate reductions before retaining a minimized cause.
These are finite models and samples, not exhaustive protocol proofs.

Managed software TPM on a native Windows QEMU Host remains a separate backend
capability. Do not remove the existing fail-closed check based on the success of
a Windows *guest* with a POSIX-hosted software TPM. Hardware trust and production
provider/signing acceptance remain outside this profile.
