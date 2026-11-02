# Contributing

Start with [GUIDE.md](docs/GUIDE.md) for the product and
[SECURITY.md](docs/SECURITY.md) for the trust model.

## Code layout

| Area | Responsibility |
| --- | --- |
| `config.py`, `onboarding.py`, `diagnostics.py` | Typed configuration, named modes, offline setup and deployment guidance |
| `engine.py`, `cli.py` | Routing/orchestration and user entry points |
| `control/`, `hypervisor/` | QGA/QMP, owned VM state and control channels |
| `agents/`, `native/` | PowerShell workers and signed Windows primitives |
| `transports/` | RDP VFS, SSH, mux and local forwarding |
| `operations/`, `security/`, `audit/` | Transactions, authorization, isolation and evidence |
| `tests/` | Behavioral regression contracts |
| `scripts/qualification/`, `contrib/qualification/` | Maintainer lab runners and safe plan templates |

Add configuration through typed fields and validate it before effects. Named
Enterprise requirements must fail closed. Keep Standard's limitations visible;
never make native isolation or signature failure silently fall back to a weaker
execution path. Preserve existing Custom configuration semantics during migration.

Tests should assert behavior: source binding, rejected invalid input, failed
execution, no replay, actual isolation and bounded cleanup. They must not require
a dated report, a specific test count from an old run, a developer's installed
VM or a private environment. Optional native/PowerShell fixtures must explain
skips. Document changes in evergreen guides, not a new dated narrative per edit.

## Validate

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/verify_hygiene.py
git diff --check
```

For real PowerShell, set `EGW_TEST_POWERSHELL` to an approved executable; native
runtime and Windows lab tests have separate prerequisites in the maintainer guide.
Run checks that exercise the actual changed boundary; mock results do not certify
remote installs or a production signing chain. Preserve failed evidence and state
exact skips/observer budgets. Do not loosen a gate to turn a failure into a pass.

Use neutral example addresses and names. Keep credentials, private keys, filled
lab manifests, proprietary installers and VM disks out of Git. Use the repository
hooks and configured author identity. Avoid unrelated formatting or infrastructure
changes in a product contribution.
