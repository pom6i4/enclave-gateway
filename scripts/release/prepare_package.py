#!/usr/bin/env python3
"""Allow-listed runtime package; unsigned artifacts never claim acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS = ("bastion_worker.ps1", "bastion_bootstrap.ps1", "appliance_init.ps1", "session_supervisor.ps1")


def prepare(output: Path, helper: Path):
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Release destination must be empty")
    if not helper.is_file() or helper.suffix.lower() != ".exe":
        raise ValueError("An explicitly built Windows credential helper is required")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    for name in AGENTS:
        shutil.copyfile(ROOT / "src/enclave_gateway/agents" / name, output / name)
    shutil.copyfile(helper, output / "egw-askpass.exe")
    for name in ("verify_windows.ps1", "install_windows.ps1"):
        shutil.copyfile(ROOT / "scripts/release" / name, output / name)
    manifest = {"status": "unsigned", "qualified_windows": False,
                "files": [{"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(output.iterdir())]}
    (output / "unsigned-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--helper", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.helper), indent=2))
