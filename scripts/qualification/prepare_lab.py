#!/usr/bin/env python3
"""Prepare disposable Windows lab media without installers, VPN keys or deployment."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.provision.builder import ApplianceProvisioner, ProvisionOptions


def prepare(destination: Path, arch: str):
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError("Lab destination must be empty")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    raw = {"profile": "isolated-lab", "appliance": {"name": "egw-lab", "arch": arch, "hypervisor": "tcg",
        "disk_path": str(destination / "disk.qcow2"), "efi_vars_path": str(destination / "efi_vars.fd"),
        "runtime_dir": str(destination / "runtime"), "rdp_forward_port": 23389, "vm_rdp_forward_port": 23390, "socks5_port": 21080, "vnc_display": 101},
        "provider": {"type": "custom", "binary_path": "", "installer_path": "", "dst_key_path": "", "dst_password_env": "", "adapter_name": "lab-only", "probe_host": "127.0.0.1", "probe_port": 3389},
        "bastion": {"host": "127.0.0.1", "user_env": "LAB_ONLY_USER", "password_env": "LAB_ONLY_PASSWORD"},
        "targets": {"fixture": {"host": "127.0.0.1", "user": "lab", "via": "appliance", "os": "windows"}}}
    config_path = destination / "lab.json"
    config_path.write_text(json.dumps(raw, indent=2) + "\n")
    provisioner = ApplianceProvisioner(EnclaveConfig.from_dict(raw))
    provisioner.prepare_bundle(destination / "seed", ProvisionOptions(arch=arch), create_disk=False)
    report = {"status": "prepared_only", "guest_created": False, "guest_started": False, "vendor_keys": "not_used",
              "requires": ["licensed Windows ISO", "matching VirtIO/QGA media", "disposable Windows VM", "separate RDP session for real RDPdr validation"],
              "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest()}
    (destination / "lab-manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "build/isolated-lab")
    parser.add_argument("--arch", choices=["arm64", "x86_64"], default="x86_64")
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.arch), indent=2))
