"""Hypervisor driver for QEMU (macOS HVF, Linux KVM, Windows WHPX) and qcow2 snapshots."""

from __future__ import annotations

import os
import platform
import shutil
import signal
import subprocess
import time
from pathlib import Path

from enclave_gateway.config import ApplianceSpec
from enclave_gateway.control.qmp_client import QmpClient


def detect_host_accelerator(preference: str = "auto") -> str:
    if preference and preference != "auto":
        return preference
    sys_name = platform.system()
    if sys_name == "Darwin":
        return "hvf"
    if sys_name == "Linux":
        return "kvm" if Path("/dev/kvm").exists() else "tcg"
    if sys_name == "Windows":
        return "whpx"
    return "tcg"


def detect_host_arch(preference: str = "auto") -> str:
    if preference and preference != "auto":
        return preference
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return "x86_64"


def resolve_qemu_binary(arch: str) -> str:
    """Locate QEMU system binary across macOS, Linux, and Windows installations."""
    binary_name = "qemu-system-aarch64" if arch == "arm64" else "qemu-system-x86_64"
    found = shutil.which(binary_name)
    if found:
        return found
    candidates = [
        f"/opt/homebrew/bin/{binary_name}",
        f"/usr/local/bin/{binary_name}",
        f"/usr/bin/{binary_name}",
        rf"C:\Program Files\qemu\{binary_name}.exe",
    ]
    for cand in candidates:
        if Path(cand).is_file():
            return cand
    return f"/opt/homebrew/bin/{binary_name}"


def resolve_efi_code_path(arch: str, configured_path: str = "") -> str:
    """Resolve UEFI firmware image across macOS (edk2), Linux (AAVMF/OVMF), and Windows."""
    if configured_path:
        expanded = Path(os.path.expanduser(configured_path))
        if expanded.is_file():
            return str(expanded)

    if arch == "arm64":
        candidates = [
            "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
            "/usr/local/share/qemu/edk2-aarch64-code.fd",
            "/usr/share/AAVMF/AAVMF_CODE.fd",
            "/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd",
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
            "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw",
            "/usr/share/edk2/aarch64/QEMU_EFI.fd",
            "/usr/share/qemu/edk2-aarch64-code.fd",
            r"C:\Program Files\qemu\share\edk2-aarch64-code.fd",
        ]
    else:
        candidates = [
            "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
            "/usr/local/share/qemu/edk2-x86_64-code.fd",
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/usr/share/qemu/OVMF.fd",
            "/usr/share/qemu/edk2-x86_64-code.fd",
            r"C:\Program Files\qemu\share\edk2-x86_64-code.fd",
        ]

    for cand in candidates:
        if Path(cand).is_file():
            return cand
    return configured_path or candidates[0]


class ApplianceHypervisor:
    """Manages the cryptographic appliance VM lifecycle and copy-on-write snapshots."""

    def __init__(self, spec: ApplianceSpec) -> None:
        self.spec = spec
        self.qmp = QmpClient(spec.qmp_socket)

    def is_running(self) -> tuple[bool, int | None]:
        if not self.spec.pid_file.is_file():
            return False, None
        try:
            pid = int(self.spec.pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
            return True, pid
        except (ValueError, OSError):
            return False, None

    def build_qemu_command(self) -> list[str]:
        accel = detect_host_accelerator(self.spec.hypervisor)
        arch = detect_host_arch(self.spec.arch)

        qemu_bin = resolve_qemu_binary(arch)
        efi_code = resolve_efi_code_path(arch, self.spec.efi_code_path)

        hostfwd_rules = [
            f"hostfwd=tcp:127.0.0.1:{self.spec.rdp_forward_port}-:33890",
            f"hostfwd=tcp:127.0.0.1:{self.spec.vm_rdp_forward_port}-:3389",
            f"hostfwd=tcp:127.0.0.1:{self.spec.socks5_port}-:1080",
        ]
        netdev_arg = "user,id=net0," + ",".join(hostfwd_rules)

        cmd: list[str] = [
            qemu_bin,
            "-name",
            self.spec.name,
            "-accel",
            accel,
            "-cpu",
            "host" if accel in ("hvf", "kvm") else "max",
            "-smp",
            str(self.spec.cpus),
            "-m",
            f"{self.spec.memory_mb}M",
        ]

        if arch == "arm64":
            cmd.extend(
                [
                    "-M",
                    "virt,highmem=on",
                    "-drive",
                    f"if=pflash,format=raw,readonly=on,file={efi_code}",
                    "-drive",
                    f"if=pflash,format=raw,file={self.spec.resolved_efi_vars_path}",
                    "-device",
                    "ramfb",
                ]
            )
        else:
            cmd.extend(["-M", "q35"])

        cmd.extend(
            [
                "-device",
                "qemu-xhci,id=xhci",
                "-device",
                "usb-kbd",
                "-device",
                "usb-tablet",
                "-drive",
                f"file={self.spec.resolved_disk_path},format=qcow2,if=none,id=drive0,cache=writeback",
                "-device",
                "nvme,drive=drive0,serial=drive0,bootindex=1",
                "-netdev",
                netdev_arg,
                "-device",
                "virtio-net-pci,netdev=net0",
                "-device",
                "virtio-serial-pci",
                "-chardev",
                f"socket,path={self.spec.qga_socket},server=on,wait=off,id=qga0",
                "-device",
                "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
                "-qmp",
                f"unix:{self.spec.qmp_socket},server=on,wait=off",
                "-vnc",
                f"127.0.0.1:{self.spec.vnc_display}",
                "-daemonize",
                "-pidfile",
                str(self.spec.pid_file),
            ]
        )
        return cmd

    def start(self) -> int:
        running, pid = self.is_running()
        if running and pid is not None:
            return pid

        for stale in (self.spec.qmp_socket, self.spec.qga_socket, self.spec.pid_file):
            stale.unlink(missing_ok=True)

        cmd = self.build_qemu_command()
        subprocess.run(cmd, check=True)
        _, new_pid = self.is_running()
        if new_pid is None:
            raise RuntimeError("QEMU process exited immediately without writing PID file.")
        return new_pid

    def stop(self, timeout_sec: float = 15.0) -> None:
        running, pid = self.is_running()
        if not running or pid is None:
            return

        self.qmp.system_powerdown()
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            still_up, _ = self.is_running()
            if not still_up:
                break
            time.sleep(0.5)
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

        for stale in (self.spec.qmp_socket, self.spec.qga_socket, self.spec.pid_file):
            stale.unlink(missing_ok=True)

    def create_snapshot(self, snapshot_name: str | None = None) -> None:
        name = snapshot_name or self.spec.golden_snapshot
        qemu_img = shutil.which("qemu-img") or "/opt/homebrew/bin/qemu-img"
        subprocess.run(
            [qemu_img, "snapshot", "-c", name, str(self.spec.resolved_disk_path)],
            check=True,
        )

    def restore_snapshot(self, snapshot_name: str | None = None) -> None:
        running, _ = self.is_running()
        if running:
            self.stop()
        name = snapshot_name or self.spec.golden_snapshot
        qemu_img = shutil.which("qemu-img") or "/opt/homebrew/bin/qemu-img"
        subprocess.run(
            [qemu_img, "snapshot", "-a", name, str(self.spec.resolved_disk_path)],
            check=True,
        )

    def create_profile_overlay(self, base_disk: Path, overlay_disk: Path) -> None:
        overlay_disk.parent.mkdir(parents=True, exist_ok=True)
        qemu_img = shutil.which("qemu-img") or "/opt/homebrew/bin/qemu-img"
        subprocess.run(
            [
                qemu_img,
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(base_disk.resolve()),
                str(overlay_disk.resolve()),
            ],
            check=True,
        )
