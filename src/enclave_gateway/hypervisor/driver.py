"""Hypervisor driver for QEMU (macOS HVF, Linux KVM, Windows WHPX) and qcow2 snapshots."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
import socket
from dataclasses import replace
from pathlib import Path

from enclave_gateway.config import ApplianceSpec
from enclave_gateway.control.qmp_client import QmpClient


def process_running(pid):
    if os.name!='nt':
        try:os.kill(pid,0)
        except ProcessLookupError:return False
        except PermissionError:return True
        return True
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32]
    kernel.OpenProcess.restype=ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint32]
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=kernel.OpenProcess(0x100000,False,pid)
    if not handle:
        if ctypes.get_last_error()==87:return False
        return True
    try:return kernel.WaitForSingleObject(handle,0)!=0
    finally:kernel.CloseHandle(handle)


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
    return binary_name


def resolve_efi_code_path(arch: str, configured_path: str = "") -> str:
    """Resolve UEFI firmware image across macOS (edk2), Linux (AAVMF/OVMF), and Windows."""
    if configured_path:
        expanded = Path(os.path.expanduser(configured_path))
        if not expanded.is_file():
            raise FileNotFoundError(f"Configured UEFI firmware does not exist: {expanded}")
        return str(expanded.absolute())

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


def qemu_value(path: str | Path) -> str:
    value = str(path)
    if any(ch in value for ch in "\n\r\0"):
        raise ValueError("Invalid QEMU option value")
    return value.replace(",", ",,")


def resolve_efi_vars_template(arch: str, code_path: str, configured_path: str = '') -> Path:
    if configured_path:
        path=Path(configured_path).expanduser().absolute()
        if not path.is_file():raise FileNotFoundError('Configured firmware variable template is missing')
        return path
    code = Path(code_path)
    names = (["edk2-aarch64-vars.fd", "AAVMF_VARS.fd", "edk2-arm-vars.fd", "AAVMF_VARS.ms.fd", "vars-template-pflash.raw"] if arch == "arm64" else
             [code.name.replace("CODE", "VARS"), "edk2-i386-vars.fd", "OVMF_VARS_4M.fd", "OVMF_VARS.fd"])
    for name in names:
        path = code.parent / name
        if path != code and path.is_file():
            return path
    raise FileNotFoundError("No matching UEFI variable-store template; configure a matched firmware pair")


class ApplianceHypervisor:
    """Manages the cryptographic appliance VM lifecycle and copy-on-write snapshots."""

    def __init__(self, spec: ApplianceSpec) -> None:
        self.spec = spec
        self.qmp = QmpClient(spec.qmp_socket)

    @staticmethod
    def tpm_capabilities():
        supported=platform.system()!='Windows'
        return {'managed_software_tpm':supported,'backend':'swtpm' if supported else None,
                'reason':None if supported else 'qemu-windows-tpm-backend-unavailable',
                'hardware_attestation':False}

    def validate_tpm_host(self):
        if self.spec.tpm_state_dir and not self.tpm_capabilities()['managed_software_tpm']:
            raise ValueError('Windows QEMU does not provide a TPM emulator backend; use a POSIX virtualization host')

    def is_running(self) -> tuple[bool, int | None]:
        if not self.spec.pid_file.is_file():
            return False, None
        try:
            pid = int(self.spec.pid_file.read_text(encoding="utf-8").strip())
            if pid <= 0:
                return False, None
            # QMP proves the VM is alive. PID probing with os.kill is not portable
            # to Windows and cannot establish ownership after PID reuse.
            if "return" not in self.qmp.query_status():
                return False, None
            identity=self.qmp.execute('query-name')
            if identity.get('return',{}).get('name')!=self.spec.name:
                from enclave_gateway.operations.context import OperationError
                raise OperationError('vm_identity_mismatch','hypervisor.identity',
                    message='Control endpoint belongs to a different VM: expected '+repr(self.spec.name)+
                    ', actual '+repr(identity.get('return',{}).get('name'))+
                    '. Set appliance.name to the verified QMP name and configure qga_socket_path, qmp_socket_path and pid_file_path separately.')
            return True, pid
        except (ValueError, OSError):
            return False, None

    def build_qemu_command(self) -> list[str]:
        self.validate_tpm_host()
        accel = detect_host_accelerator(self.spec.hypervisor)
        arch = detect_host_arch(self.spec.arch)

        if arch != detect_host_arch() and accel != "tcg":
            if self.spec.hypervisor == "auto":
                accel = "tcg"
            else:
                raise ValueError("Native acceleration requires matching host and guest architectures")
        for endpoint in (self.spec.qga_socket,self.spec.qmp_socket,self.spec.tpm_socket):
            if len(os.fsencode(endpoint))>=104:raise ValueError('Use a shorter private runtime_dir for UNIX control sockets')
        qemu_bin = resolve_qemu_binary(arch)
        efi_code = resolve_efi_code_path(arch, self.spec.efi_code_path)

        hostfwd_rules = [
            f"hostfwd=tcp:127.0.0.1:{self.spec.rdp_forward_port}-:33890",
            f"hostfwd=tcp:127.0.0.1:{self.spec.vm_rdp_forward_port}-:3389",
            f"hostfwd=tcp:127.0.0.1:{self.spec.socks5_port}-:1080",
        ]
        if self.spec.ssh_forward_port:
            hostfwd_rules.append(f'hostfwd=tcp:127.0.0.1:{self.spec.ssh_forward_port}-:22')
        netdev_arg = "user,id=net0," + ("restrict=on," if self.spec.network_restrict else "") + ",".join(hostfwd_rules)

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
        if platform.system()=='Windows':
            data=Path(qemu_bin).parent/'share'
            if data.is_dir():cmd.extend(['-L',str(data)])

        if arch == "arm64":
            cmd.extend(
                [
                    "-M",
                    "virt,highmem=on",
                    "-drive",
                    f"if=pflash,format=raw,readonly=on,file={qemu_value(efi_code)}",
                    "-drive",
                    f"if=pflash,format=raw,file={qemu_value(self.spec.resolved_efi_vars_path)}",
                    "-device",
                    self.spec.display_device,
                ]
            )
        else:
            cmd.extend(["-M", "q35,smm=on" if self.spec.secure_boot else "q35", "-drive", f"if=pflash,format=raw,readonly=on,file={qemu_value(efi_code)}",
                        "-drive", f"if=pflash,format=raw,file={qemu_value(self.spec.resolved_efi_vars_path)}"])

        if self.spec.secure_boot:
            if arch!='x86_64':raise ValueError('Configured secure firmware mode currently requires x86_64')
            cmd.extend(['-global','driver=cfi.pflash01,property=secure,value=on'])
        cmd.extend(
            [
                "-device",
                "qemu-xhci,id=xhci",
                "-device",
                "usb-kbd",
                "-device",
                "usb-tablet",
                "-drive",
                f"file={qemu_value(self.spec.resolved_disk_path)},format=qcow2,if=none,id=drive0,cache=writeback",
                "-device",
                "nvme,drive=drive0,serial=drive0,bootindex=1",
                "-netdev",
                netdev_arg,
                "-device",
                "virtio-net-pci,netdev=net0",
                "-device",
                "virtio-serial-pci",
                "-chardev",
                f"socket,path={qemu_value(self.spec.qga_socket)},server=on,wait=off,id=qga0",
                "-device",
                "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
                "-qmp",
                f"unix:{qemu_value(self.spec.qmp_socket)},server=on,wait=off",
                "-vnc",
                f"127.0.0.1:{self.spec.vnc_display}",
                "-daemonize",
                "-pidfile",
                str(self.spec.pid_file),
            ]
        )
        if self.spec.tpm_state_dir:
            cmd.extend(['-chardev',f'socket,id=tpmctrl,path={qemu_value(self.spec.tpm_socket)}',
                        '-tpmdev','emulator,id=tpm0,chardev=tpmctrl','-device',
                        'tpm-tis-device,tpmdev=tpm0' if arch=='arm64' else 'tpm-tis,tpmdev=tpm0'])
        if platform.system() == "Windows":
            cmd.remove("-daemonize")
        return cmd

    def state_store(self):
        from enclave_gateway.hypervisor.state import StateStore
        spec=replace(self.spec,arch=detect_host_arch(self.spec.arch))
        return StateStore(spec,resolve_efi_code_path(spec.arch,spec.efi_code_path))

    def _assert_offline(self):
        if self.is_running()[0] or self.spec.pid_file.exists():
            raise RuntimeError('Stop the appliance before changing its offline state')
        if self.spec.qmp_socket.exists():
            # An orphan control endpoint is not proof that its disk is stopped.
            try:
                result=self.qmp.execute('query-name')
            except (OSError,ValueError):pass
            else:raise RuntimeError('VM control endpoint is still active')
        self._stop_tpm()

    def _stop_tpm(self):
        if not self.spec.tpm_state_dir or not self.spec.tpm_socket.exists():return
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
            probe.settimeout(1)
            try:probe.connect(str(self.spec.tpm_socket))
            except OSError:return
        tool=shutil.which('swtpm_ioctl')
        if not tool:raise FileNotFoundError('swtpm_ioctl is required to quiesce TPM state')
        subprocess.run([tool,'--unix',str(self.spec.tpm_socket),'-s'],check=True,capture_output=True,timeout=10)
        deadline=time.monotonic()+5
        while self.spec.tpm_socket.exists():
            if time.monotonic()>deadline:raise TimeoutError('TPM backend has not stopped')
            time.sleep(.05)

    def _start_tpm(self):
        if not self.spec.tpm_state_dir:return
        self.validate_tpm_host()
        from enclave_gateway.hypervisor.state import private_dir
        state=Path(self.spec.tpm_state_dir).expanduser().absolute();private_dir(state)
        self._stop_tpm()
        self.spec.tpm_socket.unlink(missing_ok=True)
        executable=shutil.which('swtpm')
        if not executable:raise FileNotFoundError('swtpm is required for this appliance')
        subprocess.run([executable,'socket','--tpm2','--tpmstate','dir='+str(state),
                        '--ctrl','type=unixio,path='+str(self.spec.tpm_socket),
                        '--flags','not-need-init','--daemon'],check=True,capture_output=True,timeout=10)

    def start(self) -> int:
        if any((self.spec.qga_socket_path,self.spec.qmp_socket_path,self.spec.pid_file_path)):
            return self._start()
        store=self.state_store()
        with store.locked():
            if store.pending.exists():
                self._assert_offline();store.recover()
            return self._start()

    def _start(self) -> int:
        running, pid = self.is_running()
        if running and pid is not None:
            return pid
        if any((self.spec.qga_socket_path,self.spec.qmp_socket_path,self.spec.pid_file_path)):
            raise ValueError('Explicit control paths attach to an existing VM; start it with its owner launcher or omit the overrides for managed creation')

        if self.spec.pid_file.exists():
            raise RuntimeError("Unresponsive VM PID file exists; verify process ownership before removing stale state")
        self._assert_offline()
        runtime = Path(self.spec.runtime_dir)
        if runtime.is_symlink():
            raise ValueError("Runtime directory must not be a symlink")
        from enclave_gateway.hypervisor.state import private_dir
        private_dir(runtime)
        for stale in (self.spec.qmp_socket, self.spec.qga_socket):
            stale.unlink(missing_ok=True)
        cmd = self.build_qemu_command()
        if not self.spec.resolved_disk_path.is_file() or not self.spec.resolved_efi_vars_path.is_file():
            raise FileNotFoundError("Appliance disk or UEFI variable store is missing")
        if self.spec.profile_base_bundle:
            from enclave_gateway.hypervisor.state import digest
            import json
            base=Path(self.spec.profile_base_bundle).expanduser().absolute()
            if digest(base/'manifest.json')!=self.spec.profile_base_manifest_sha256:raise ValueError('Profile base manifest changed')
            verifier=self.state_store();verifier.root=base.parent;verifier.verify(base.name)
            info=json.loads(subprocess.check_output([shutil.which('qemu-img') or 'qemu-img','info','--output=json',str(self.spec.resolved_disk_path)]))
            backing=info.get('full-backing-filename')
            if not backing or Path(backing).resolve()!=(base/'disk').resolve():raise ValueError('Profile backing image mismatch')
        self._start_tpm()
        if platform.system() == "Windows":
            log=runtime/'qemu-start.log'
            if log.is_symlink():raise ValueError('QEMU startup log cannot be a link')
            with log.open('wb') as stderr:
                process=subprocess.Popen(cmd, cwd=runtime, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
                                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline and process.poll() is None:
                if self.is_running()[0]:break
                time.sleep(0.05)
            if process.poll() is not None:
                raise RuntimeError('QEMU exited during startup; inspect the private qemu-start.log')
        else:
            try:
                subprocess.run(cmd, check=True)
            except (OSError, subprocess.CalledProcessError):
                # Quiesce only after the ordinary offline ownership checks.
                # An ambiguous live endpoint must keep its backend untouched.
                self._assert_offline()
                raise
        _, new_pid = self.is_running()
        if new_pid is None:
            raise RuntimeError("QEMU process exited immediately without writing PID file.")
        return new_pid

    def stop(self, timeout_sec: float = 120.0) -> None:
        if any((self.spec.qga_socket_path,self.spec.qmp_socket_path,self.spec.pid_file_path)):
            self._stop(timeout_sec);return
        with self.state_store().locked():self._stop(timeout_sec)

    def _stop(self, timeout_sec: float) -> None:
        running, pid = self.is_running()
        if not running or pid is None:
            if self.spec.pid_file.exists():
                raise RuntimeError("Cannot verify appliance state; runtime files are preserved")
            return

        deadline = time.monotonic() + timeout_sec
        try:
            from enclave_gateway.control.qga_client import QgaClient
            QgaClient(self.spec.qga_socket).shutdown_guest(timeout_sec=min(10,max(.001,timeout_sec)))
        except (OSError,ValueError,RuntimeError):
            if not self.qmp.system_powerdown():raise RuntimeError('Neither guest shutdown nor ACPI was acknowledged')
        while time.monotonic() < deadline:
            still_up, _ = self.is_running()
            if not still_up and not process_running(pid):
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("Appliance did not stop; runtime state is preserved")

        self._stop_tpm()
        if not any((self.spec.qga_socket_path,self.spec.qmp_socket_path,self.spec.pid_file_path)):
            for stale in (self.spec.qmp_socket, self.spec.qga_socket, self.spec.pid_file):
                stale.unlink(missing_ok=True)

    def create_snapshot(self, snapshot_name: str | None = None) -> None:
        store=self.state_store()
        with store.locked():
            self._assert_offline()
            store.create(snapshot_name or self.spec.golden_snapshot)

    def restore_snapshot(self, snapshot_name: str | None = None) -> None:
        if self.is_running()[0]:self.stop()
        store=self.state_store()
        with store.locked():
            self._assert_offline()
            store.restore(snapshot_name or self.spec.golden_snapshot)

    def recover_snapshot_restore(self):
        store=self.state_store()
        with store.locked():
            self._assert_offline()
            return store.recover()

    def create_profile_overlay(self, base_disk: Path, overlay_disk: Path) -> None:
        if overlay_disk.exists():
            raise FileExistsError("Profile overlay already exists")
        if base_disk.resolve() == overlay_disk.resolve():
            raise ValueError("Overlay must differ from its backing disk")
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
            check=True,capture_output=True,
        )
