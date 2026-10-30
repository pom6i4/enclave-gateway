"""Automated Appliance image builder (Autounattend.xml, VirtIO, QGA, ViPNet Client)."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from enclave_gateway.config import EnclaveConfig
from enclave_gateway.hypervisor.driver import (
    ApplianceHypervisor,
    detect_host_arch,
)


@dataclass(slots=True)
class ProvisionOptions:
    arch: str = "auto"
    admin_user: str = "Admin"
    admin_password: str = "Enclave#Appliance2026"
    computer_name: str = "enclave-vm"
    disk_size_gb: int = 64
    auto_partition: bool = True
    locale: str = "en-US"
    win_iso_path: str = ""
    virtio_iso_path: str = ""

    def resolved_arch(self, config_arch: str = "auto") -> str:
        pref = self.arch if self.arch != "auto" else config_arch
        return detect_host_arch(pref)


def generate_autounattend_xml(cfg: EnclaveConfig, opts: ProvisionOptions) -> str:
    """Generate a Windows 11 Unattended answer file (Autounattend.xml) for ARM64 or x86_64."""
    arch = opts.resolved_arch(cfg.appliance.arch)
    xml_arch = "arm64" if arch == "arm64" else "amd64"
    virtio_arch_dir = "ARM64\\w11" if arch == "arm64" else "amd64\\w11"
    qga_msi_name = "qemu-ga-aarch64.msi" if arch == "arm64" else "qemu-ga-x86_64.msi"

    user_esc = escape(opts.admin_user)
    pw_esc = escape(opts.admin_password)
    comp_esc = escape(opts.computer_name[:15])
    loc_esc = escape(opts.locale)

    driver_paths_xml_parts: list[str] = []
    path_key = 1
    for drive_letter in ("D", "E", "F"):
        for drv in ("viostor", "NetKVM", "vioserial", "qxldod"):
            driver_paths_xml_parts.append(
                f'        <PathAndCredentials wcm:action="add" wcm:keyValue="{path_key}">\n'
                f"          <Path>{drive_letter}:\\{drv}\\{virtio_arch_dir}</Path>\n"
                f"        </PathAndCredentials>"
            )
            path_key += 1
    driver_paths_xml = "\n".join(driver_paths_xml_parts)

    disk_config_xml = ""
    image_install_target_xml = ""
    if opts.auto_partition:
        disk_config_xml = """
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>EFI</Type>
              <Size>260</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>MSR</Type>
              <Size>16</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Label>System</Label>
              <Format>FAT32</Format>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>2</PartitionID>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>3</Order>
              <PartitionID>3</PartitionID>
              <Label>Windows</Label>
              <Letter>C</Letter>
              <Format>NTFS</Format>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>"""
        image_install_target_xml = """
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>3</PartitionID>
          </InstallTo>"""

    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage>
        <UILanguage>{loc_esc}</UILanguage>
      </SetupUILanguage>
      <InputLocale>{loc_esc}</InputLocale>
      <SystemLocale>{loc_esc}</SystemLocale>
      <UILanguage>{loc_esc}</UILanguage>
      <UserLocale>{loc_esc}</UserLocale>
    </component>
    <component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DriverPaths>
{driver_paths_xml}
      </DriverPaths>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">{disk_config_xml}
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/INDEX</Key>
              <Value>1</Value>
            </MetaData>
          </InstallFrom>{image_install_target_xml}
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>{user_esc}</FullName>
        <Organization>EnclaveGateway</Organization>
      </UserData>
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg.exe add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>reg.exe add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>3</Order>
          <Path>reg.exe add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>4</Order>
          <Path>reg.exe add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{comp_esc}</ComputerName>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Password>
              <Value>{pw_esc}</Value>
              <PlainText>true</PlainText>
            </Password>
            <Description>Enclave Appliance Administrator</Description>
            <DisplayName>{user_esc}</DisplayName>
            <Group>Administrators</Group>
            <Name>{user_esc}</Name>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Password>
          <Value>{pw_esc}</Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <Username>{user_esc}</Username>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Description>Install QEMU Guest Agent from VirtIO ISO</Description>
          <CommandLine>powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "foreach ($d in @('D','E','F','G')) {{ $p = \"$($d):\\guest-agent\\{qga_msi_name}\"; if (Test-Path $p) {{ Start-Process msiexec.exe -ArgumentList \"/i `\"$p`\" /qn /norestart\" -Wait; break }} }}"</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Description>Execute Enclave Gateway Appliance Post-Install Provisioner</Description>
          <CommandLine>powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "foreach ($d in @('D','E','F','G')) {{ $s = \"$($d):\\post_install.ps1\"; if (Test-Path $s) {{ &amp; $s; break }} }}"</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""


def generate_post_install_ps1(cfg: EnclaveConfig, opts: ProvisionOptions) -> str:
    """Generate the PowerShell post-installation script executed on first logon."""
    spool_dir = cfg.bastion.appliance_spool_dir
    bastion_host = cfg.bastion.host
    bastion_port = cfg.bastion.port
    task_name = cfg.bastion.scheduled_task_name
    mtu = cfg.appliance.mtu
    adapter_name = cfg.provider.adapter_name

    return f"""# Enclave Gateway Appliance First-Logon Provisioning Script
$ErrorActionPreference = "Continue"
$SeedRoot = $PSScriptRoot
$InstallRoot = "C:\\EnclaveGateway"
$SpoolDir = "{spool_dir}"

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
New-Item -ItemType Directory -Force -Path $SpoolDir | Out-Null

# 1. Copy agent scripts into C:\\EnclaveGateway and SpoolDir
foreach ($scriptName in @("appliance_init.ps1", "session_supervisor.ps1", "bastion_worker.ps1", "bastion_bootstrap.ps1")) {{
    $src = Join-Path $SeedRoot $scriptName
    if (Test-Path $src) {{
        Copy-Item $src (Join-Path $InstallRoot $scriptName) -Force
        Copy-Item $src (Join-Path $SpoolDir $scriptName) -Force
    }}
}}

# 2. Ensure QEMU Guest Agent service is running
Get-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
Start-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue

# 3. Synthesize RDP connection profile with rdpdr drive redirection enabled
$RdpFile = Join-Path $InstallRoot "bastion.rdp"
$RdpContent = @"
full address:s:{bastion_host}:{bastion_port}
prompt for credentials:i:0
administrative session:i:0
drivestoredirect:s:C:;
redirectdrives:i:1
redirectclipboard:i:1
autoreconnection enabled:i:1
authentication level:i:0
"@
[IO.File]::WriteAllText($RdpFile, $RdpContent, [Text.Encoding]::ASCII)

# 4. Register interactive Scheduled Task for Bastion RDP session
$TaskCmd = "mstsc.exe `"$RdpFile`""
& schtasks.exe /create /tn "{task_name}" /tr $TaskCmd /sc ONLOGON /ru "{opts.admin_user}" /it /rl HIGHEST /f | Out-Null

# 5. Apply MTU={mtu}, fClientDisableUDP=1, and optional ViPNet MSI + DST installation
$InitScript = Join-Path $InstallRoot "appliance_init.ps1"
$MsiCandidate = Join-Path $SeedRoot "ViPNet_Client.msi"
$DstCandidate = Join-Path $SeedRoot "client.dst"
if (Test-Path $InitScript) {{
    & $InitScript -Mtu {mtu} -AdapterName "{adapter_name}" -BastionHost "{bastion_host}" -BastionPort {bastion_port} -MsiPath $MsiCandidate -DstPath $DstCandidate
}}

Write-Output "ENCLAVE_PROVISION_COMPLETE"
"""


class ApplianceProvisioner:
    """Builds unattended provisioning bundles and initializes qcow2 appliance storage."""

    def __init__(self, config: EnclaveConfig) -> None:
        self.config = config
        self.hypervisor = ApplianceHypervisor(config.appliance)

    def prepare_bundle(
        self,
        output_dir: Path,
        opts: ProvisionOptions | None = None,
        *,
        create_disk: bool = False,
        force_disk: bool = False,
    ) -> dict[str, Any]:
        """Generate Autounattend.xml, agent scripts, and optional qcow2/EFI storage."""
        options = opts or ProvisionOptions()
        out_path = output_dir.expanduser().resolve()
        out_path.mkdir(parents=True, exist_ok=True)

        autounattend_path = out_path / "Autounattend.xml"
        autounattend_xml = generate_autounattend_xml(self.config, options)
        autounattend_path.write_text(autounattend_xml, encoding="utf-8")

        post_install_path = out_path / "post_install.ps1"
        post_install_ps1 = generate_post_install_ps1(self.config, options)
        post_install_path.write_text(post_install_ps1, encoding="utf-8")

        agents_dir = Path(__file__).resolve().parent.parent / "agents"
        copied_agents: list[str] = []
        for agent_file in (
            "appliance_init.ps1",
            "session_supervisor.ps1",
            "bastion_worker.ps1",
            "bastion_bootstrap.ps1",
        ):
            src = agents_dir / agent_file
            if src.is_file():
                dst = out_path / agent_file
                shutil.copy2(src, dst)
                copied_agents.append(agent_file)

        disk_path = self.config.appliance.resolved_disk_path
        efi_vars_path = self.config.appliance.resolved_efi_vars_path
        disk_created = False
        efi_created = False

        if create_disk:
            disk_created = self._ensure_qcow2_disk(
                disk_path, options.disk_size_gb, force=force_disk
            )
            if options.resolved_arch(self.config.appliance.arch) == "arm64":
                efi_created = self._ensure_efi_vars(efi_vars_path, force=force_disk)

        qemu_cmd = self.build_install_qemu_command(out_path, options)

        return {
            "arch": options.resolved_arch(self.config.appliance.arch),
            "output_dir": str(out_path),
            "autounattend_xml": str(autounattend_path),
            "post_install_ps1": str(post_install_path),
            "copied_agents": copied_agents,
            "disk_path": str(disk_path),
            "disk_size_gb": options.disk_size_gb,
            "disk_created": disk_created,
            "efi_vars_path": str(efi_vars_path),
            "efi_vars_created": efi_created,
            "qemu_install_command": qemu_cmd,
        }

    def build_install_qemu_command(
        self, seed_dir: Path, opts: ProvisionOptions
    ) -> list[str]:
        """Construct the QEMU command line with Windows ISO, VirtIO ISO, and VVFAT Autounattend seed."""
        cmd = list(self.hypervisor.build_qemu_command())
        # Remove -daemonize so interactive/automated installation can be monitored or awaited
        if "-daemonize" in cmd:
            cmd.remove("-daemonize")

        if opts.win_iso_path:
            win_iso = str(Path(opts.win_iso_path).expanduser().resolve())
            cmd.extend(
                [
                    "-drive",
                    f"file={win_iso},media=cdrom,readonly=on,if=none,id=cdrom_win",
                    "-device",
                    "usb-storage,drive=cdrom_win,bootindex=0",
                ]
            )
        if opts.virtio_iso_path:
            virtio_iso = str(Path(opts.virtio_iso_path).expanduser().resolve())
            cmd.extend(
                [
                    "-drive",
                    f"file={virtio_iso},media=cdrom,readonly=on,if=none,id=cdrom_virtio",
                    "-device",
                    "usb-storage,drive=cdrom_virtio",
                ]
            )

        # Attach the provisioning directory as a read-only Virtual VFAT USB drive containing Autounattend.xml
        cmd.extend(
            [
                "-drive",
                f"file=fat:rw:{seed_dir.resolve()},format=raw,if=none,id=seed_vvfat",
                "-device",
                "usb-storage,drive=seed_vvfat",
            ]
        )
        return cmd

    @staticmethod
    def _ensure_qcow2_disk(disk_path: Path, size_gb: int, *, force: bool = False) -> bool:
        if disk_path.exists() and not force:
            return False
        disk_path.parent.mkdir(parents=True, exist_ok=True)
        qemu_img = shutil.which("qemu-img") or "/opt/homebrew/bin/qemu-img"
        subprocess.run(
            [qemu_img, "create", "-f", "qcow2", str(disk_path), f"{size_gb}G"],
            check=True,
        )
        return True

    @staticmethod
    def _ensure_efi_vars(efi_vars_path: Path, *, force: bool = False) -> bool:
        if efi_vars_path.exists() and not force:
            return False
        efi_vars_path.parent.mkdir(parents=True, exist_ok=True)
        # 64 MB pflash image required by QEMU edk2-aarch64
        with efi_vars_path.open("wb") as fp:
            fp.seek(64 * 1024 * 1024 - 1)
            fp.write(b"\x00")
        return True
