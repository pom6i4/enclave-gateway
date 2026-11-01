"""Automated Appliance image builder (Autounattend.xml, VirtIO, QGA, ViPNet Client)."""

from __future__ import annotations

import shutil
import secrets
import re
import json
import hashlib
import uuid
import os
import tempfile
import subprocess
from dataclasses import dataclass, field, replace, asdict
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from enclave_gateway.config import EnclaveConfig
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.hypervisor.driver import (
    ApplianceHypervisor,
    detect_host_arch,
    resolve_efi_code_path,
    resolve_efi_vars_template,
    qemu_value,
)


@dataclass(slots=True)
class ProvisionOptions:
    arch: str = "auto"
    admin_user: str = "Admin"
    admin_password: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    computer_name: str = "enclave-vm"
    disk_size_gb: int = 64
    auto_partition: bool = True
    locale: str = "en-US"
    win_iso_path: str = ""
    virtio_iso_path: str = ""
    seed_iso_path: str = ""
    guest_agent_sha256: str = ""
    completion_mode: str = 'StartupTask'

    def __post_init__(self):
        if self.completion_mode not in ('StartupTask','SetupComplete'):raise ValueError('Invalid machine completion mode')
        if self.guest_agent_sha256:
            if not isinstance(self.guest_agent_sha256,str) or not re.fullmatch(r'[a-fA-F0-9]{64}',self.guest_agent_sha256):
                raise ValueError('Guest agent approval must be an exact SHA-256')
            self.guest_agent_sha256=self.guest_agent_sha256.lower()

    def resolved_arch(self, config_arch: str = "auto") -> str:
        pref = self.arch if self.arch != "auto" else config_arch
        return detect_host_arch(pref)


def generate_autounattend_xml(cfg: EnclaveConfig, opts: ProvisionOptions) -> str:
    """Generate a Windows 11 Unattended answer file (Autounattend.xml) for ARM64 or x86_64."""
    arch = opts.resolved_arch(cfg.appliance.arch)
    xml_arch = "arm64" if arch == "arm64" else "amd64"
    driver_arch_dir = "ARM64" if arch == "arm64" else "amd64"
    qga_msi_name = "qemu-ga-aarch64.msi" if arch == "arm64" else "qemu-ga-x86_64.msi"

    user_esc = escape(opts.admin_user)
    pw_esc = escape(opts.admin_password)
    comp_esc = escape(opts.computer_name[:15])
    loc_esc = escape(opts.locale)

    driver_paths_xml_parts: list[str] = []
    path_key = 1
    for drive_letter in ("D", "E", "F"):
        for drv in ("viostor", "NetKVM", "vioserial", "viogpudo", "qxldod"):
            paths=(f"{drv}\\{driver_arch_dir}\\w11",f"{drv}\\w11\\{driver_arch_dir}",f"Drivers\\{drv}\\w11\\{driver_arch_dir}")
            for relative in paths:
                driver_paths_xml_parts.append(
                    f'        <PathAndCredentials wcm:action="add" wcm:keyValue="{path_key}">\n'
                    f"          <Path>{drive_letter}:\\{relative}</Path>\n"
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

    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order>
        <Path>powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$s=@(Get-PSDrive -PSProvider FileSystem|%{{Join-Path $_.Root machine_prepare.ps1}}|?{{Test-Path -LiteralPath $_}});if($s.Count -ne 1){{exit 1}};&amp; $s[0] -Architecture '{arch}'"</Path>
      </RunSynchronousCommand></RunSynchronous>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="{xml_arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{comp_esc}</ComputerName>
      <TimeZone>UTC</TimeZone>
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
        <ProtectYourPC>1</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
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

    </component>
  </settings>
</unattend>
"""


def generate_post_install_ps1(cfg: EnclaveConfig, opts: ProvisionOptions) -> str:
    """Generate machine provisioning runnable from its media or through QGA."""
    spool_dir = cfg.bastion.appliance_spool_dir
    bastion_host = cfg.bastion.host
    bastion_port = cfg.bastion.port
    task_name = cfg.bastion.scheduled_task_name
    mtu = cfg.appliance.mtu
    adapter_name = cfg.provider.adapter_name

    return f"""# Enclave Gateway Appliance Machine Provisioning Script
$ErrorActionPreference = "Stop"
$SeedRoot = $PSScriptRoot
if (-not $SeedRoot) {{
    $seeds=@(Get-PSDrive -PSProvider FileSystem | Where-Object {{
        (Test-Path (Join-Path $_.Root 'machine_prepare.ps1')) -and (Test-Path (Join-Path $_.Root 'bastion_worker.ps1'))
    }})
    if ($seeds.Count -ne 1) {{throw 'Expected one attached provision seed'}}
    $SeedRoot=$seeds[0].Root
}}
$InstallRoot = "C:\\EnclaveGateway"
$SpoolDir = {ps_quote(spool_dir)}

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
Get-Service -Name "qemu-ga" -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
Start-Service -Name "qemu-ga" -ErrorAction SilentlyContinue

if (-not {str(cfg.bastion.enabled).lower().replace('true','$true').replace('false','$false')}) {{
    Write-Output 'ENCLAVE_PROVISION_COMPLETE_NO_BASTION'
    return
}}

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
bitmapcachepersistenable:i:0
compression:i:1
authentication level:i:1
"@
[IO.File]::WriteAllText($RdpFile, $RdpContent, [Text.Encoding]::ASCII)

# 4. Register interactive Scheduled Task for Bastion RDP session
$TaskCmd = "mstsc.exe `"$RdpFile`""
& schtasks.exe /create /tn {ps_quote(task_name)} /tr $TaskCmd /sc ONLOGON /ru {ps_quote(opts.admin_user)} /it /rl HIGHEST /f | Out-Null

# 5. Apply MTU={mtu}, fClientDisableUDP=1, and optional ViPNet MSI + DST installation
$InitScript = Join-Path $InstallRoot "appliance_init.ps1"
$MsiCandidate = Join-Path $SeedRoot "ViPNet_Client.msi"
$DstCandidate = Join-Path $SeedRoot "client.dst"
if (Test-Path $InitScript) {{
    & $InitScript -Mtu {mtu} -AdapterName {ps_quote(adapter_name)} -BastionHost {ps_quote(bastion_host)} -BastionPort {bastion_port} -MsiPath $MsiCandidate -DstPath $DstCandidate
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
        self.hypervisor.validate_tpm_host()
        if create_disk:
            self.hypervisor._assert_offline()
        out_path = output_dir.expanduser().resolve()
        from enclave_gateway.hypervisor.state import private_dir
        private_dir(out_path)

        autounattend_path = out_path / "Autounattend.xml"
        autounattend_xml = generate_autounattend_xml(self.config, options)
        autounattend_path.write_text(autounattend_xml, encoding="utf-8")
        (out_path/'provision-media.json').write_text(json.dumps({'revision':1,'guest_agent_sha256':options.guest_agent_sha256,'completion_mode':options.completion_mode})+'\n',encoding='utf-8')

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
            "machine_prepare.ps1",
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
            arch = options.resolved_arch(self.config.appliance.arch)
            code = resolve_efi_code_path(arch, self.config.appliance.efi_code_path)
            efi_created = self._ensure_efi_vars(efi_vars_path, template=resolve_efi_vars_template(arch, code, self.config.appliance.efi_vars_template_path), force=force_disk)

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
        spec = replace(self.config.appliance, arch=opts.resolved_arch(self.config.appliance.arch))
        cmd = list(ApplianceHypervisor(spec).build_qemu_command())
        # Remove -daemonize so interactive/automated installation can be monitored or awaited
        if "-daemonize" in cmd:
            cmd.remove("-daemonize")

        if opts.win_iso_path:
            win_iso = str(Path(opts.win_iso_path).expanduser().resolve())
            cmd.extend(
                [
                    "-drive",
                    f"file={qemu_value(win_iso)},media=cdrom,readonly=on,if=none,id=cdrom_win",
                    "-device",
                    # An empty system disk falls through to this installer;
                    # after setup, the populated system disk remains first.
                    "usb-storage,drive=cdrom_win,bootindex=2",
                ]
            )
        # A prebuilt ISO avoids distributor-specific VVFAT filename handling.
        source=f"file={qemu_value(Path(opts.seed_iso_path).expanduser().resolve())}" if opts.seed_iso_path else f"file=fat:{qemu_value(seed_dir.resolve())}"
        cmd.extend(['-drive',source+(',media=cdrom' if opts.seed_iso_path else '')+',readonly=on,format=raw,if=none,id=seed_vvfat','-device','usb-storage,drive=seed_vvfat'])
        if opts.virtio_iso_path:
            virtio_iso = str(Path(opts.virtio_iso_path).expanduser().resolve())
            cmd.extend(
                [
                    "-drive",
                    f"file={qemu_value(virtio_iso)},media=cdrom,readonly=on,if=none,id=cdrom_virtio",
                    "-device",
                    "usb-storage,drive=cdrom_virtio",
                ]
            )

        return cmd

    @staticmethod
    def _ensure_qcow2_disk(disk_path: Path, size_gb: int, *, force: bool = False) -> bool:
        if size_gb < 1:
            raise ValueError("Disk size must be positive")
        if disk_path.exists() and not force:
            return False
        disk_path.parent.mkdir(parents=True, exist_ok=True)
        qemu_img = shutil.which("qemu-img") or "/opt/homebrew/bin/qemu-img"
        subprocess.run(
            [qemu_img, "create", "-f", "qcow2", str(disk_path), f"{size_gb}G"],
            check=True,capture_output=True,
        )
        return True

    @staticmethod
    def _ensure_efi_vars(efi_vars_path: Path, *, template: Path, force: bool = False) -> bool:
        if efi_vars_path.exists() and not force:
            return False
        efi_vars_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(template, efi_vars_path)
        return True

    def create_cow_profile(
        self,
        profile_name: str,
        *,
        base_disk: Path | None = None,
        output_dir: Path | None = None,
        create_disk: bool = False,
    ) -> dict[str, Any]:
        """Create a Copy-on-Write (CoW) qcow2 overlay profile and topology configuration."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", profile_name):
            raise ValueError("Invalid profile name")
        base_path = (
            base_disk.expanduser().resolve()
            if base_disk is not None
            else self.config.appliance.resolved_disk_path
        )
        prof_dir = (
            output_dir.expanduser().resolve()
            if output_dir is not None
            else base_path.parent / "profiles" / profile_name
        )
        from enclave_gateway.hypervisor.state import private_dir,digest,copy_resource
        private_dir(prof_dir)

        overlay_disk = prof_dir / f"{profile_name}.qcow2"
        profile_yaml = prof_dir / f"enclave.{profile_name}.yaml"

        qemu_img = shutil.which("qemu-img") or "/opt/homebrew/bin/qemu-img"
        qemu_img_cmd = [
            qemu_img,
            "create",
            "-f",
            "qcow2",
            "-b",
            str(base_path),
            "-F",
            "qcow2",
            str(overlay_disk),
        ]

        if profile_yaml.exists():
            raise FileExistsError("Profile configuration already exists")
        overlay_created = False
        base_bundle=None
        if create_disk:
            if base_path!=self.config.appliance.resolved_disk_path:
                raise ValueError('Create a profile from a configuration matching the complete base state')
            store=self.hypervisor.state_store()
            with store.locked():
                self.hypervisor._assert_offline()
                name='profile_'+profile_name[:40]+'_'+uuid.uuid4().hex[:12]
                store.create(name);base_bundle=(store.root/name).resolve();base_path=base_bundle/'disk'
                self.hypervisor.create_profile_overlay(base_path, overlay_disk)
            qemu_img_cmd[qemu_img_cmd.index('-b')+1]=str(base_path)
            overlay_created = True

        profile_data = asdict(self.config)
        profile_data["profile"] = profile_name
        profile_data["appliance"]["name"] = f"enclave-{profile_name}" if len(profile_name)<=24 else 'enclave-'+hashlib.sha256(profile_name.encode()).hexdigest()[:16]
        profile_data['appliance']['runtime_dir']=tempfile.mkdtemp(prefix='egw-profile-',dir='/tmp' if os.name!='nt' else None)
        profile_data["appliance"]["disk_path"] = str(overlay_disk)
        profile_data['appliance']['snapshot_dir']=''
        if base_bundle:
            profile_data['appliance']['profile_base_bundle']=str(base_bundle)
            profile_data['appliance']['profile_base_manifest_sha256']=digest(base_bundle/'manifest.json')
        if self.config.appliance.tpm_state_dir:
            profile_data['appliance']['tpm_state_dir']=str(prof_dir/'tpm')
            source=base_bundle/'tpm' if base_bundle else Path(self.config.appliance.tpm_state_dir)
            if create_disk:copy_resource(source,prof_dir/'tpm')
        # Stable, distinct planned ports. Binding at VM start remains the final
        # collision check; these ports are not reserved by profile generation.
        port_base = 20000 + (int(hashlib.sha256(profile_name.encode()).hexdigest()[:8], 16) % 7500) * 4
        for offset, key in enumerate(("rdp_forward_port", "vm_rdp_forward_port", "socks5_port")):
            profile_data["appliance"][key] = port_base + offset
        profile_data['appliance']['ssh_forward_port']=port_base+3 if self.config.appliance.ssh_forward_port else 0
        profile_data["appliance"]["vnc_display"] = 100 + port_base % 1000
        profile_vars = prof_dir / "efi_vars.fd"
        profile_data["appliance"]["efi_vars_path"] = str(profile_vars)
        nvram_source=base_bundle/'nvram' if base_bundle else self.config.appliance.resolved_efi_vars_path
        if nvram_source.is_file() and not profile_vars.exists():
            shutil.copyfile(nvram_source, profile_vars)
        profile_yaml.write_text(json.dumps(profile_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        return {
            "profile": profile_name,
            "base_disk": str(base_path),
            "overlay_disk": str(overlay_disk),
            "profile_config": str(profile_yaml),
            "overlay_created": overlay_created,
            "qemu_img_command": qemu_img_cmd,
        }
