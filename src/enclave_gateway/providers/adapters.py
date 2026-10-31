"""Probe installed artifacts without guessing proprietary commands or importing keys."""

from __future__ import annotations

from dataclasses import dataclass

from enclave_gateway.security.quoting import ps_quote


@dataclass(frozen=True)
class ProviderAdapter:
    name: str
    revision: int
    binary_candidates: tuple[str, ...] = ()
    status_arguments: tuple[str, ...] = ()
    service_pattern: str = ""

    def capabilities(self):
        return {"provider": self.name, "adapter_revision": self.revision, "status_probe": True,
                "automatic_key_import": False, "automatic_install": False,
                "qualification": "requires-installed-version-and-driver-validation"}

    def probe_script(self, spec) -> str:
        candidates = ",".join(ps_quote(path) for path in self.binary_candidates)
        arguments = ",".join(ps_quote(arg) for arg in self.status_arguments)
        versions = ",".join(ps_quote(version) for version in spec.qualified_versions)
        architectures = ",".join(ps_quote(arch) for arch in spec.qualified_architectures)
        return f"""
$providerName={ps_quote(self.name)}
$providerRevision={self.revision}
$binary={ps_quote(spec.binary_path)}
$serviceName={ps_quote(spec.service_name or self.service_pattern)}
if (-not $binary) {{
    foreach ($candidate in @({candidates})) {{
        $expanded=[Environment]::ExpandEnvironmentVariables($candidate)
        if (Test-Path -LiteralPath $expanded -PathType Leaf) {{ $binary=$expanded; break }}
    }}
}}
$service=@()
if ($serviceName) {{ $service=@(Get-Service -Name $serviceName -ErrorAction SilentlyContinue | Select-Object Name,Status) }}
$version=''
$publisher=''
$signatureStatus='not_available'
$binaryArchitecture='unknown'
$info=($service | Out-String).Trim()
if ($binary -and (Test-Path -LiteralPath $binary -PathType Leaf)) {{
    $version=(Get-Item -LiteralPath $binary).VersionInfo.FileVersion
    $signature=Get-AuthenticodeSignature -LiteralPath $binary
    $signatureStatus=[string]$signature.Status
    if ($signature.SignerCertificate) {{ $publisher=$signature.SignerCertificate.Subject }}
    $fs=[IO.File]::OpenRead($binary)
    try {{
        $reader=New-Object IO.BinaryReader($fs)
        if ($reader.ReadUInt16() -eq 0x5a4d) {{
            $fs.Position=0x3c
            $offset=$reader.ReadInt32()
            if ($offset -gt 0 -and $offset -lt $fs.Length-6) {{
                $fs.Position=$offset
                if ($reader.ReadUInt32() -eq 0x4550) {{
                    $machine=$reader.ReadUInt16()
                    $binaryArchitecture=switch ($machine) {{ 0xaa64 {{ 'arm64' }} 0x8664 {{ 'x86_64' }} 0x014c {{ 'x86' }} default {{ 'unknown' }} }}
                }}
            }}
        }}
    }} finally {{ $fs.Dispose() }}
    # Invoke public status commands only for a matching trusted publisher/version.
    # Signature validity alone does not authorize an arbitrary installed binary.
}}
$expectedPublisher={ps_quote(spec.expected_publisher)}
$versionMatched=(@({versions}) -contains $version)
$architectureMatched=(@({architectures}) -contains $binaryArchitecture)
$publisherMatched=($expectedPublisher -and $publisher -eq $expectedPublisher -and $signatureStatus -eq 'Valid')
$configurationMatched=[bool]($versionMatched -and $architectureMatched -and $publisherMatched)
if ($configurationMatched -and @({arguments}).Count -gt 0) {{
    $info=(& $binary @({arguments}) | Out-String).Trim()
}}
$providerEvidence=@{{
    name=$providerName; adapter_revision=$providerRevision; version=$version; binary_architecture=$binaryArchitecture;
    signature_status=$signatureStatus; configuration_matched=$configurationMatched;
    status=if ($configurationMatched) {{ 'configuration_matched' }} else {{ 'unqualified' }};
    automatic_key_import=$false; driver_qualification='not_verified'; services=$service
}}
"""


_ADAPTERS = {
    "wireguard": ProviderAdapter("wireguard", 1, (r"%ProgramFiles%\WireGuard\wg.exe",), ("show",), "WireGuardTunnel$*"),
    "anyconnect": ProviderAdapter("anyconnect", 1, (
        r"%ProgramFiles(x86)%\Cisco\Cisco Secure Client\vpncli.exe",
        r"%ProgramFiles(x86)%\Cisco\Cisco AnyConnect Secure Mobility Client\vpncli.exe"), ("state",), "vpnagent"),
    "openvpn": ProviderAdapter("openvpn", 1, (r"%ProgramFiles%\OpenVPN\bin\openvpn.exe",), (), "OpenVPNService*"),
    "vipnet": ProviderAdapter("vipnet", 1),
    "kontinent": ProviderAdapter("kontinent", 1),
    "custom": ProviderAdapter("custom", 1),
}


def provider_adapter(name: str) -> ProviderAdapter:
    if name not in _ADAPTERS:
        raise ValueError("Unsupported VPN provider type")
    return _ADAPTERS[name]
