param(
    [int]$Mtu = 1350,
    [string]$AdapterName = "Infotecs",
    [string]$BastionHost = "10.0.1.10",
    [int]$BastionPort = 3389,
    [int]$LocalProxyPort = 33890,
    [string]$MsiPath = "",
    [string]$DstPath = "",
    [string]$DstPassword = ""
)

$ErrorActionPreference = "Stop"

# 1. Disable RDP-over-UDP to prevent unnegotiated 1500-byte UDP frame drops over VPN tunnels
$rdpClientPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
if (-not (Test-Path $rdpClientPolicy)) {
    New-Item -Path $rdpClientPolicy -Force | Out-Null
}
Set-ItemProperty -Path $rdpClientPolicy -Name "fClientDisableUDP" -Value 1 -Type DWord

# 2. Enforce persistent MTU on VPN and primary Ethernet interfaces to prevent PMTUD blackholes
foreach ($iface in @($AdapterName, "Ethernet")) {
    & netsh.exe interface ipv4 set subinterface "$iface" mtu=$Mtu store=persistent 2>$null | Out-Null
}

# 3. Configure local TCP portproxy for Bastion RDP forwarding
& netsh.exe interface portproxy delete v4tov4 listenport=$LocalProxyPort listenaddress=0.0.0.0 2>$null | Out-Null
& netsh.exe interface portproxy add v4tov4 listenport=$LocalProxyPort listenaddress=0.0.0.0 connectport=$BastionPort connectaddress=$BastionHost | Out-Null

# 4. Optional silent installation of VPN client MSI and key deployment
if ($MsiPath -and (Test-Path $MsiPath)) {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$MsiPath`" /qn /norestart" -Wait
}

if ($DstPath -and (Test-Path $DstPath)) {
    $vipnetBin = "C:\Program Files\Mobile\bin\vipnetclient.exe"
    if (Test-Path $vipnetBin) {
        if ($DstPassword) {
            & $vipnetBin installkey "$DstPath" --psw "$DstPassword" | Out-Null
        } else {
            & $vipnetBin installkey "$DstPath" | Out-Null
        }
    }
}

Write-Output "APPLIANCE_INIT_OK"
