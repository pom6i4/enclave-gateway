param(
    [int]$Mtu = 1350,
    [string]$AdapterName = "Infotecs",
    [string]$BastionHost = "10.0.1.10",
    [int]$BastionPort = 3389,
    [int]$LocalProxyPort = 33890,
    [int64]$HostEpochUtc = 0,
    [string]$RoutesCsv = "",
    [string]$DnsServersCsv = "",
    [string]$MsiPath = "",
    [string]$DstPath = "",
    [string]$DstPassword = ""
)

$ErrorActionPreference = "Continue"

# 1. Post-snapshot clock resync & W32Time unlimited phase correction (prevents Kerberos/NLA 5-min skew failures)
$w32Config = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"
if (Test-Path $w32Config) {
    Set-ItemProperty -Path $w32Config -Name "MaxPosPhaseCorrection" -Value 0xFFFFFFFF -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $w32Config -Name "MaxNegPhaseCorrection" -Value 0xFFFFFFFF -Type DWord -ErrorAction SilentlyContinue
}
if ($HostEpochUtc -gt 0) {
    try {
        $targetTime = [DateTimeOffset]::FromUnixTimeSeconds($HostEpochUtc).LocalDateTime
        Set-Date -Date $targetTime | Out-Null
    } catch {}
}

# 2. Disable RDP-over-UDP and idle session timeouts to prevent UDP fragmentation drops and rdpdr unmounts
$tsPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpClientPolicy = "$tsPolicy\Client"
foreach ($p in @($tsPolicy, $rdpClientPolicy)) {
    if (-not (Test-Path $p)) {
        New-Item -Path $p -Force | Out-Null
    }
}
Set-ItemProperty -Path $rdpClientPolicy -Name "fClientDisableUDP" -Value 1 -Type DWord
Set-ItemProperty -Path $tsPolicy -Name "MaxIdleTime" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path $tsPolicy -Name "MaxDisconnectionTime" -Value 0 -Type DWord -ErrorAction SilentlyContinue
& powercfg.exe /change standby-timeout-ac 0 2>$null | Out-Null
& powercfg.exe /change monitor-timeout-ac 0 2>$null | Out-Null

# 3. Enforce persistent MTU on VPN and primary Ethernet interfaces to prevent PMTUD blackholes
foreach ($iface in @($AdapterName, "Ethernet")) {
    & netsh.exe interface ipv4 set subinterface "$iface" mtu=$Mtu store=persistent 2>$null | Out-Null
}

# 4. Optional VPN split-tunnel static routes and internal enclave DNS servers
if ($RoutesCsv) {
    $vpnIf = Get-NetAdapter -Name "*$AdapterName*" -ErrorAction SilentlyContinue | Select-Object -First 1
    foreach ($prefix in ($RoutesCsv -split ",")) {
        $p = $prefix.Trim()
        if ($p -and $vpnIf) {
            New-NetRoute -DestinationPrefix $p -InterfaceIndex $vpnIf.ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
if ($DnsServersCsv) {
    $dnsList = @($DnsServersCsv -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($dnsList.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceAlias "*$AdapterName*" -ServerAddresses $dnsList -ErrorAction SilentlyContinue
    }
}

# 5. Configure local TCP portproxy for Bastion RDP forwarding
& netsh.exe interface portproxy delete v4tov4 listenport=$LocalProxyPort listenaddress=0.0.0.0 2>$null | Out-Null
& netsh.exe interface portproxy add v4tov4 listenport=$LocalProxyPort listenaddress=0.0.0.0 connectport=$BastionPort connectaddress=$BastionHost | Out-Null

# 6. Optional silent installation of VPN client MSI and key deployment
if ($MsiPath -and (Test-Path $MsiPath)) {
    $installer = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$MsiPath`" /qn /norestart" -Wait -PassThru
    if ($installer.ExitCode -notin @(0, 3010)) { throw "VPN installer failed: $($installer.ExitCode)" }
}

if ($DstPath -and (Test-Path -LiteralPath $DstPath)) {
    throw 'Automatic key import is not configured. Use the documented procedure for the installed provider version.'
}

Write-Output "APPLIANCE_INIT_OK"
