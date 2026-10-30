param(
    [string]$BastionHost = "10.0.1.10",
    [int]$BastionPort = 3389,
    [string]$SpoolDir = "C:\EnclaveGateway\spool",
    [string]$ScheduledTaskName = "StartEnclaveBastionRDP",
    [string]$InteractiveUser = "Admin",
    [string]$RdpDomainUser = "",
    [string]$RdpPassword = "",
    [switch]$ForceReconnect
)

$ErrorActionPreference = "SilentlyContinue"

# 1. If credentials are provided, inject them into the interactive desktop session's Credential Manager
if ($RdpDomainUser -and $RdpPassword) {
    $taskName = "UpdateEnclaveRDPCred"
    $cmdLine = "cmd.exe /c cmdkey /generic:TERMSRV/$BastionHost /user:$RdpDomainUser /pass:$RdpPassword"
    & schtasks.exe /create /tn $taskName /tr $cmdLine /sc ONCE /st 00:00 /ru $InteractiveUser /it /f | Out-Null
    & schtasks.exe /run /tn $taskName | Out-Null
    Start-Sleep -Seconds 2
    & schtasks.exe /delete /tn $taskName /f | Out-Null
}

# 2. Verify active TCP connection and worker telemetry
$stateFile = Join-Path $SpoolDir "worker_state.json"
$legacyHb = Join-Path $SpoolDir "heartbeat.txt"
$conn = Get-NetTCPConnection -RemoteAddress $BastionHost -RemotePort $BastionPort -State Established -ErrorAction SilentlyContinue

$hbFresh = $false
if (Test-Path $stateFile) {
    $hbFresh = (((Get-Date) - (Get-Item $stateFile).LastWriteTime).TotalSeconds -lt 6)
} elseif (Test-Path $legacyHb) {
    $hbFresh = (((Get-Date) - (Get-Item $legacyHb).LastWriteTime).TotalSeconds -lt 6)
}

if (-not $ForceReconnect -and $conn -and $hbFresh) {
    Write-Output "SESSION_ACTIVE"
    exit 0
}

Stop-Process -Name mstsc -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue

for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $conn = Get-NetTCPConnection -RemoteAddress $BastionHost -RemotePort $BastionPort -State Established -ErrorAction SilentlyContinue
    if (Test-Path $stateFile) {
        if ($conn -and (((Get-Date) - (Get-Item $stateFile).LastWriteTime).TotalSeconds -lt 6)) {
            Write-Output "SESSION_RECONNECTED"
            exit 0
        }
    } elseif (Test-Path $legacyHb) {
        if ($conn -and (((Get-Date) - (Get-Item $legacyHb).LastWriteTime).TotalSeconds -lt 6)) {
            Write-Output "SESSION_RECONNECTED"
            exit 0
        }
    }
}

Write-Output "SESSION_PENDING_WORKER"
exit 0
