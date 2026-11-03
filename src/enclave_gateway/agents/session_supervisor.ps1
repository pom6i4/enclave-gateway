param(
    [ValidateSet('Files','Stream')][string]$SpoolProtocol = 'Files',
    [string]$BastionHost = "10.0.1.10",
    [int]$BastionPort = 3389,
    [ValidateRange(5,300)][int]$HeartbeatMaxAgeSec = 45,
    [string]$SpoolDir = "C:\EnclaveGateway\spool",
    [string]$ScheduledTaskName = "StartEnclaveBastionRDP",
    [string]$InteractiveUser = "Admin",
    [string]$RdpDomainUser = "",
    [string]$RdpPassword = "",
    [string]$RdpPasswordB64 = "",
    [switch]$ForceReconnect
)

$ErrorActionPreference = "SilentlyContinue"

# 1. If credentials are provided, inject them into the interactive desktop session's Credential Manager without exposing cleartext in schtasks /tr
$effectiveB64 = $RdpPasswordB64
if (-not $effectiveB64 -and $RdpPassword) {
    $effectiveB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($RdpPassword))
}

if ($RdpDomainUser -and $effectiveB64) {
    if (-not (Test-Path $SpoolDir)) { New-Item -ItemType Directory -Force -Path $SpoolDir | Out-Null }
    $taskName = "UpdateEnclaveRDPCred"
    $credScript = Join-Path $SpoolDir "cred_update.ps1"
    $scriptBody = @"
`$pw = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$effectiveB64'))
& cmdkey.exe "/generic:TERMSRV/$BastionHost" "/user:$RdpDomainUser" "/pass:`$pw" | Out-Null
`$pw = `$null
"@
    try {
        [IO.File]::WriteAllText($credScript, $scriptBody, [Text.Encoding]::UTF8)
        $cmdLine = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$credScript`""
        & schtasks.exe /create /tn $taskName /tr $cmdLine /sc ONCE /st 00:00 /ru $InteractiveUser /it /f | Out-Null
        & schtasks.exe /run /tn $taskName | Out-Null
        Start-Sleep -Seconds 2
    } finally {
        & schtasks.exe /delete /tn $taskName /f | Out-Null
        if (Test-Path $credScript) {
            [IO.File]::WriteAllBytes($credScript, (New-Object byte[] 256))
            Remove-Item $credScript -Force -ErrorAction SilentlyContinue
        }
    }
}

# 2. Verify active TCP connection and worker telemetry
$stateFile = Join-Path $SpoolDir "worker_state.json"
$legacyHb = Join-Path $SpoolDir "heartbeat.txt"
$conn = Get-NetTCPConnection -RemoteAddress $BastionHost -RemotePort $BastionPort -State Established -ErrorAction SilentlyContinue

function Test-WorkerHeartbeat {
$hbFresh = $false
if($SpoolProtocol -eq 'Stream'){
    $descriptor=Join-Path $SpoolDir 'ipc_descriptor.json';$latest=$null;$latestStamp=[DateTime]::MinValue
    try{
        $info=[IO.File]::ReadAllText($descriptor)|ConvertFrom-Json
        if($info.revision -ne 3 -or $info.block_bytes -ne 4096 -or $info.instance -cnotmatch '^[a-f0-9]{32}$' -or $info.worker_sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid stream descriptor'}
        foreach($slot in @('a','b')){
            try{
                $snapshot=[IO.File]::ReadAllText((Join-Path $SpoolDir ('worker_pulse_'+$info.instance+'_'+$slot+'.json')))|ConvertFrom-Json
                $stamp=[DateTime]::Parse($snapshot.last_heartbeat_utc).ToUniversalTime();$age=([DateTime]::UtcNow-$stamp).TotalSeconds
                if($snapshot.instance_id -cne $info.instance -or $snapshot.worker_sha256 -cne $info.worker_sha256 -or $snapshot.spool_protocol -ne 'stream' -or $snapshot.status -notin @('running','stopping','stopped') -or $age -lt 0 -or $age -ge $HeartbeatMaxAgeSec){continue}
                if($stamp -gt $latestStamp -or ($stamp -eq $latestStamp -and $snapshot.status -ne 'running')){$latest=$snapshot;$latestStamp=$stamp}
            }catch{}
        }
        $hbFresh=$null -ne $latest -and $latest.status -eq 'running'
    }catch{}
}elseif (Test-Path $stateFile) {
    $hbFresh = (((Get-Date) - (Get-Item $stateFile).LastWriteTime).TotalSeconds -lt $HeartbeatMaxAgeSec)
} elseif (Test-Path $legacyHb) {
    $hbFresh = (((Get-Date) - (Get-Item $legacyHb).LastWriteTime).TotalSeconds -lt $HeartbeatMaxAgeSec)
}

return $hbFresh
}
$hbFresh=Test-WorkerHeartbeat

if (-not $ForceReconnect -and $conn -and $hbFresh) {
    Write-Output "SESSION_ACTIVE"
    exit 0
}

# Restrict reconnection to the managed RDP profile; preserve unrelated sessions.
$rdpProfile = 'C:\EnclaveGateway\bastion.rdp'
Get-CimInstance Win32_Process -Filter "Name='mstsc.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($rdpProfile) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
Start-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue

for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $conn = Get-NetTCPConnection -RemoteAddress $BastionHost -RemotePort $BastionPort -State Established -ErrorAction SilentlyContinue
    if ($conn -and (Test-WorkerHeartbeat)) {
        Write-Output 'SESSION_RECONNECTED'
        exit 0
    }

}

Write-Error "SESSION_PENDING_WORKER"
exit 124
