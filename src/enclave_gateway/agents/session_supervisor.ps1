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
    [switch]$ForceReconnect,
    [switch]$ObserveOnly
)

$ErrorActionPreference = "SilentlyContinue"

# Credential updates belong to the native stdin-only credential operation.
# Retain legacy parameters only to fail explicitly instead of silently reconnecting
# with stale credentials or recreating a password-bearing script.
if ($RdpPassword -or $RdpPasswordB64 -or $RdpDomainUser) {
    throw 'Credential refresh requires the approved native credential operation; no script fallback is permitted'
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
    if(-not $hbFresh -and $null -eq $latest){
        try{
            $file=Get-Item -LiteralPath $stateFile -Force -ErrorAction Stop
            $age=([DateTime]::UtcNow-$file.LastWriteTimeUtc).TotalSeconds
            if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 65536 -or
               $age -lt 0 -or $age -ge $HeartbeatMaxAgeSec){return $false}
            $state=[IO.File]::ReadAllText($stateFile)|ConvertFrom-Json
            $hbFresh=$state.status -ceq 'running' -and $state.spool_protocol -ceq 'stream' -and
                $state.execution_profile -ceq 'structured_only' -and $state.structured_backend -ceq 'operator' -and
                $state.instance_id -cmatch '^[a-f0-9]{32}$' -and $state.worker_sha256 -cmatch '^[a-f0-9]{64}$'
            if($hbFresh -and $info -and ($info.instance -cne $state.instance_id -or $info.worker_sha256 -cne $state.worker_sha256)){
                $hbFresh=$false
            }
        }catch{$hbFresh=$false}
    }
}elseif (Test-Path $stateFile) {
    $hbFresh = (((Get-Date) - (Get-Item $stateFile).LastWriteTime).TotalSeconds -lt $HeartbeatMaxAgeSec)
} elseif (Test-Path $legacyHb) {
    $hbFresh = (((Get-Date) - (Get-Item $legacyHb).LastWriteTime).TotalSeconds -lt $HeartbeatMaxAgeSec)
}

return $hbFresh
}
$hbFresh=Test-WorkerHeartbeat

if (($ObserveOnly -or -not $ForceReconnect) -and $conn -and $hbFresh) {
    Write-Output "SESSION_ACTIVE"
    exit 0
}
if ($ObserveOnly) {
    Write-Output 'SESSION_PENDING_OPERATOR: Open or reconnect the approved RDP session, start the adapter, attach OpenSSH, and run egw agent-verify.'
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
