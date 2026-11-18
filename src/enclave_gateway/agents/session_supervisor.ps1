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

function Read-WorkerMetadata {
    param([string]$Path,[int]$MaxBytes=65536)
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt $MaxBytes){throw 'Invalid worker metadata'}
    $stamp=$item.LastWriteTimeUtc
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try{
        if($file.Length -gt $MaxBytes){throw 'Oversized worker metadata'}
        $reader=[IO.StreamReader]::new($file)
        try{
            $buffer=New-Object char[] ($MaxBytes+1)
            $count=$reader.ReadBlock($buffer,0,$buffer.Length)
            if($count -gt $MaxBytes){throw 'Oversized worker metadata'}
            $value=([string]::new($buffer,0,$count))|ConvertFrom-Json -ErrorAction Stop
        }finally{$reader.Dispose()}
    }finally{$file.Dispose()}
    $after=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if(($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $after.LastWriteTimeUtc -ne $stamp){throw 'Worker metadata changed during observation'}
    return @{value=$value;stamp=$stamp}
}

function Test-WorkerHeartbeatSnapshot {
$hbFresh = $false
if($SpoolProtocol -eq 'Stream'){
    $descriptor=Join-Path $SpoolDir 'ipc_descriptor.json';$info=$null
    $latest=$null;$latestStamp=[DateTime]::MinValue
    if([IO.File]::Exists($descriptor)){
        try{
            $candidate=(Read-WorkerMetadata $descriptor 4096).value
            if($candidate.revision -ne 3 -or $candidate.block_bytes -ne 4096 -or $candidate.instance -cnotmatch '^[a-f0-9]{32}$' -or $candidate.worker_sha256 -cnotmatch '^[a-f0-9]{64}$'){return $false}
            $info=$candidate
        }catch{return $false}
        foreach($slot in @('a','b')){
            try{
                $snapshot=(Read-WorkerMetadata (Join-Path $SpoolDir ('worker_pulse_'+$info.instance+'_'+$slot+'.json'))).value
                # PowerShell editions can deserialize ISO timestamps either as
                # strings or DateTime. Do not stringify a typed UTC/local value.
                $stamp=if($snapshot.last_heartbeat_utc -is [DateTime]){
                    $snapshot.last_heartbeat_utc.ToUniversalTime()
                }else{
                    [DateTimeOffset]::Parse($snapshot.last_heartbeat_utc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
                }
                $age=([DateTime]::UtcNow-$stamp).TotalSeconds
                if($snapshot.instance_id -cne $info.instance -or $snapshot.worker_sha256 -cne $info.worker_sha256 -or $snapshot.spool_protocol -ne 'stream' -or $snapshot.status -notin @('running','stopping','stopped') -or $age -lt -5 -or $age -ge $HeartbeatMaxAgeSec){continue}
                if($stamp -gt $latestStamp -or ($stamp -eq $latestStamp -and $snapshot.status -ne 'running')){$latest=$snapshot;$latestStamp=$stamp}
            }catch{}
        }
    }
    # A fresh stopping/stopped pulse must not fall back to an older running state.
    if($null -ne $latest){return $latest.status -eq 'running'}
    try{
        $metadata=Read-WorkerMetadata $stateFile
        $age=([DateTime]::UtcNow-$metadata.stamp).TotalSeconds
        if($age -lt -5 -or $age -ge $HeartbeatMaxAgeSec){return $false}
        $state=$metadata.value
        $hbFresh=$state.status -ceq 'running' -and $state.spool_protocol -ceq 'stream' -and
            $state.execution_profile -ceq 'structured_only' -and $state.structured_backend -ceq 'operator' -and
            $state.instance_id -cmatch '^[a-f0-9]{32}$' -and $state.worker_sha256 -cmatch '^[a-f0-9]{64}$'
        if($hbFresh -and $info -and ($info.instance -cne $state.instance_id -or $info.worker_sha256 -cne $state.worker_sha256)){
            $hbFresh=$false
        }
    }catch{$hbFresh=$false}
}elseif (Test-Path $stateFile) {
    $hbFresh = (((Get-Date) - (Get-Item $stateFile).LastWriteTime).TotalSeconds -lt $HeartbeatMaxAgeSec)
} elseif (Test-Path $legacyHb) {
    $hbFresh = (((Get-Date) - (Get-Item $legacyHb).LastWriteTime).TotalSeconds -lt $HeartbeatMaxAgeSec)
}
return $hbFresh
}

function Test-WorkerHeartbeat {
    # Transient publication can briefly expose a missing or partial snapshot.
    # Retry observations only; never reconnect an operator session here.
    for($attempt=0;$attempt -lt 3;$attempt++){
        if(Test-WorkerHeartbeatSnapshot){return $true}
        if($SpoolProtocol -ne 'Stream'){break}
        if($attempt -lt 2){Start-Sleep -Milliseconds 100}
    }
    return $false
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
