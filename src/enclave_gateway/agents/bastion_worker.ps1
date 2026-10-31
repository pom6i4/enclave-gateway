param(
    [string]$SpoolDir = "\\tsclient\C\EnclaveGateway\spool",
    [int]$PollIntervalMs = 150,
    [int]$ParallelStreams = 4
)

[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = "Continue"
Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
$startedAt = Get-Date
$lastHeartbeat = [DateTime]::MinValue

if (-not $Global:EnclaveMuxSockets) {
    $Global:EnclaveMuxSockets = [hashtable]::Synchronized(@{})
}

if (-not $Global:EnclaveRunspacePool -or $Global:EnclaveRunspacePool.RunspacePoolStateInfo.State -ne "Opened") {
    $maxStreams = [Math]::Max(1, $ParallelStreams)
    $Global:EnclaveRunspacePool = [runspacefactory]::CreateRunspacePool(1, $maxStreams)
    $Global:EnclaveRunspacePool.Open()
}

# Clean up any orphaned temporary files from a previous interrupted session
if (Test-Path $SpoolDir) {
    Get-ChildItem -Path $SpoolDir -Include "*.tmp", "chunk_*.bin", "pull_*.bin", "ask_*.cmd", "s_*.bin", "egw_stage_*", "egw_pull_*" -File -ErrorAction SilentlyContinue |
        Where-Object { ((Get-Date) - $_.LastWriteTime).TotalMinutes -gt 10 } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

$activeTxJobs = New-Object System.Collections.Generic.List[object]

$asyncExecWorker = {
    param([string]$ScriptText)
    $stdoutStr = ""
    $stderrStr = ""
    $exitCode = 0
    try {
        $global:LASTEXITCODE = 0
        $outputItems = & ([scriptblock]::Create($ScriptText)) 2>&1
        if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
            $exitCode = [int]$LASTEXITCODE
        }
        $outLines = New-Object System.Collections.Generic.List[string]
        $errLines = New-Object System.Collections.Generic.List[string]
        foreach ($item in $outputItems) {
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                $errLines.Add($item.ToString())
            } elseif ($null -ne $item) {
                $outLines.Add($item.ToString())
            }
        }
        $stdoutStr = ($outLines -join "`n")
        $stderrStr = ($errLines -join "`n")
    } catch {
        $stderrStr = ($_ | Out-String)
        if ($exitCode -eq 0) { $exitCode = 1 }
    }
    return @{
        ExitCode  = $exitCode
        StdoutStr = $stdoutStr
        StderrStr = $stderrStr
    }
}

function Write-EnclaveResponse {
    param(
        [string]$Spool,
        [string]$TxId,
        [int]$ExitCode,
        [string]$StdoutStr,
        [string]$StderrStr,
        [int]$DurationMs
    )
    $resObj = @{
        tx_id         = $TxId
        exit_code     = $ExitCode
        stdout_b64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($StdoutStr))
        stderr_b64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($StderrStr))
        duration_ms   = $DurationMs
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $resJson = ConvertTo-Json $resObj -Compress
    $resTmp = Join-Path $Spool "res_${TxId}.tmp"
    $resPath = Join-Path $Spool "res_${TxId}.json"
    [IO.File]::WriteAllText($resTmp, $resJson, [Text.Encoding]::UTF8)
    Move-Item $resTmp $resPath -Force -ErrorAction SilentlyContinue
}

Write-Host "[BastionWorker] In-process RDP VFS agent started (PID $PID, Spool: $SpoolDir, ParallelStreams: $ParallelStreams)"

try {
    while ($true) {
        try {
            if (Test-Path $SpoolDir) {
                # 1. Reap completed asynchronous RunspacePool transactions without blocking mux_io
                for ($j = $activeTxJobs.Count - 1; $j -ge 0; $j--) {
                    $job = $activeTxJobs[$j]
                    if ($job.Handle.IsCompleted) {
                        $job.Sw.Stop()
                        try {
                            $resCollection = $job.Pipe.EndInvoke($job.Handle)
                            $resMap = $resCollection[0]
                            Write-EnclaveResponse -Spool $SpoolDir -TxId $job.TxId -ExitCode $resMap.ExitCode -StdoutStr $resMap.StdoutStr -StderrStr $resMap.StderrStr -DurationMs ([int]$job.Sw.ElapsedMilliseconds)
                        } catch {
                            Write-EnclaveResponse -Spool $SpoolDir -TxId $job.TxId -ExitCode 1 -StdoutStr "" -StderrStr ($_ | Out-String) -DurationMs ([int]$job.Sw.ElapsedMilliseconds)
                        } finally {
                            $job.Pipe.Dispose()
                            $activeTxJobs.RemoveAt($j)
                        }
                    }
                }

                $now = Get-Date
                if (($now - $lastHeartbeat).TotalSeconds -ge 2.0) {
                    # Reap idle multiplexed TCP sockets older than 300s of inactivity
                    $staleIds = @()
                    foreach ($k in $Global:EnclaveMuxSockets.Keys) {
                        $entry = $Global:EnclaveMuxSockets[$k]
                        if ($entry -and (($now - $entry.LastActive).TotalSeconds -gt 300)) {
                            $staleIds += $k
                        }
                    }
                    foreach ($sid in $staleIds) {
                        try { $Global:EnclaveMuxSockets[$sid].Client.Close() } catch {}
                        $Global:EnclaveMuxSockets.Remove($sid)
                    }

                    # Reap consumed (0-byte truncated) or stale res_*.json envelopes
                    Get-ChildItem -Path $SpoolDir -Filter "res_*.json" -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -eq 0 -or (($now - $_.LastWriteTime).TotalSeconds -gt 60) } |
                        Remove-Item -Force -ErrorAction SilentlyContinue

                    $uptimeSec = [int]($now - $startedAt).TotalSeconds
                    $stateObj = @{
                        pid                = $PID
                        user               = "$env:USERDOMAIN\$env:USERNAME"
                        hostname           = $env:COMPUTERNAME
                        uptime_sec         = $uptimeSec
                        parallel_streams   = $ParallelStreams
                        active_mux_streams = $Global:EnclaveMuxSockets.Count
                        active_tx_jobs     = $activeTxJobs.Count
                        last_heartbeat_utc = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                    $stateJson = ConvertTo-Json $stateObj -Compress
                    $stateTmp = Join-Path $SpoolDir "worker_state.tmp"
                    $statePath = Join-Path $SpoolDir "worker_state.json"
                    [IO.File]::WriteAllText($stateTmp, $stateJson, [Text.Encoding]::UTF8)
                    Move-Item $stateTmp $statePath -Force -ErrorAction SilentlyContinue
                    $lastHeartbeat = $now
                }

                $reqFiles = Get-ChildItem -Path $SpoolDir -Filter "req_*.json" -ErrorAction SilentlyContinue | Sort-Object Name
                foreach ($reqItem in $reqFiles) {
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    $rawJson = Get-Content $reqItem.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    Remove-Item $reqItem.FullName -Force -ErrorAction SilentlyContinue
                    if (-not $rawJson) { continue }

                    $envObj = ConvertFrom-Json $rawJson
                    $txId = $envObj.tx_id
                    $opType = if ($envObj.op) { [string]$envObj.op } else { "exec" }
                    $scriptText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envObj.payload_b64))

                    $needsMainRunspace = ($opType -eq "mux") -or ($scriptText -match '\$Global:EnclaveMuxSockets|\$Global:EnclaveRunspacePool')
                    if (-not $needsMainRunspace -and $Global:EnclaveRunspacePool -and $Global:EnclaveRunspacePool.RunspacePoolStateInfo.State -eq "Opened") {
                        $ps = [powershell]::Create()
                        $ps.RunspacePool = $Global:EnclaveRunspacePool
                        [void]$ps.AddScript($asyncExecWorker).AddArgument($scriptText)
                        $activeTxJobs.Add(@{
                            TxId   = $txId
                            Pipe   = $ps
                            Handle = $ps.BeginInvoke()
                            Sw     = $sw
                        })
                        continue
                    }

                    $resMap = & $asyncExecWorker $scriptText
                    $sw.Stop()
                    Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode $resMap.ExitCode -StdoutStr $resMap.StdoutStr -StderrStr $resMap.StderrStr -DurationMs ([int]$sw.ElapsedMilliseconds)
                }

                # Event-driven FileSystemWatcher wait with short-poll fallback
                if ($activeTxJobs.Count -gt 0) {
                    Start-Sleep -Milliseconds 15
                } else {
                    try {
                        $fsw = New-Object System.IO.FileSystemWatcher($SpoolDir, "req_*.json")
                        [void]$fsw.WaitForChanged([System.IO.WatcherChangeTypes]::Created -bor [System.IO.WatcherChangeTypes]::Renamed, $PollIntervalMs)
                        $fsw.Dispose()
                    } catch {
                        Start-Sleep -Milliseconds 30
                    }
                }
            } else {
                Start-Sleep -Milliseconds $PollIntervalMs
            }
        } catch {
            Start-Sleep -Milliseconds 150
        }
    }
} finally {
    foreach ($k in @($Global:EnclaveMuxSockets.Keys)) {
        try { $Global:EnclaveMuxSockets[$k].Client.Close() } catch {}
    }
    $Global:EnclaveMuxSockets.Clear()
    if ($Global:EnclaveRunspacePool) {
        try { $Global:EnclaveRunspacePool.Close(); $Global:EnclaveRunspacePool.Dispose() } catch {}
    }
}
