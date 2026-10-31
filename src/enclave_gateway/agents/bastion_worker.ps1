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
$lastActivity = Get-Date
$isFullLang = ($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage")

if (-not $Global:EnclaveMuxSockets) {
    $Global:EnclaveMuxSockets = if ($isFullLang) { [hashtable]::Synchronized(@{}) } else { @{} }
}

if ($isFullLang -and (-not $Global:EnclaveRunspacePool -or $Global:EnclaveRunspacePool.RunspacePoolStateInfo.State -ne "Opened")) {
    try {
        $maxStreams = [Math]::Max(1, $ParallelStreams)
        $Global:EnclaveRunspacePool = [runspacefactory]::CreateRunspacePool(1, $maxStreams)
        $Global:EnclaveRunspacePool.Open()
    } catch {}
}

# Clean up any orphaned temporary files from a previous interrupted session
if (Test-Path $SpoolDir) {
    Get-ChildItem -Path $SpoolDir -Include "*.tmp", "chunk_*.bin", "pull_*.bin", "ask_*.cmd", "s_*.bin", "egw_stage_*", "egw_pull_*" -File -ErrorAction SilentlyContinue |
        Where-Object { ((Get-Date) - $_.LastWriteTime).TotalMinutes -gt 10 } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

$activeTxJobs = @()

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
        $outLines = @()
        $errLines = @()
        foreach ($item in $outputItems) {
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                $errLines += $item.ToString()
            } elseif ($null -ne $item) {
                $outLines += $item.ToString()
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
    if ($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage") {
        [IO.File]::WriteAllText($resTmp, $resJson, [Text.Encoding]::UTF8)
    } else {
        Set-Content -Path $resTmp -Value $resJson -Encoding UTF8 -NoNewline -Force
    }
    Move-Item $resTmp $resPath -Force -ErrorAction SilentlyContinue
}

Write-Host "[BastionWorker] In-process RDP VFS agent started (PID $PID, Spool: $SpoolDir, ParallelStreams: $ParallelStreams, Mode: $($ExecutionContext.SessionState.LanguageMode))"

try {
    while ($true) {
        try {
            if (Test-Path $SpoolDir) {
                # 1. Reap completed asynchronous RunspacePool transactions without blocking mux_io
                if ($activeTxJobs.Count -gt 0) {
                    $remainingJobs = @()
                    foreach ($job in $activeTxJobs) {
                        if ($job.Handle.IsCompleted) {
                            $durMs = [int]((Get-Date) - $job.StartedAt).TotalMilliseconds
                            try {
                                $resCollection = $job.Pipe.EndInvoke($job.Handle)
                                $resMap = $resCollection[0]
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $job.TxId -ExitCode $resMap.ExitCode -StdoutStr $resMap.StdoutStr -StderrStr $resMap.StderrStr -DurationMs $durMs
                            } catch {
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $job.TxId -ExitCode 1 -StdoutStr "" -StderrStr ($_ | Out-String) -DurationMs $durMs
                            } finally {
                                $job.Pipe.Dispose()
                            }
                            $lastActivity = Get-Date
                        } else {
                            $remainingJobs += $job
                        }
                    }
                    $activeTxJobs = $remainingJobs
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
                        language_mode      = [string]$ExecutionContext.SessionState.LanguageMode
                        uptime_sec         = $uptimeSec
                        parallel_streams   = $ParallelStreams
                        active_mux_streams = $Global:EnclaveMuxSockets.Count
                        active_tx_jobs     = $activeTxJobs.Count
                        last_heartbeat_utc = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                    $stateJson = ConvertTo-Json $stateObj -Compress
                    $stateTmp = Join-Path $SpoolDir "worker_state.tmp"
                    $statePath = Join-Path $SpoolDir "worker_state.json"
                    if ($isFullLang) {
                        [IO.File]::WriteAllText($stateTmp, $stateJson, [Text.Encoding]::UTF8)
                    } else {
                        Set-Content -Path $stateTmp -Value $stateJson -Encoding UTF8 -NoNewline -Force
                    }
                    Move-Item $stateTmp $statePath -Force -ErrorAction SilentlyContinue
                    $lastHeartbeat = $now
                }

                $reqFiles = Get-ChildItem -Path $SpoolDir -Filter "req_*.json" -ErrorAction SilentlyContinue | Sort-Object Name
                foreach ($reqItem in $reqFiles) {
                    $startedTx = Get-Date
                    $rawJson = Get-Content $reqItem.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    if (-not $rawJson) {
                        if (((Get-Date) - $reqItem.LastWriteTime).TotalSeconds -gt 10) {
                            Remove-Item $reqItem.FullName -Force -ErrorAction SilentlyContinue
                        }
                        continue
                    }

                    $envObj = $null
                    try {
                        $envObj = ConvertFrom-Json $rawJson -ErrorAction Stop
                    } catch {
                        if (((Get-Date) - $reqItem.LastWriteTime).TotalSeconds -gt 10) {
                            Remove-Item $reqItem.FullName -Force -ErrorAction SilentlyContinue
                        }
                        continue
                    }
                    Remove-Item $reqItem.FullName -Force -ErrorAction SilentlyContinue
                    $lastActivity = Get-Date

                    $txId = [string]$envObj.tx_id
                    $opType = if ($envObj.op) { [string]$envObj.op } else { "exec" }

                    # Native fast-path for stateful TCP/SOCKS5 multiplexer (zero ScriptBlock compilation overhead)
                    if ($isFullLang -and $envObj.mux_action) {
                        $muxAction = [string]$envObj.mux_action
                        $connId = [string]$envObj.conn_id
                        try {
                            if ($muxAction -eq "open") {
                                $tHost = [string]$envObj.target_host
                                $tPort = [int]$envObj.target_port
                                $tMs = if ($envObj.timeout_ms) { [int]$envObj.timeout_ms } else { 15000 }
                                $client = New-Object System.Net.Sockets.TcpClient
                                $client.NoDelay = $true
                                $client.ReceiveTimeout = $tMs
                                $client.SendTimeout = $tMs
                                $client.Connect($tHost, $tPort)
                                $Global:EnclaveMuxSockets[$connId] = @{
                                    Client     = $client
                                    Stream     = $client.GetStream()
                                    Target     = "${tHost}:${tPort}"
                                    LastActive = (Get-Date)
                                }
                                $durMs = [int]((Get-Date) - $startedTx).TotalMilliseconds
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode 0 -StdoutStr "MUX_OPEN_OK:$connId" -StderrStr "" -DurationMs $durMs
                                continue
                            } elseif ($muxAction -eq "io") {
                                if (-not $Global:EnclaveMuxSockets.ContainsKey($connId)) {
                                    $durMs = [int]((Get-Date) - $startedTx).TotalMilliseconds
                                    Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode 0 -StdoutStr "MUX_EOF:" -StderrStr "" -DurationMs $durMs
                                    continue
                                }
                                $entry = $Global:EnclaveMuxSockets[$connId]
                                $client = $entry.Client
                                $stream = $entry.Stream
                                $entry.LastActive = (Get-Date)
                                $txB64 = [string]$envObj.tx_b64
                                if ($txB64) {
                                    $txBytes = [Convert]::FromBase64String($txB64)
                                    $stream.Write($txBytes, 0, $txBytes.Length)
                                    $stream.Flush()
                                }
                                $maxRead = if ($envObj.max_read_bytes) { [int]$envObj.max_read_bytes } else { 65536 }
                                $waitMs = if ($null -ne $envObj.read_wait_ms) { [int]$envObj.read_wait_ms } else { 100 }
                                $ms = New-Object System.IO.MemoryStream
                                $buf = New-Object byte[] $maxRead
                                $eof = $false
                                $waited = 0
                                while (-not $stream.DataAvailable -and $waited -lt $waitMs) {
                                    if ($client.Client.Poll(1000, [System.Net.Sockets.SelectMode]::SelectRead) -and $client.Client.Available -eq 0) {
                                        $eof = $true
                                        break
                                    }
                                    Start-Sleep -Milliseconds 15
                                    $waited += 15
                                }
                                while ($stream.DataAvailable -and $ms.Length -lt $maxRead) {
                                    $toRead = [Math]::Min($buf.Length, $maxRead - [int]$ms.Length)
                                    $r = $stream.Read($buf, 0, $toRead)
                                    if ($r -le 0) { $eof = $true; break }
                                    $ms.Write($buf, 0, $r)
                                }
                                if (-not $eof -and $client.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead) -and $client.Client.Available -eq 0) {
                                    $eof = $true
                                }
                                $rxB64 = [Convert]::ToBase64String($ms.ToArray())
                                $outLine = if ($eof) {
                                    try { $client.Close() } catch {}
                                    $Global:EnclaveMuxSockets.Remove($connId)
                                    "MUX_EOF:$rxB64"
                                } else {
                                    "MUX_DATA:$rxB64"
                                }
                                $durMs = [int]((Get-Date) - $startedTx).TotalMilliseconds
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode 0 -StdoutStr $outLine -StderrStr "" -DurationMs $durMs
                                continue
                            } elseif ($muxAction -eq "close") {
                                if ($Global:EnclaveMuxSockets.ContainsKey($connId)) {
                                    try { $Global:EnclaveMuxSockets[$connId].Client.Close() } catch {}
                                    $Global:EnclaveMuxSockets.Remove($connId)
                                }
                                $durMs = [int]((Get-Date) - $startedTx).TotalMilliseconds
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode 0 -StdoutStr "MUX_CLOSED" -StderrStr "" -DurationMs $durMs
                                continue
                            }
                        } catch {
                            $durMs = [int]((Get-Date) - $startedTx).TotalMilliseconds
                            Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode 1 -StdoutStr "" -StderrStr ($_ | Out-String) -DurationMs $durMs
                            continue
                        }
                    }

                    $scriptText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envObj.payload_b64))

                    $needsMainRunspace = ($opType -eq "mux") -or ($scriptText -match '\$Global:EnclaveMuxSockets|\$Global:EnclaveRunspacePool')
                    if ($isFullLang -and -not $needsMainRunspace -and $Global:EnclaveRunspacePool -and $Global:EnclaveRunspacePool.RunspacePoolStateInfo.State -eq "Opened") {
                        $ps = [powershell]::Create()
                        $ps.RunspacePool = $Global:EnclaveRunspacePool
                        [void]$ps.AddScript($asyncExecWorker).AddArgument($scriptText)
                        $activeTxJobs += @{
                            TxId      = $txId
                            Pipe      = $ps
                            Handle    = $ps.BeginInvoke()
                            StartedAt = $startedTx
                        }
                        continue
                    }

                    $resMap = & $asyncExecWorker $scriptText
                    $durMs = [int]((Get-Date) - $startedTx).TotalMilliseconds
                    Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode $resMap.ExitCode -StdoutStr $resMap.StdoutStr -StderrStr $resMap.StderrStr -DurationMs $durMs
                }

                # Adaptive burst polling (10ms during active traffic or within 3s of activity; 120ms when idle)
                if ($activeTxJobs.Count -gt 0 -or $Global:EnclaveMuxSockets.Count -gt 0 -or ((Get-Date) - $lastActivity).TotalSeconds -lt 3.0) {
                    Start-Sleep -Milliseconds 10
                } else {
                    Start-Sleep -Milliseconds ([Math]::Min(120, $PollIntervalMs))
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
