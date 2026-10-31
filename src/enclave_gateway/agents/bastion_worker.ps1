param(
    [string]$SpoolDir = "\\tsclient\C\EnclaveGateway\spool",
    [int]$PollIntervalMs = 150,
    [int]$ParallelStreams = 4
)

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'BastionWorker requires a policy-approved FullLanguage script; constrained execution is unsupported'
}
if ($ParallelStreams -lt 1 -or $ParallelStreams -gt 64) { throw 'ParallelStreams must be in 1..64' }

[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"
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
        $ErrorActionPreference = "Stop"
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
    $published = $false
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            Move-Item -LiteralPath $resTmp -Destination $resPath -Force -ErrorAction Stop
            $published = $true
            break
        } catch { Start-Sleep -Milliseconds 25 }
    }
    if (-not $published) { throw "Response publication failed for $TxId" }
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
                        if (-not $job.Handle.IsCompleted -and ((Get-Date) - $job.StartedAt).TotalMilliseconds -gt $job.TimeoutMs) {
                            try { $job.Pipe.Stop() } catch {}
                        }
                        if ($job.Handle.IsCompleted) {
                            $durMs = [int]((Get-Date) - $job.StartedAt).TotalMilliseconds
                            try {
                                $resCollection = $job.Pipe.EndInvoke($job.Handle)
                                if ($resCollection.Count -eq 0) { throw 'Transaction ended without an execution result' }
                                $resMap = $resCollection[0]
                            } catch {
                                $resMap = @{ ExitCode = 1; StdoutStr = ''; StderrStr = ($_ | Out-String) }
                            } finally {
                                $job.Pipe.Dispose()
                            }
                            try {
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $job.TxId -ExitCode $resMap.ExitCode -StdoutStr $resMap.StdoutStr -StderrStr $resMap.StderrStr -DurationMs $durMs
                            } catch { Write-Warning "Response pending publication: $($job.TxId)" }
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

                    # Retry publication of complete response files without replaying work.
                    Get-ChildItem -LiteralPath $SpoolDir -Filter 'res_*.tmp' -File -ErrorAction SilentlyContinue | ForEach-Object {
                        try { Move-Item -LiteralPath $_.FullName -Destination ($_.FullName -replace '\.tmp$', '.json') -Force -ErrorAction Stop } catch {}
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
                    # Claim by rename before reading. A sharing violation is retried on
                    # the next scan and must never cause duplicate command execution.
                    $claimPath = "$($reqItem.FullName).processing"
                    try {
                        Move-Item -LiteralPath $reqItem.FullName -Destination $claimPath -ErrorAction Stop
                    } catch { continue }
                    $rawJson = Get-Content -LiteralPath $claimPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    if (-not $rawJson) {
                        if (((Get-Date) - $reqItem.LastWriteTime).TotalSeconds -gt 10) {
                            Remove-Item -LiteralPath $claimPath -Force -ErrorAction SilentlyContinue
                        }
                        continue
                    }

                    $envObj = $null
                    try {
                        $envObj = ConvertFrom-Json $rawJson -ErrorAction Stop
                    } catch {
                        if (((Get-Date) - $reqItem.LastWriteTime).TotalSeconds -gt 10) {
                            Remove-Item -LiteralPath $claimPath -Force -ErrorAction SilentlyContinue
                        }
                        continue
                    }
                    $lastActivity = Get-Date

                    $txId = [string]$envObj.tx_id
                    if ($txId -notmatch '^[A-Za-z0-9_]{1,128}$' -or $reqItem.Name -ne "req_${txId}.json") { continue }
                    $timeoutMs = if ($envObj.timeout_ms) { [int64]$envObj.timeout_ms } else { 120000 }
                    if ($timeoutMs -lt 1 -or $timeoutMs -gt 86400000) { continue }
                    $opType = if ($envObj.op) { [string]$envObj.op } else { "exec" }
                    if ($activeTxJobs.Count -ge (4 * $ParallelStreams) -and -not $envObj.mux_action) {
                        Move-Item -LiteralPath $claimPath -Destination $reqItem.FullName -ErrorAction SilentlyContinue
                        continue
                    }
                    Remove-Item -LiteralPath $claimPath -Force -ErrorAction SilentlyContinue

                    # Native fast-path for stateful TCP/SOCKS5 multiplexer (zero ScriptBlock compilation overhead)
                    if ($isFullLang -and $envObj.mux_action) {
                        $muxAction = [string]$envObj.mux_action
                        $connId = [string]$envObj.conn_id
                        try {
                            if ($muxAction -eq "open") {
                                if ($Global:EnclaveMuxSockets.Count -ge 2048 -or $Global:EnclaveMuxSockets.ContainsKey($connId)) { throw 'Mux connection limit or duplicate identifier' }
                                $tHost = [string]$envObj.target_host
                                $tPort = [int]$envObj.target_port
                                $tMs = if ($envObj.timeout_ms) { [int]$envObj.timeout_ms } else { 15000 }
                                $family = if ($tHost.Contains(':')) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
                                $client = New-Object System.Net.Sockets.TcpClient($family)
                                $client.NoDelay = $true
                                $client.ReceiveTimeout = $tMs
                                $client.SendTimeout = $tMs
                                $connection = $null
                                try {
                                    $connection = $client.BeginConnect($tHost, $tPort, $null, $null)
                                    if (-not $connection.AsyncWaitHandle.WaitOne($tMs)) { throw 'TCP connect timed out' }
                                    $client.EndConnect($connection)
                                } catch { $client.Close(); throw } finally { if ($connection) { $connection.AsyncWaitHandle.Close() } }
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
                                if ($maxRead -lt 1 -or $maxRead -gt 4194304 -or $waitMs -lt 0 -or $waitMs -gt 1000) { throw 'Invalid mux I/O limits' }
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
                                $ms.Dispose()
                                $outLine = if ($eof) {
                                    "MUX_EOF:$rxB64"
                                } else {
                                    "MUX_DATA:$rxB64"
                                }
                                $durMs = [int]((Get-Date) - $startedTx).TotalMilliseconds
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode 0 -StdoutStr $outLine -StderrStr "" -DurationMs $durMs
                                continue
                            } elseif ($muxAction -eq "shutdown_write") {
                                if ($Global:EnclaveMuxSockets.ContainsKey($connId)) {
                                    $Global:EnclaveMuxSockets[$connId].Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
                                }
                                Write-EnclaveResponse -Spool $SpoolDir -TxId $txId -ExitCode 0 -StdoutStr 'MUX_SHUTDOWN_OK' -StderrStr '' -DurationMs 0
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
                            if ($Global:EnclaveMuxSockets.ContainsKey($connId)) {
                                try { $Global:EnclaveMuxSockets[$connId].Client.Close() } catch {}
                                $Global:EnclaveMuxSockets.Remove($connId)
                            }
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
                        try { $handle = $ps.BeginInvoke() } catch { $ps.Dispose(); throw }
                        $activeTxJobs += @{
                            TxId      = $txId
                            Pipe      = $ps
                            Handle    = $handle
                            StartedAt = $startedTx
                            TimeoutMs = $timeoutMs
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
    foreach ($job in $activeTxJobs) {
        try { $job.Pipe.Stop() } catch {} finally { $job.Pipe.Dispose() }
    }
    foreach ($k in @($Global:EnclaveMuxSockets.Keys)) {
        try { $Global:EnclaveMuxSockets[$k].Client.Close() } catch {}
    }
    $Global:EnclaveMuxSockets.Clear()
    if ($Global:EnclaveRunspacePool) {
        try { $Global:EnclaveRunspacePool.Close(); $Global:EnclaveRunspacePool.Dispose() } catch {}
    }
}
