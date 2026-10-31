param(
    [string]$SpoolDir = "\\tsclient\C\EnclaveGateway\spool",
    [int]$PollIntervalMs = 20,
    [int]$ParallelStreams = 4,
    [int]$MaxMuxSessions = 256,
    [int]$MaxRequestsPerTick = 32,
    [int]$MaxTransactionRecords = 100000,
    [string]$StopFile = ""
)

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'BastionWorker requires a policy-approved FullLanguage script; constrained execution is unsupported'
}
if ($ParallelStreams -lt 1 -or $ParallelStreams -gt 64 -or $MaxMuxSessions -lt 1 -or $MaxRequestsPerTick -lt 1 -or $MaxTransactionRecords -lt 1) {
    throw 'Invalid worker resource limits'
}
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
[void][IO.Directory]::CreateDirectory($SpoolDir)
$stateDir = Join-Path $SpoolDir '.transactions'
[void][IO.Directory]::CreateDirectory($stateDir)
$Global:EnclaveMuxSockets = @{}
$pendingMux = New-Object Collections.Generic.List[object]
$activeTxJobs = New-Object Collections.Generic.List[object]
$pool = [runspacefactory]::CreateRunspacePool(1, $ParallelStreams)
$pool.Open()
$clock = [Diagnostics.Stopwatch]::StartNew()
$lastHeartbeat = -2000
$completedCount = 0
$transactionCount = @(Get-ChildItem -LiteralPath $stateDir -Filter '*.json' -File).Count

function Write-DurableText([string]$Path, [string]$Text) {
    $bytes=[Text.Encoding]::UTF8.GetBytes($Text)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Write-State {
    param([string]$TxId, [string]$State)
    $path = Join-Path $stateDir "$TxId.json"
    $temporary = "$path.tmp"
    $newRecord = -not (Test-Path -LiteralPath $path)
    $json = @{ tx_id=$TxId; state=$State; updated_utc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress
    Write-DurableText $temporary $json
    Move-Item -LiteralPath $temporary -Destination $path -Force
    if ($newRecord) { $script:transactionCount++ }
}

function Write-Response {
    param([string]$TxId, [int]$ExitCode=0, [string]$Stdout='', [string]$Stderr='', [int]$DurationMs=0, [string]$State='completed', [bool]$StoreState=$true)
    $result = @{ tx_id=$TxId; exit_code=$ExitCode; state=$State;
        stdout_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Stdout));
        stderr_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Stderr)); duration_ms=$DurationMs }
    $temporary = Join-Path $SpoolDir "res_$TxId.tmp"
    $path = Join-Path $SpoolDir "res_$TxId.json"
    Write-DurableText $temporary ($result | ConvertTo-Json -Compress)
    if ($StoreState) { Write-State $TxId $State }
    # A failed rename is retried by maintenance; execution is never replayed.
    try { Move-Item -LiteralPath $temporary -Destination $path -Force -ErrorAction Stop } catch {}
    $script:completedCount++
}

function Close-Mux {
    param([string]$ConnectionId)
    if ($Global:EnclaveMuxSockets.ContainsKey($ConnectionId)) {
        try { $Global:EnclaveMuxSockets[$ConnectionId].Client.Close() } catch {}
        $Global:EnclaveMuxSockets.Remove($ConnectionId)
    }
}

$execute = {
    param([string]$ScriptText)
    $ErrorActionPreference = 'Stop'
    $global:LASTEXITCODE = 0
    try {
        $items = @(& ([scriptblock]::Create($ScriptText)) 2>&1)
        $outLines = New-Object Collections.Generic.List[string]
        $errLines = New-Object Collections.Generic.List[string]
        foreach ($item in $items) {
            if ($item -is [Management.Automation.ErrorRecord]) { $errLines.Add($item.ToString()) }
            elseif ($null -ne $item) { $outLines.Add($item.ToString()) }
        }
        return @{ ExitCode=[int]$LASTEXITCODE; Stdout=($outLines -join "`n"); Stderr=($errLines -join "`n") }
    } catch { return @{ ExitCode=1; Stdout=''; Stderr=($_ | Out-String) } }
}

try {
    while (-not $StopFile -or -not (Test-Path -LiteralPath $StopFile)) {
        # Cancellation files have priority over new work. They contain no code.
        foreach ($cancelFile in @(Get-ChildItem -LiteralPath $SpoolDir -Filter 'cancel_*.json' -File | Select-Object -First $MaxRequestsPerTick)) {
            try {
                $cancel = Get-Content -LiteralPath $cancelFile.FullName -Raw | ConvertFrom-Json
                $cancelId = [string]$cancel.tx_id
                if ($cancelId -notmatch '^[A-Za-z0-9_-]{1,128}$' -or $cancelFile.Name -ne "cancel_$cancelId.json") { continue }
                [IO.File]::WriteAllText((Join-Path $stateDir "$cancelId.cancel"), '')
                foreach ($job in @($activeTxJobs.ToArray())) {
                    if ($job.TxId -eq $cancelId -and -not $job.Cancelled) {
                        $job.Cancelled=$true
                        $job.StopHandle=$job.Pipe.BeginStop($null, $null)
                    }
                }
                foreach ($job in @($pendingMux.ToArray())) { if ($job.TxId -eq $cancelId) { $job.Cancelled=$true } }
            } finally { Remove-Item -LiteralPath $cancelFile.FullName -Force -ErrorAction SilentlyContinue }
        }

        # Reap shell pipelines without waiting for incomplete work.
        foreach ($job in @($activeTxJobs.ToArray())) {
            if (-not $job.Handle.IsCompleted -and $job.Timer.ElapsedMilliseconds -ge $job.TimeoutMs -and -not $job.Cancelled) {
                $job.Cancelled=$true
                $job.StopHandle=$job.Pipe.BeginStop($null, $null)
            }
            if (-not $job.Handle.IsCompleted) { continue }
            $activeTxJobs.Remove($job) | Out-Null
            try {
                $values=$job.Pipe.EndInvoke($job.Handle)
                if ($job.Cancelled) { throw 'Execution interrupted; external effects may continue' }
                if ($values.Count -ne 1) { throw 'Execution ended without a result' }
                $value=$values[0]
                $state=if ($value.ExitCode -eq 0) { 'completed' } else { 'failed' }
                Write-Response $job.TxId $value.ExitCode $value.Stdout $value.Stderr ([int]$job.Timer.ElapsedMilliseconds) $state
            } catch {
                $state=if ($job.Cancelled) { 'indeterminate' } else { 'failed' }
                $code=if ($job.Cancelled) { 125 } else { 1 }
                Write-Response $job.TxId $code '' ($_ | Out-String) ([int]$job.Timer.ElapsedMilliseconds) $state
            } finally {
                if ($job.StopHandle -and $job.StopHandle.IsCompleted) { try { $job.Pipe.EndStop($job.StopHandle) } catch {} }
                $job.Pipe.Dispose()
            }
        }

        # One bounded nonblocking turn per connection. Slow connects/writers never
        # hold the main dispatcher while another connection is ready.
        foreach ($job in @($pendingMux.ToArray())) {
            $done=$false
            try {
                if ($job.Cancelled) { throw 'Mux request cancelled' }
                if ($job.Timer.ElapsedMilliseconds -ge $job.TimeoutMs) { throw 'Mux request deadline expired' }
                $entry=$Global:EnclaveMuxSockets[$job.ConnectionId]
                if (-not $entry) { throw 'Mux session closed' }
                if ($job.Action -eq 'open') {
                    if (-not $job.ConnectHandle.IsCompleted) { continue }
                    $entry.Client.EndConnect($job.ConnectHandle)
                    $entry.Client.NoDelay=$true
                    $entry.Client.Client.Blocking=$false
                    $entry.State='open'
                    Write-Response $job.TxId 0 "MUX_OPEN_OK:$($job.ConnectionId)" '' ([int]$job.Timer.ElapsedMilliseconds)
                    $done=$true
                } else {
                    $socket=$entry.Client.Client
                    if ($job.Offset -lt $job.Bytes.Length -and $socket.Poll(0, [Net.Sockets.SelectMode]::SelectWrite)) {
                        try {
                            $count=$socket.Send($job.Bytes, $job.Offset, [Math]::Min(16384, $job.Bytes.Length-$job.Offset), [Net.Sockets.SocketFlags]::None)
                            if ($count -le 0) { throw 'Mux send made no progress' }
                            $job.Offset+=$count
                        } catch [Net.Sockets.SocketException] {
                            if ($_.Exception.SocketErrorCode -notin @([Net.Sockets.SocketError]::WouldBlock, [Net.Sockets.SocketError]::IOPending, [Net.Sockets.SocketError]::NoBufferSpaceAvailable)) { throw }
                        }
                    }
                    if (-not $entry.ReadEof -and $job.Receive.Length -lt $job.MaxRead -and $socket.Poll(0, [Net.Sockets.SelectMode]::SelectRead)) {
                        $buffer=New-Object byte[] ([Math]::Min(16384, $job.MaxRead-[int]$job.Receive.Length))
                        try {
                            $count=$socket.Receive($buffer, 0, $buffer.Length, [Net.Sockets.SocketFlags]::None)
                            if ($count -eq 0) { $entry.ReadEof=$true } else { $job.Receive.Write($buffer, 0, $count) }
                        } catch [Net.Sockets.SocketException] {
                            if ($_.Exception.SocketErrorCode -ne [Net.Sockets.SocketError]::WouldBlock) { throw }
                        }
                    }
                    if ($job.Offset -eq $job.Bytes.Length) {
                        if ($job.ReadStarted -lt 0) { $job.ReadStarted=$job.Timer.ElapsedMilliseconds }
                        if ($entry.ReadEof -or $job.Receive.Length -gt 0 -or ($job.Timer.ElapsedMilliseconds-$job.ReadStarted) -ge $job.WaitMs) {
                            $prefix=if ($entry.ReadEof) { 'MUX_EOF:' } else { 'MUX_DATA:' }
                            $output=$prefix + [Convert]::ToBase64String($job.Receive.ToArray())
                            Write-Response $job.TxId 0 $output '' ([int]$job.Timer.ElapsedMilliseconds)
                            $done=$true
                        }
                    }
                }
                $entry.LastActive=$clock.ElapsedMilliseconds
            } catch {
                Close-Mux $job.ConnectionId
                Write-Response $job.TxId 1 '' ($_ | Out-String) ([int]$job.Timer.ElapsedMilliseconds) 'failed'
                $done=$true
            } finally {
                if ($done) {
                    if ($job.ConnectHandle) { $job.ConnectHandle.AsyncWaitHandle.Close() }
                    if ($job.Receive) { $job.Receive.Dispose() }
                    if ($Global:EnclaveMuxSockets.ContainsKey($job.ConnectionId)) { $Global:EnclaveMuxSockets[$job.ConnectionId].Busy=$false }
                    $pendingMux.Remove($job) | Out-Null
                }
            }
        }

        foreach ($file in @(Get-ChildItem -LiteralPath $SpoolDir -Filter 'req_*.json' -File | Sort-Object Name | Select-Object -First $MaxRequestsPerTick)) {
            $claim="$($file.FullName).processing"
            try { Move-Item -LiteralPath $file.FullName -Destination $claim -ErrorAction Stop } catch { continue }
            $txId=''
            try {
                if ($file.Length -gt 8388608) { throw 'Envelope exceeds size limit' }
                $request=Get-Content -LiteralPath $claim -Raw -Encoding UTF8 | ConvertFrom-Json
                $txId=[string]$request.tx_id
                if ($txId -notmatch '^[A-Za-z0-9_-]{1,128}$' -or $file.Name -ne "req_$txId.json") { throw 'Invalid transaction identifier' }
                if (Test-Path -LiteralPath (Join-Path $stateDir "$txId.cancel")) {
                    Write-Response $txId 125 '' 'Cancelled before dispatch' 0 'cancelled'
                    continue
                }
                $stateFile=Join-Path $stateDir "$txId.json"
                if (Test-Path -LiteralPath $stateFile) {
                    # Never execute a reused request id, including after a restart.
                    if (-not (Test-Path -LiteralPath (Join-Path $SpoolDir "res_$txId.json"))) {
                        Write-Response $txId 125 '' 'Existing transaction; query the Host journal' 0 'indeterminate'
                    }
                    continue
                }
                if ($transactionCount -ge $MaxTransactionRecords) {
                    Write-Response $txId 75 '' 'Transaction capacity reached; explicit spool archival is required' 0 'failed' $false
                    continue
                }
                $timeout=if ($request.timeout_ms) { [int]$request.timeout_ms } else { 120000 }
                if ($timeout -lt 1 -or $timeout -gt 86400000) { throw 'Invalid request timeout' }
                $action=[string]$request.mux_action
                if (-not $action -and $activeTxJobs.Count -ge 4*$ParallelStreams) {
                    Move-Item -LiteralPath $claim -Destination $file.FullName
                    continue
                }
                Write-State $txId 'running'
                if ($action) {
                    $connectionId=[string]$request.conn_id
                    if ($connectionId -notmatch '^mux_[0-9a-f]+$' -and $action -ne 'close_all') { throw 'Invalid mux identifier' }
                    if ($action -eq 'open') {
                        if ($Global:EnclaveMuxSockets.Count -ge $MaxMuxSessions -or $Global:EnclaveMuxSockets.ContainsKey($connectionId)) { throw 'Mux session limit or duplicate id' }
                        $hostName=[string]$request.target_host
                        $port=[int]$request.target_port
                        if (-not $hostName -or $port -lt 1 -or $port -gt 65535) { throw 'Invalid mux endpoint' }
                        $family=if ($hostName.Contains(':')) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
                        $client=New-Object Net.Sockets.TcpClient($family)
                        try { $handle=$client.BeginConnect($hostName, $port, $null, $null) } catch { $client.Close(); throw }
                        $Global:EnclaveMuxSockets[$connectionId]=@{ Client=$client; State='connecting'; Busy=$true; ReadEof=$false; LastActive=$clock.ElapsedMilliseconds }
                        $pendingMux.Add(@{ TxId=$txId; ConnectionId=$connectionId; Action='open'; ConnectHandle=$handle; Timer=[Diagnostics.Stopwatch]::StartNew(); TimeoutMs=$timeout; Cancelled=$false; Receive=$null })
                    } elseif ($action -eq 'io') {
                        if (-not $Global:EnclaveMuxSockets.ContainsKey($connectionId)) { Write-Response $txId 0 'MUX_EOF:'; continue }
                        $entry=$Global:EnclaveMuxSockets[$connectionId]
                        if ($entry.Busy -or $entry.State -ne 'open') { throw 'Concurrent I/O on one mux session is not supported' }
                        $bytes=[Convert]::FromBase64String([string]$request.tx_b64)
                        $maxRead=if ($request.max_read_bytes) { [int]$request.max_read_bytes } else { 65536 }
                        $wait=if ($null -ne $request.read_wait_ms) { [int]$request.read_wait_ms } else { 100 }
                        if ($bytes.Length -gt 1048576 -or $maxRead -lt 1 -or $maxRead -gt 4194304 -or $wait -lt 0 -or $wait -gt 1000) { throw 'Invalid mux buffer limits' }
                        $entry.Busy=$true
                        $pendingMux.Add(@{ TxId=$txId; ConnectionId=$connectionId; Action='io'; ConnectHandle=$null; Timer=[Diagnostics.Stopwatch]::StartNew(); TimeoutMs=$timeout; Cancelled=$false;
                            Bytes=$bytes; Offset=0; MaxRead=$maxRead; WaitMs=$wait; ReadStarted=-1; Receive=(New-Object IO.MemoryStream) })
                    } elseif ($action -eq 'close_all') {
                        foreach ($id in @($Global:EnclaveMuxSockets.Keys)) { Close-Mux $id }
                        Write-Response $txId 0 'MUX_CLOSED_ALL'
                    } elseif ($action -eq 'close') {
                        Close-Mux $connectionId
                        Write-Response $txId 0 'MUX_CLOSED'
                    } elseif ($action -eq 'shutdown_write') {
                        if ($Global:EnclaveMuxSockets.ContainsKey($connectionId)) { $Global:EnclaveMuxSockets[$connectionId].Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send) }
                        Write-Response $txId 0 'MUX_SHUTDOWN_OK'
                    } else { throw 'Unsupported mux action' }
                } else {
                    $scriptText=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$request.payload_b64))
                    if ($scriptText -match '\$Global:EnclaveMuxSockets|\$Global:EnclaveRunspacePool') { throw 'Worker state is accessible only through structured mux operations' }
                    $pipe=[powershell]::Create()
                    $pipe.RunspacePool=$pool
                    [void]$pipe.AddScript($execute).AddArgument($scriptText)
                    try { $handle=$pipe.BeginInvoke() } catch { $pipe.Dispose(); throw }
                    $activeTxJobs.Add(@{ TxId=$txId; Pipe=$pipe; Handle=$handle; StopHandle=$null; Timer=[Diagnostics.Stopwatch]::StartNew(); TimeoutMs=$timeout; Cancelled=$false })
                }
            } catch {
                if ($txId -match '^[A-Za-z0-9_-]{1,128}$') { Write-Response $txId 1 '' ($_ | Out-String) 0 'failed' }
            } finally { Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue }
        }

        if ($clock.ElapsedMilliseconds-$lastHeartbeat -ge 2000) {
            foreach ($file in @(Get-ChildItem -LiteralPath $SpoolDir -Filter 'res_*.tmp' -File)) {
                try { Move-Item -LiteralPath $file.FullName -Destination ($file.FullName -replace '\.tmp$', '.json') -Force } catch {}
            }
            foreach ($id in @($Global:EnclaveMuxSockets.Keys)) {
                if (-not $Global:EnclaveMuxSockets[$id].Busy -and $clock.ElapsedMilliseconds-$Global:EnclaveMuxSockets[$id].LastActive -gt 300000) { Close-Mux $id }
            }
            Get-ChildItem -LiteralPath $SpoolDir -Filter 'res_*.json' -File | Where-Object { $_.Length -eq 0 -or ((Get-Date)-$_.LastWriteTime).TotalSeconds -gt 300 } | Remove-Item -Force -ErrorAction SilentlyContinue
            $self=[Diagnostics.Process]::GetCurrentProcess()
            $state=@{ working_set_bytes=$self.WorkingSet64; handles=$self.HandleCount; threads=$self.Threads.Count; pid=$PID; language_mode=[string]$ExecutionContext.SessionState.LanguageMode; uptime_sec=[int]$clock.Elapsed.TotalSeconds;
                parallel_streams=$ParallelStreams; active_mux_streams=$Global:EnclaveMuxSockets.Count; active_tx_jobs=$activeTxJobs.Count;
                pending_mux=$pendingMux.Count; completed_transactions=$completedCount; transaction_records=$transactionCount; transaction_capacity=$MaxTransactionRecords; last_heartbeat_utc=(Get-Date).ToUniversalTime().ToString('o') }
            $self.Dispose()
            $temporary=Join-Path $SpoolDir 'worker_state.tmp'
            [IO.File]::WriteAllText($temporary, ($state | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $temporary -Destination (Join-Path $SpoolDir 'worker_state.json') -Force -ErrorAction SilentlyContinue
            $lastHeartbeat=$clock.ElapsedMilliseconds
        }
        Start-Sleep -Milliseconds ([Math]::Max(1, [Math]::Min($PollIntervalMs, 50)))
    }
} finally {
    foreach ($job in @($activeTxJobs.ToArray())) { try { $job.Pipe.Stop() } catch {} finally { $job.Pipe.Dispose() } }
    foreach ($job in @($pendingMux.ToArray())) {
        if ($job.ConnectHandle) { $job.ConnectHandle.AsyncWaitHandle.Close() }
        if ($job.Receive) { $job.Receive.Dispose() }
    }
    foreach ($id in @($Global:EnclaveMuxSockets.Keys)) { Close-Mux $id }
    $pool.Close()
    $pool.Dispose()
}
