param(
    [string]$SpoolDir = "\\tsclient\C\EnclaveGateway\spool",
    [int]$PollIntervalMs = 180
)

[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = "Continue"
$startedAt = Get-Date
$lastHeartbeat = [DateTime]::MinValue

Write-Host "[BastionWorker] In-process RDP VFS agent started (PID $PID, Spool: $SpoolDir)"

while ($true) {
    try {
        if (Test-Path $SpoolDir) {
            $now = Get-Date
            if (($now - $lastHeartbeat).TotalSeconds -ge 2.0) {
                $uptimeSec = [int]($now - $startedAt).TotalSeconds
                $stateObj = @{
                    pid                = $PID
                    user               = "$env:USERDOMAIN\$env:USERNAME"
                    hostname           = $env:COMPUTERNAME
                    uptime_sec         = $uptimeSec
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
                $scriptText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envObj.payload_b64))

                $stdoutStr = ""
                $stderrStr = ""
                $exitCode = 0

                try {
                    $global:LASTEXITCODE = 0
                    $outputItems = & ([scriptblock]::Create($scriptText)) 2>&1
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

                $sw.Stop()
                $resObj = @{
                    tx_id         = $txId
                    exit_code     = $exitCode
                    stdout_b64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stdoutStr))
                    stderr_b64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stderrStr))
                    duration_ms   = [int]$sw.ElapsedMilliseconds
                    timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
                $resJson = ConvertTo-Json $resObj -Compress
                $resTmp = Join-Path $SpoolDir "res_${txId}.tmp"
                $resPath = Join-Path $SpoolDir "res_${txId}.json"
                [IO.File]::WriteAllText($resTmp, $resJson, [Text.Encoding]::UTF8)
                Move-Item $resTmp $resPath -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Start-Sleep -Milliseconds 300
    }
    Start-Sleep -Milliseconds $PollIntervalMs
}
