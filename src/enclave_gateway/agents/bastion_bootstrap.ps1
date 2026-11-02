param(
    [ValidateSet('Standard','Enterprise','Custom')][string]$Mode = 'Custom',
    [bool]$ProcessIsolation = ($env:OS -eq 'Windows_NT'),
    [bool]$RequireSignedAgents = $true,
    [string]$SourceSpool = "\\tsclient\C\EnclaveGateway\spool",
    [string]$InstallDir = "$env:LOCALAPPDATA\EnclaveGateway",
    [string]$WorkerPath = '',
    [string]$StopFile = '',
    [string]$RuntimeHelper = '',
    [string[]]$TrustedSignerThumbprints = @(),
    [string]$TrustedSignerThumbprintsCsv = '',
    [switch]$AllowUnsignedLab,
    [switch]$RegisterStartup,
    [switch]$UseStartupConfiguration
)
$ErrorActionPreference='Stop'
if ($Mode -eq 'Standard') {
    if (-not $PSBoundParameters.ContainsKey('ProcessIsolation')) {$ProcessIsolation=$false}
    if (-not $PSBoundParameters.ContainsKey('RequireSignedAgents')) {$RequireSignedAgents=$false}
    if ($AllowUnsignedLab -or $RegisterStartup) {throw 'Standard mode is foreground only; use Enterprise for managed persistent startup'}
}
if ($Mode -eq 'Enterprise' -and ($AllowUnsignedLab -or -not $ProcessIsolation -or -not $RequireSignedAgents)) {
    throw 'Enterprise bootstrap cannot disable signatures or native process isolation'
}
if ($UseStartupConfiguration) {
    if ($RegisterStartup -or $AllowUnsignedLab) {throw 'Invalid persistent startup mode'}
    $settings=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'bastion_startup.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($settings.revision -notin @(1,2) -or -not $settings.source_spool -or -not $settings.runtime_helper -or -not $settings.trusted_signers.Count) {throw 'Invalid startup configuration'}
    $Mode=if($settings.revision -eq 2){[string]$settings.mode}else{'Custom'}
    if($Mode -notin @('Enterprise','Custom')){throw 'Persistent startup requires a signed mode'}
    $ProcessIsolation=$true;$RequireSignedAgents=$true
    $SourceSpool=[string]$settings.source_spool
    $WorkerPath=Join-Path $PSScriptRoot 'bastion_worker.ps1'
    $RuntimeHelper=[string]$settings.runtime_helper
    $TrustedSignerThumbprints=@($settings.trusted_signers)
    $TrustedSignerThumbprintsCsv=''
}
if ($AllowUnsignedLab -and $RegisterStartup) { throw 'Unsigned lab mode cannot register persistent startup' }
$trusted=@($TrustedSignerThumbprints)
if ($TrustedSignerThumbprintsCsv) { $trusted+=@($TrustedSignerThumbprintsCsv.Split(',')) }
$trusted=@($trusted | ForEach-Object { $_.Replace(' ','').ToUpperInvariant() })
foreach ($thumbprint in $trusted) {
    if ($thumbprint -notmatch '^[A-F0-9]{40,64}$') { throw 'Invalid trusted signer identifier' }
}
if (-not $RuntimeHelper) {$RuntimeHelper=Join-Path $InstallDir 'bin\egw-runtime.exe'}
$RuntimeHelper=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([Environment]::ExpandEnvironmentVariables($RuntimeHelper))
$workerSrc=if ($WorkerPath) { $WorkerPath } else { Join-Path $SourceSpool 'bastion_worker.ps1' }
if (-not (Test-Path -LiteralPath $workerSrc -PathType Leaf)) { throw 'Worker file is missing' }
function Assert-TrustedScript([string]$Path) {
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -notin $trusted) {
        throw 'Runtime requires a valid signature from an explicitly trusted publisher'
    }
}
if ($RequireSignedAgents -and -not $AllowUnsignedLab) {
    Assert-TrustedScript $workerSrc
    if($Mode -ne 'Custom'){Assert-TrustedScript $PSCommandPath}
}
if ($ProcessIsolation -and -not $AllowUnsignedLab) {Assert-TrustedScript $RuntimeHelper}
if ($RegisterStartup) {
    if(-not $ProcessIsolation -or -not $RequireSignedAgents){throw 'Managed startup requires signed native process isolation'}
    Assert-TrustedScript $PSCommandPath
    foreach ($value in @($SourceSpool,$InstallDir,$RuntimeHelper)) {
        if ($value.IndexOfAny([char[]]@('"',"`r","`n")) -ge 0) { throw 'Invalid startup path' }
    }
    $InstallDir=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([Environment]::ExpandEnvironmentVariables($InstallDir))
    $SourceSpool=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([Environment]::ExpandEnvironmentVariables($SourceSpool))
    $workerDst=Join-Path $InstallDir 'bastion_worker.ps1'
    $bootstrapDst=Join-Path $InstallDir 'bastion_bootstrap.ps1'
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments="-NoProfile -NonInteractive -File `"$bootstrapDst`" -UseStartupConfiguration"
    if ($arguments.Length+$shell.Length -gt 32760) {throw 'Startup command exceeds the process command-line limit'}
    [void][IO.Directory]::CreateDirectory($InstallDir)
    Copy-Item -LiteralPath $workerSrc -Destination $workerDst -Force
    Copy-Item -LiteralPath $PSCommandPath -Destination $bootstrapDst -Force
    Assert-TrustedScript $workerDst
    Assert-TrustedScript $bootstrapDst
    $settings=@{revision=2;mode=$Mode;source_spool=$SourceSpool;runtime_helper=$RuntimeHelper;trusted_signers=$trusted}|ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $InstallDir 'bastion_startup.json'),$settings,(New-Object Text.UTF8Encoding($false)))
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$sid=$identity.User.Value;$accountName=$identity.Name} finally {$identity.Dispose()}
    $taskName="EnclaveBastionWorker_$sid"
    $action=New-ScheduledTaskAction -Execute $shell -Argument $arguments -WorkingDirectory $InstallDir
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
    $reconnectClass=Get-CimClass -Namespace 'Root/Microsoft/Windows/TaskScheduler' -ClassName 'MSFT_TaskSessionStateChangeTrigger'
    $reconnect=New-CimInstance -CimClass $reconnectClass -ClientOnly -Property @{StateChange=[uint32]3;UserId=$accountName;Enabled=$true}
    $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
    $options=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger,$reconnect) -Principal $principal -Settings $options -Force | Out-Null
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'EnclaveBastionWorker' -ErrorAction SilentlyContinue
    # One managed resident instance owns this SID's startup and reconnects.
    # Deployment restarts that instance; it must not launch a second foreground
    # worker alongside the scheduled one.
    Stop-ScheduledTask -TaskName $taskName
    $until=[DateTime]::UtcNow.AddSeconds(10)
    while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
        if ([DateTime]::UtcNow -ge $until) {throw 'Previous managed worker did not stop'}
        Start-Sleep -Milliseconds 100
    }
    Start-ScheduledTask -TaskName $taskName
    @{status='startup_registered';task_name=$taskName;worker_health='requires_fresh_attestation'} | ConvertTo-Json -Compress
    return
}
if ($UseStartupConfiguration -and $SourceSpool.StartsWith('\\tsclient\',[StringComparison]::OrdinalIgnoreCase)) {
    $share=[IO.Path]::GetPathRoot($SourceSpool)
    $until=[DateTime]::UtcNow.AddSeconds(30)
    while(-not (Test-Path -LiteralPath $share)) {
        if([DateTime]::UtcNow -ge $until) {throw 'Redirected startup drive unavailable'}
        Start-Sleep -Milliseconds 200
    }
}
& $workerSrc -Mode $Mode -ProcessIsolation:$ProcessIsolation -SpoolDir $SourceSpool -StopFile $StopFile -RuntimeHelper $RuntimeHelper -TrustedSignerThumbprints $trusted -AllowUnsignedLab:$AllowUnsignedLab
