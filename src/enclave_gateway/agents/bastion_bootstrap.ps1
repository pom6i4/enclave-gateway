param(
    [string]$SourceSpool = "\\tsclient\C\EnclaveGateway\spool",
    [string]$InstallDir = "$env:LOCALAPPDATA\EnclaveGateway",
    [switch]$RegisterStartup
)

Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue

$workerSrc = Join-Path $SourceSpool "bastion_worker.ps1"

# Only touch local disk and HKCU Run registry key if explicitly requested (-RegisterStartup)
if ($RegisterStartup) {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }
    $workerDst = Join-Path $InstallDir "bastion_worker.ps1"
    if (Test-Path $workerSrc) {
        Copy-Item $workerSrc $workerDst -Force
    }
    $runReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $launchCmd = "powershell.exe -NoProfile -File `"$workerDst`" -SpoolDir `"$SourceSpool`""
    Set-ItemProperty -Path $runReg -Name "EnclaveBastionWorker" -Value $launchCmd
    & $workerDst -SpoolDir $SourceSpool
    exit $LASTEXITCODE
}

# Zero-disk default: load and execute bastion_worker.ps1 directly in memory from the redirected VFS spool
if (-not (Test-Path $workerSrc)) {
    Write-Error "BastionWorker script not found on VFS spool: $workerSrc"
    exit 1
}
$workerCode = [IO.File]::ReadAllText($workerSrc, [Text.Encoding]::UTF8)
& ([scriptblock]::Create($workerCode)) -SpoolDir $SourceSpool
