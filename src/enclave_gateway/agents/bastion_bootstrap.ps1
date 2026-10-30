param(
    [string]$SourceSpool = "\\tsclient\C\EnclaveGateway\spool",
    [string]$InstallDir = "$env:LOCALAPPDATA\EnclaveGateway"
)

Set-ExecutionPolicy Bypass -Scope Process -Force
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

$workerSrc = Join-Path $SourceSpool "bastion_worker.ps1"
$workerDst = Join-Path $InstallDir "bastion_worker.ps1"
if (Test-Path $workerSrc) {
    Copy-Item $workerSrc $workerDst -Force
}

$runReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$launchCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$workerDst`" -SpoolDir `"$SourceSpool`""
Set-ItemProperty -Path $runReg -Name "EnclaveBastionWorker" -Value $launchCmd

& $workerDst -SpoolDir $SourceSpool
