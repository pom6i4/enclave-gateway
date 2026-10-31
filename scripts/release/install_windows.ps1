param([Parameter(Mandatory=$true)][string]$PackageDir, [Parameter(Mandatory=$true)][string[]]$TrustedThumbprints,
      [string]$InstallDir="$env:LOCALAPPDATA\EnclaveGateway")
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Managed installation requires Windows' }
& (Join-Path $PackageDir 'verify_windows.ps1') -PackageDir $PackageDir -TrustedThumbprints $TrustedThumbprints
$bin=Join-Path $InstallDir 'bin'
$agents=Join-Path $InstallDir 'agents'
[void][IO.Directory]::CreateDirectory($bin)
[void][IO.Directory]::CreateDirectory($agents)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($directory in @($bin,$agents)) {
    & icacls.exe $directory /inheritance:r /grant:r "*$($sid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict managed runtime ACL' }
}
foreach ($name in @('bastion_worker.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PackageDir $name) -Destination (Join-Path $agents $name) -Force
}
Copy-Item -LiteralPath (Join-Path $PackageDir 'egw-askpass.exe') -Destination (Join-Path $bin 'egw-askpass.exe') -Force
# Installation does not launch a worker, modify VPN state, or reconnect sessions.
@{ status='installed_files_only'; worker_started=$false; helper_path=(Join-Path $bin 'egw-askpass.exe'); agents_path=$agents } | ConvertTo-Json
