param(
    [string]$SourceSpool = "\\tsclient\C\EnclaveGateway\spool",
    [string]$InstallDir = "$env:LOCALAPPDATA\EnclaveGateway",
    [string]$WorkerPath = '',
    [string[]]$TrustedSignerThumbprints = @(),
    [string]$TrustedSignerThumbprintsCsv = '',
    [switch]$AllowUnsignedLab,
    [switch]$RegisterStartup
)
$ErrorActionPreference='Stop'
if ($AllowUnsignedLab -and $RegisterStartup) { throw 'Unsigned lab mode cannot register persistent startup' }
$trusted=@($TrustedSignerThumbprints)
if ($TrustedSignerThumbprintsCsv) { $trusted+=@($TrustedSignerThumbprintsCsv.Split(',')) }
$trusted=@($trusted | ForEach-Object { $_.Replace(' ','').ToUpperInvariant() })
foreach ($thumbprint in $trusted) {
    if ($thumbprint -notmatch '^[A-F0-9]{40,64}$') { throw 'Invalid trusted signer identifier' }
}
$workerSrc=if ($WorkerPath) { $WorkerPath } else { Join-Path $SourceSpool 'bastion_worker.ps1' }
if (-not (Test-Path -LiteralPath $workerSrc -PathType Leaf)) { throw 'Worker file is missing' }
function Assert-TrustedScript([string]$Path) {
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -notin $trusted) {
        throw 'Runtime requires a valid signature from an explicitly trusted publisher'
    }
}
if (-not $AllowUnsignedLab) { Assert-TrustedScript $workerSrc }
if ($RegisterStartup) {
    Assert-TrustedScript $PSCommandPath
    foreach ($value in @($SourceSpool,$InstallDir)) {
        if ($value.IndexOfAny([char[]]@('"',"`r","`n")) -ge 0) { throw 'Invalid startup path' }
    }
    [void][IO.Directory]::CreateDirectory($InstallDir)
    $workerDst=Join-Path $InstallDir 'bastion_worker.ps1'
    Copy-Item -LiteralPath $workerSrc -Destination $workerDst -Force
    $bootstrapDst=Join-Path $InstallDir 'bastion_bootstrap.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $bootstrapDst -Force
    Assert-TrustedScript $workerDst
    Assert-TrustedScript $bootstrapDst
    $thumbprints=$trusted -join ','
    $launch="powershell.exe -NoProfile -File `"$bootstrapDst`" -SourceSpool `"$SourceSpool`" -WorkerPath `"$workerDst`" -TrustedSignerThumbprintsCsv $thumbprints"
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'EnclaveBastionWorker' -Value $launch
    & $workerDst -SpoolDir $SourceSpool
    return
}
& $workerSrc -SpoolDir $SourceSpool
