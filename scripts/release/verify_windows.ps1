param([Parameter(Mandatory=$true)][string]$PackageDir, [Parameter(Mandatory=$true)][string[]]$TrustedThumbprints)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows signature verification requires Windows' }
$trusted=@($TrustedThumbprints | ForEach-Object { $_.Replace(' ','').ToUpperInvariant() })
$manifest=Get-Content -LiteralPath (Join-Path $PackageDir 'signature-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.status -ne 'signed' -or -not $manifest.files.Count) { throw 'A signed manifest is required' }
$root=(Resolve-Path -LiteralPath $PackageDir).Path
$expected=@{}
$required=@('egw-askpass.exe','egw-runtime.exe','bastion_worker.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1','verify_windows.ps1','install_windows.ps1')
if($manifest.files.Count -ne $required.Count){throw 'Incomplete release manifest'}
if((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Package root cannot be a reparse point'}
foreach ($item in $manifest.files) {
    if($item.file -cnotin $required -or $item.sha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Invalid release manifest entry'}
    $path=[IO.Path]::GetFullPath((Join-Path $root $item.file))
    if($expected.ContainsKey($path)){throw 'Duplicate release manifest entry'}
    if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Package files cannot be reparse points'}
    if (-not $path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest path escapes package root' }
    $signature=Get-AuthenticodeSignature -LiteralPath $path
    try {
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -notin $trusted) {throw 'Untrusted release signature'}
    } finally {foreach($certificate in @($signature.SignerCertificate,$signature.TimeStamperCertificate)){if($certificate){$certificate.Dispose()}}}
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() -ne $item.sha256) { throw 'Release hash mismatch' }
    $expected[$path]=$true
}
foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.exe') })) {
    if (-not $expected.ContainsKey($file.FullName)) { throw 'Executable file missing from signed manifest' }
}
Write-Output 'PACKAGE_SIGNATURES_VALID'
