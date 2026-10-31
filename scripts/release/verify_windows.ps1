param([Parameter(Mandatory=$true)][string]$PackageDir, [Parameter(Mandatory=$true)][string[]]$TrustedThumbprints)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows signature verification requires Windows' }
$trusted=@($TrustedThumbprints | ForEach-Object { $_.Replace(' ','').ToUpperInvariant() })
$manifest=Get-Content -LiteralPath (Join-Path $PackageDir 'signature-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.status -ne 'signed' -or -not $manifest.files.Count) { throw 'A signed manifest is required' }
$root=(Resolve-Path -LiteralPath $PackageDir).Path
$expected=@{}
foreach ($item in $manifest.files) {
    $path=[IO.Path]::GetFullPath((Join-Path $root $item.file))
    if (-not $path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest path escapes package root' }
    $signature=Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -notin $trusted) { throw 'Untrusted release signature' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() -ne $item.sha256) { throw 'Release hash mismatch' }
    $expected[$path]=$true
}
foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.exe') })) {
    if (-not $expected.ContainsKey($file.FullName)) { throw 'Executable file missing from signed manifest' }
}
Write-Output 'PACKAGE_SIGNATURES_VALID'
