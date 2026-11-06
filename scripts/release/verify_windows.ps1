param([Parameter(Mandatory=$true)][string]$PackageDir, [Parameter(Mandatory=$true)][string[]]$TrustedThumbprints)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows signature verification requires Windows' }
$trusted=@($TrustedThumbprints | ForEach-Object { $_.Replace(' ','').ToUpperInvariant() })
# Authenticate the exact metadata bytes before interpreting file identities or
# release ordering. CMS crypto, OS chain trust, code-signing EKU and pins agree.
Add-Type -AssemblyName System.Security
$bytes=[IO.File]::ReadAllBytes((Join-Path $PackageDir 'signature-manifest.json'))
$content=New-Object Security.Cryptography.Pkcs.ContentInfo(,$bytes)
$cms=New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
$cms.Decode([IO.File]::ReadAllBytes((Join-Path $PackageDir 'signature-manifest.p7s')))
if($cms.SignerInfos.Count -ne 1){throw 'One metadata signer is required'}
if($cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1'){throw 'Metadata requires a SHA-256 signature'}
$cms.CheckSignature($true)
$metadataSigner=$cms.SignerInfos[0].Certificate
if(-not $metadataSigner -or $metadataSigner.Thumbprint -notin $trusted){throw 'Untrusted metadata signer'}
$chain=New-Object Security.Cryptography.X509Certificates.X509Chain
try{
    [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3')))
    if(-not $chain.Build($metadataSigner)){throw 'Metadata signer chain is not trusted'}
}finally{$chain.Dispose()}
$manifest=Get-Content -LiteralPath (Join-Path $PackageDir 'signature-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.revision -ne 2 -or $manifest.sequence -isnot [int] -or $manifest.sequence -lt 1 -or $manifest.channel -cnotmatch '^[a-z0-9][a-z0-9-]{0,31}$' -or $manifest.status -ne 'signed' -or -not $manifest.files.Count) { throw 'A signed manifest is required' }
$root=(Resolve-Path -LiteralPath $PackageDir).Path
$expected=@{}
$required=@('egw-askpass.exe','egw-runtime.exe','bastion_worker.ps1','bastion_structured.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1','verify_windows.ps1','install_windows.ps1')
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
