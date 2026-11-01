param(
    [Parameter(Mandatory=$true)][string]$PackageDir,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [string]$TimestampServer,
    [Parameter(Mandatory=$true)][ValidateRange(1,2147483647)][int]$ReleaseSequence,
    [ValidateScript({$_ -cmatch '^[a-z0-9][a-z0-9-]{0,31}$'})][string]$Channel='stable',
    [switch]$AllowUntimestampedLab,
    [ValidateSet('CurrentUser','LocalMachine')][string]$CertificateStore='CurrentUser'
)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Authenticode release signing requires Windows' }
$thumbprint=$CertificateThumbprint.Replace(' ','').ToUpperInvariant()
if ($thumbprint -notmatch '^[A-F0-9]{40,64}$') { throw 'Invalid certificate identifier' }
$certificate=Get-Item -LiteralPath "Cert:\$CertificateStore\My\$thumbprint"
if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le (Get-Date)) { throw 'A current code-signing certificate with a private key is required' }
$oid='1.3.6.1.5.5.7.3.3'
if (-not @($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq $oid }).Count) { throw 'Certificate is not valid for code signing' }
if(-not $TimestampServer -and -not $AllowUntimestampedLab){throw 'TimestampServer is required outside disposable signing fixtures'}
$files=@(Get-ChildItem -LiteralPath $PackageDir -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.exe') })
if (-not $files.Count) { throw 'No executable release files found' }
$manifest=@()
foreach ($file in $files) {
    $options=@{LiteralPath=$file.FullName;Certificate=$certificate;HashAlgorithm='SHA256'}
    if($TimestampServer){$options.TimestampServer=$TimestampServer}
    $signature=Set-AuthenticodeSignature @options
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $thumbprint) { throw "Signature verification failed: $($file.Name)" }
    $manifest+=@{ file=$file.FullName.Substring((Resolve-Path -LiteralPath $PackageDir).Path.Length+1); sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower(); signer=$thumbprint; signature='Valid' }
}
$metadata=@{revision=2;status='signed';files=$manifest;qualified_windows=$false;sequence=$ReleaseSequence;channel=$Channel;timestamp=$(if($TimestampServer){'authenticode'}else{'lab-not-qualified'})}
$bytes=[Text.Encoding]::UTF8.GetBytes(($metadata|ConvertTo-Json -Depth 6 -Compress))
[IO.File]::WriteAllBytes((Join-Path $PackageDir 'signature-manifest.json'),$bytes)
Add-Type -AssemblyName System.Security
$content=New-Object Security.Cryptography.Pkcs.ContentInfo(,$bytes)
$cms=New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
$signer=New-Object Security.Cryptography.Pkcs.CmsSigner($certificate)
$signer.DigestAlgorithm=New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
$cms.ComputeSignature($signer)
[IO.File]::WriteAllBytes((Join-Path $PackageDir 'signature-manifest.p7s'),$cms.Encode())
