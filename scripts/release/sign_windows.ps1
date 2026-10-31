param(
    [Parameter(Mandatory=$true)][string]$PackageDir,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][string]$TimestampServer,
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
$files=@(Get-ChildItem -LiteralPath $PackageDir -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.exe') })
if (-not $files.Count) { throw 'No executable release files found' }
$manifest=@()
foreach ($file in $files) {
    $signature=Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $thumbprint) { throw "Signature verification failed: $($file.Name)" }
    $manifest+=@{ file=$file.FullName.Substring((Resolve-Path -LiteralPath $PackageDir).Path.Length+1); sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower(); signer=$thumbprint; signature='Valid' }
}
@{ status='signed'; files=$manifest; qualified_windows=$false } | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $PackageDir 'signature-manifest.json') -Encoding UTF8
