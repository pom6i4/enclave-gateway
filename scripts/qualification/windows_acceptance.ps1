param([Parameter(Mandatory=$true)][string]$InputRoot,[Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:OS -ne 'Windows_NT'){throw 'Disposable Windows required'}
if(Test-Path -LiteralPath $Workspace){throw 'Use a new results workspace'}
$root=[IO.Path]::GetFullPath($InputRoot).TrimEnd('\')
if($root -notmatch '^C:\\EnclaveGateway\\Qualification\\[a-f0-9]{32}\\input$'){throw 'Input is outside the dedicated qualification namespace'}
if([IO.Path]::GetFullPath($Workspace) -ne (Join-Path (Split-Path $root) 'results')){throw 'Results must belong to this qualification namespace'}
$manifest=Get-Content (Join-Path $root 'inputs.json') -Raw -Encoding UTF8|ConvertFrom-Json
foreach($entry in $manifest.files){
 if($entry.path -match '(^[\\/]|:|(^|[\\/])\.\.([\\/]|$))'){throw 'Invalid input path'}
 $p=Join-Path $root $entry.path
 if((Get-Item $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Input link rejected'}
 if((Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256){throw 'Qualification input hash mismatch'}
}
[void][IO.Directory]::CreateDirectory($Workspace)
$source=Join-Path $root 'source';$package=Join-Path $root 'package';$certificate=$null;$rootStore=$null
$report=@{status='running';scope='disposable-issued-pki-migration-and-preparation';production_keys='not_used';checks=@()}
try{
 $certificate=New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=EGW Disposable '+[Guid]::NewGuid().ToString('N')) -CertStoreLocation 'Cert:\LocalMachine\My' -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' -HashAlgorithm SHA256 -NotAfter (Get-Date).AddHours(6)
 $thumb=$certificate.Thumbprint
 $rootStore=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');$rootStore.Open('ReadWrite');$rootStore.Add($certificate);$rootStore.Close();$rootStore=$null
 & (Join-Path $source 'scripts/release/sign_windows.ps1') -PackageDir $package -CertificateThumbprint $thumb -CertificateStore LocalMachine -ReleaseSequence 1 -AllowUntimestampedLab
 & (Join-Path $package 'verify_windows.ps1') -PackageDir $package -TrustedThumbprints @($thumb) | Out-Null
 & (Join-Path $source 'scripts/qualification/machine_prepare_faults.ps1') -Source (Join-Path $source 'src/enclave_gateway/agents/machine_prepare.ps1') -Workspace (Join-Path $Workspace 'preparation') | Out-Null
 $report.checks+='preparation-real-task-crash-and-publication-recovery'
 & (Join-Path $source 'scripts/qualification/windows_migration.ps1') -Package $package -TrustedThumbprints @($thumb) -Workspace (Join-Path $Workspace 'migration') | Out-Null
 $report.checks+='v1-dry-run-crash-resume-rollback'
 & (Join-Path $source 'scripts/qualification/pki_acceptance.ps1') -PkiLab (Join-Path $root 'PkiLab.exe') -Worker (Join-Path $package 'bastion_worker.ps1') -Runtime (Join-Path $package 'egw-runtime.exe') -SignScript (Join-Path $source 'scripts/release/sign_windows.ps1') -Workspace (Join-Path $Workspace 'pki') | Out-Null
 $report.checks+='issued-crl-ocsp-cache-expiry-timestamp-and-pin-rotation'
 $report.status='passed'
}catch{$report.status='failed';$report.error_type=$_.Exception.GetType().FullName;throw}
finally{
 try{
  if($rootStore){$rootStore.Close()}
  if($certificate){
   $thumb=$certificate.Thumbprint;$certificate.Dispose();$certificate=$null
   if(Test-Path "Cert:\LocalMachine\Root\$thumb"){Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$thumb" -Force}
   if(Test-Path "Cert:\LocalMachine\My\$thumb"){Remove-Item -LiteralPath "Cert:\LocalMachine\My\$thumb" -DeleteKey -Force}
   if((Test-Path "Cert:\LocalMachine\Root\$thumb") -or (Test-Path "Cert:\LocalMachine\My\$thumb")){throw 'Temporary signer remains'}
  }
  $report.cleanup='passed'
 }catch{$report.status='failed';$report.cleanup='failed';$report.cleanup_error_type=$_.Exception.GetType().FullName;throw}
 finally{$report|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8}
}
$report|ConvertTo-Json -Depth 8
