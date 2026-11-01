param([Parameter(Mandatory=$true)][string]$PkiLab,[Parameter(Mandatory=$true)][string]$Worker,
      [Parameter(Mandatory=$true)][string]$Runtime,[Parameter(Mandatory=$true)][string]$SignScript,
      [Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Workspace){throw 'Use a new PKI acceptance directory'}
[void][IO.Directory]::CreateDirectory($Workspace)
$checks=@();$owned=New-Object 'Collections.Generic.List[Diagnostics.Process]';$nonceTimes=New-Object 'Collections.Generic.List[long]';$server=$null;$description=$null;$chainStatus=@{}
function Read-Line($Process,[int]$TimeoutMs=120000){
 $task=$Process.StandardOutput.ReadLineAsync()
 try{if(-not $task.Wait($TimeoutMs)){throw 'PKI protocol deadline expired'};return $task.Result}finally{if($task.IsCompleted){$task.Dispose()}}
}
function Frame($Process,$Value){$Process.StandardInput.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 6 -Compress))));$Process.StandardInput.Flush()}
function Stop-Owned($Process){
 if(-not $Process){return $true}
 $stopped=$false
 try{if(-not $Process.HasExited){$Process.Kill()};$stopped=$Process.WaitForExit(10000)}catch{}
 foreach($name in @('StandardInput','StandardOutput','StandardError')){try{$Process.$name.Dispose()}catch{}}
 $Process.Dispose()
 return $stopped
}
function Start-Probe([string]$Path,[bool]$RequireSigned){
 $p=New-Object Diagnostics.Process;$start=New-Object Diagnostics.ProcessStartInfo
 $start.FileName=$Runtime;$start.Arguments="attest-server $PID";$start.UseShellExecute=$false
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $p.StartInfo=$start;[void]$p.Start();$owned.Add($p)
 Frame $p @{worker_path=$Path;runtime_path=$Runtime;worker_sha256=(Get-FileHash $Path -Algorithm SHA256).Hash.ToLowerInvariant();runtime_sha256=(Get-FileHash $Runtime -Algorithm SHA256).Hash.ToLowerInvariant();require_signed=$RequireSigned}
 $line=Read-Line $p
 if($RequireSigned -and -not $line){if(-not $p.WaitForExit(10000) -or $p.ExitCode -eq 0){throw 'Rejected startup did not fail'};return $null}
 if(($line|ConvertFrom-Json).ready -ne 1){throw 'Native PKI observer did not initialize'}
 return $p
}
function Nonce($Process,[string]$Path,[bool]$Valid,[string]$Thumbprint){
 $timer=[Diagnostics.Stopwatch]::StartNew()
 Frame $Process @{worker_path=$Path;runtime_path=$Runtime;process_isolation=$true;evidence=@{nonce=([Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N'))}}
 $reply=Read-Line $Process 10000|ConvertFrom-Json;$nonceTimes.Add($timer.ElapsedMilliseconds)
 if($timer.ElapsedMilliseconds -gt 10000){throw 'PKI nonce exceeded the challenge deadline'}
 if($reply.ExitCode -ne 0){throw 'Native PKI protocol failed'}
 $e=$reply.Stdout|ConvertFrom-Json
 if($e.runtime_signature_status -ne 'Valid' -or $e.trust_policy -ne 'cache-only-chain-revocation-excluding-root'){throw 'Unexpected runtime trust policy'}
 if($Valid){if($e.signature_status -ne 'Valid' -or $e.signer -ne $Thumbprint){throw 'Valid issued signer rejected'}}
 else{if($e.signature_status -eq 'Valid' -or $e.signer){throw 'Invalid issued signer accepted'}}
 return $e
}
function Stats {
 $server.StandardInput.WriteLine('stats');$server.StandardInput.Flush();return (Read-Line $server|ConvertFrom-Json).requests
}
function Assert-ChainReason([string]$Name,[string]$Expected){
 $certificate=Get-Item ('Cert:\LocalMachine\My\'+$description.certificates.$Name)
 $chain=New-Object Security.Cryptography.X509Certificates.X509Chain
 try{
  $chain.ChainPolicy.RevocationMode='Offline';$chain.ChainPolicy.RevocationFlag='ExcludeRoot';$chain.ChainPolicy.VerificationFlags='NoFlag'
  [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3')))
  $valid=$chain.Build($certificate);$flags=0
  foreach($status in $chain.ChainStatus){$flags=$flags -bor [int]$status.Status}
  $chainStatus[$Name]=@($chain.ChainStatus|ForEach-Object {[string]$_.Status})
  $wanted=[int][Enum]::Parse([Security.Cryptography.X509Certificates.X509ChainStatusFlags],$Expected)
  if($valid -or ($flags -band $wanted) -eq 0){throw ('Wrong causal chain failure: '+$Name)}
  if($Expected -eq 'Revoked' -and ($flags -band [int][Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown)){
   throw 'Revocation was not established independently of unavailable status'
  }
 }finally{$chain.Dispose();$certificate.Dispose()}
}
function Sign-Copy([string]$Name,[switch]$Timestamp){
 $path=Join-Path $Workspace ($Name+'.ps1');Copy-Item -LiteralPath $Worker -Destination $path
 $cert=Get-Item ('Cert:\LocalMachine\My\'+$description.certificates.$Name)
 $options=@{LiteralPath=$path;Certificate=$cert;HashAlgorithm='SHA256'}
 if($Timestamp){$options.TimestampServer=$description.origin+'/timestamp'}
 $signature=Set-AuthenticodeSignature @options
 if(-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint){
  @{status=[string]$signature.Status;message=$signature.StatusMessage;has_private_key=$cert.HasPrivateKey}|ConvertTo-Json|Set-Content (Join-Path $Workspace 'signing-diagnostic.json') -Encoding UTF8
  throw 'Issued fixture signing failed'
 }
 if($Timestamp -and (-not $signature.TimeStamperCertificate -or $signature.TimeStamperCertificate.Thumbprint -ne $description.tsa)){throw 'Local Authenticode timestamp was not attached'}
 $cert.Dispose();return $path
}
try{
 $server=New-Object Diagnostics.Process;$start=New-Object Diagnostics.ProcessStartInfo
 $start.FileName=$PkiLab;$start.Arguments='"'+(Join-Path $Workspace 'authority')+'"';$start.UseShellExecute=$false
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $server.StartInfo=$start;[void]$server.Start()
 $description=Read-Line $server|ConvertFrom-Json
 if($description.status -ne 'ready'){throw 'Disposable authority did not start'}
 $description|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Workspace 'authority.json') -Encoding UTF8
 # Establish an actually usable cache before its short CRL expires.
 $cache=Sign-Copy 'cache';$cacheHost=Start-Probe $cache $true
 if(-not $cacheHost){throw 'Fresh cached CRL startup rejected'}
 [void](Nonce $cacheHost $cache $true $description.certificates.cache)
 $cacheRequests=(Stats).cache
 if(-not $cacheRequests){throw 'CRL was not obtained from the local authority'}
 $checks+='issued-chain-fresh-crl-startup-and-cache-only-nonce'
 $expired=Sign-Copy 'expired' -Timestamp
 if((Stats).timestamp -lt 1){throw 'Timestamp service was not contacted'}
 $checks+='local-authenticode-timestamp-attached-and-verified'
 $good=Sign-Copy 'good';$goodHost=Start-Probe $good $true
 if(-not $goodHost){throw 'Valid issued chain rejected'}
 $before=Stats;[void](Nonce $goodHost $good $true $description.certificates.good);$after=Stats
 if($before.good -ne $after.good){throw 'Cache-only nonce contacted the network'}
 $checks+='valid-issued-chain-nonce-without-network'
 foreach($name in @('revoked','stale')){
  $path=Sign-Copy $name
  if(Start-Probe $path $true){throw ('Strict startup accepted '+$name)}
  $observer=Start-Probe $path $false;[void](Nonce $observer $path $false '')
  Assert-ChainReason $name $(if($name -eq 'revoked'){'Revoked'}else{'RevocationStatusUnknown'})
  $checks+=($name+'-crl-rejected-at-startup-and-nonce')
 }
 foreach($name in @('ocsp-good','ocsp-revoked')){
  $path=Sign-Copy $name;$valid=($name -eq 'ocsp-good')
  $hostProcess=Start-Probe $path $true
  if($valid -and -not $hostProcess){throw 'Valid local OCSP response rejected'}
  if(-not $valid -and $hostProcess){throw 'Revoked local OCSP response accepted'}
  if(-not $hostProcess){$hostProcess=Start-Probe $path $false}
  $before=(Stats).$name;[void](Nonce $hostProcess $path $valid $description.certificates.$name);$after=(Stats).$name
  if(-not $before -or $before -ne $after){throw 'OCSP cache-only evidence is invalid'}
  if(-not $valid){Assert-ChainReason $name 'Revoked'}
  $checks+=($name+'-startup-and-cache-only-nonce')
 }
 $rotation=Sign-Copy 'rotation';$rotated=Start-Probe $rotation $true
 if(-not $rotated){throw 'Rotated issued certificate rejected'}
 $e=Nonce $rotated $rotation $true $description.certificates.rotation
 if($e.signer -eq $description.certificates.good){throw 'Signer rotation retained the old identity'}
 $checks+='rotation-reports-fresh-signer-identity'
 $until=[DateTime]::Parse($description.cache_expiry).ToUniversalTime().AddSeconds(3)
 while([DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 250}
 $before=Stats;[void](Nonce $cacheHost $cache $false '');$after=Stats
 if($before.cache -ne $after.cache){throw 'Expired cache performed an online fallback'}
 Assert-ChainReason 'cache' 'RevocationStatusUnknown'
 $checks+='expired-crl-cache-rejected-without-network-fallback'
 $until=[DateTime]::Parse($description.signer_expiry).ToUniversalTime().AddSeconds(3)
 while([DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 250}
 $sig=Get-AuthenticodeSignature -LiteralPath $expired
 if($sig.Status -ne 'Valid' -or -not $sig.TimeStamperCertificate){throw 'Timestamp did not preserve OS signature validity'}
 if(Start-Probe $expired $true){throw 'Current-signer policy accepted an expired signer through its timestamp'}
 $observer=Start-Probe $expired $false;[void](Nonce $observer $expired $false '')
 Assert-ChainReason 'expired' 'NotTimeValid'
 $checks+='timestamp-preserves-os-validity-but-current-signer-policy-rejects-expiry'
 # Exercise actual CMS package pins through an already approved entry point.
 # Neither the new package nor unsigned legacy metadata chooses its verifier.
 $approved=Split-Path $Worker -Parent;$verifier=Join-Path $approved 'verify_windows.ps1';$installer=Join-Path $approved 'install_windows.ps1'
 $sign=[scriptblock]::Create([IO.File]::ReadAllText($SignScript));$packages=@{}
 foreach($name in @('good','rotation')){
  $package=Join-Path $Workspace ('release-'+$name);[void][IO.Directory]::CreateDirectory($package)
  foreach($file in @('egw-askpass.exe','egw-runtime.exe','bastion_worker.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1','verify_windows.ps1','install_windows.ps1')){
   Copy-Item -LiteralPath (Join-Path $approved $file) -Destination (Join-Path $package $file)
  }
  & $sign -PackageDir $package -CertificateThumbprint $description.certificates.$name -CertificateStore LocalMachine -ReleaseSequence $(if($name -eq 'good'){31}else{32}) -AllowUntimestampedLab
  & $verifier -PackageDir $package -TrustedThumbprints $description.certificates.$name | Out-Null
  $packages[$name]=$package
 }
 $rejected=$false;try{& $verifier -PackageDir $packages.rotation -TrustedThumbprints $description.certificates.good|Out-Null}catch{$rejected=$true}
 if(-not $rejected){throw 'CMS rotation accepted an unapproved new pin'}
 $target=Join-Path $Workspace 'managed-rotation'
 & $installer -PackageDir $packages.good -InstallDir $target -TrustedThumbprints $description.certificates.good | Out-Null
 $selected=& $installer -PackageDir $packages.rotation -InstallDir $target -TrustedThumbprints @($description.certificates.good,$description.certificates.rotation) | Out-String | ConvertFrom-Json
 & $installer -Action Status -InstallDir $target -TrustedThumbprints $description.certificates.rotation | Out-Null
 $rejected=$false;try{& $installer -Action Rollback -InstallDir $target -TrustedThumbprints $description.certificates.rotation|Out-Null}catch{$rejected=$true}
 $selection=Get-Content (Join-Path $target 'installation.json') -Raw|ConvertFrom-Json
 if(-not $rejected -or $selection.current -ne $selected.release_id){throw 'Retired signer pin allowed rollback or changed selection'}
 $checks+='cms-rotation-requires-explicit-new-pin-and-overlap-during-upgrade'
 $checks+='retired-pin-rejects-old-generation-without-changing-selection'
 $report=@{status='passed';scope='disposable-issued-pki';checks=$checks;requests=(Stats);chain_status=$chainStatus;private_keys='nonexportable-lab-only';production_pki='not_qualified'}
}catch{$report=@{status='failed';scope='disposable-issued-pki';checks=$checks;error_type=$_.Exception.GetType().FullName};throw}
finally{
 $report.chain_status=$chainStatus
 $report.nonce_deadline_ms=10000;$report.nonce_elapsed_ms=$nonceTimes.ToArray()
 $report.native_cleanup='passed'
 foreach($p in $owned){if(-not (Stop-Owned $p)){$report.status='failed';$report.native_cleanup='failed'}}
 if($server){
  try{
   if(-not $server.HasExited){$server.StandardInput.WriteLine('stop');$server.StandardInput.Flush();if(-not $server.WaitForExit(30000)){throw 'Authority cleanup deadline expired'}}
   if($server.ExitCode -ne 0){$report.status='failed';$report.authority_error=$server.StandardError.ReadToEnd()}
  }finally{if(-not (Stop-Owned $server)){$report.status='failed';$report.authority_cleanup='failed'}}
 }
 if(-not (Test-Path (Join-Path $Workspace 'authority\cleanup.json'))){$report.status='failed';$report.cleanup='missing'}
 $report|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8
}
if($report.status -ne 'passed'){throw 'PKI acceptance or cleanup failed'}
$report|ConvertTo-Json -Depth 6
