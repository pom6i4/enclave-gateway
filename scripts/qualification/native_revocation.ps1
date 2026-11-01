param([Parameter(Mandatory=$true)][string]$Worker,[Parameter(Mandatory=$true)][string]$Runtime,
      [Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Workspace){throw 'Use a new revocation fixture directory'}
[void][IO.Directory]::CreateDirectory($Workspace)
$root=$null;$leaf=$null;$store=$null;$checks=@()
function Probe([bool]$RequireSigned){
 $process=New-Object Diagnostics.Process
 try{
  $start=New-Object Diagnostics.ProcessStartInfo
  $start.FileName=$Runtime;$start.Arguments="attest-server $PID";$start.UseShellExecute=$false
  $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $process.StartInfo=$start;[void]$process.Start()
  function Frame($Value){
   $json=$Value|ConvertTo-Json -Depth 5 -Compress
   $process.StandardInput.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)));$process.StandardInput.Flush()
  }
  function Read-Frame {
   $task=$process.StandardOutput.ReadLineAsync()
   try{if(-not $task.Wait(120000)){throw 'Revocation observer deadline expired'};return $task.Result}
   finally{if($task.IsCompleted){$task.Dispose()}}
  }
  Frame @{worker_path=$copy;runtime_path=$Runtime;worker_sha256=(Get-FileHash $copy -Algorithm SHA256).Hash.ToLowerInvariant();runtime_sha256=(Get-FileHash $Runtime -Algorithm SHA256).Hash.ToLowerInvariant();require_signed=$RequireSigned}
  $ready=Read-Frame
  if($RequireSigned){
   if($ready -or -not $process.WaitForExit(10000) -or $process.ExitCode -eq 0){throw 'Signed startup accepted missing revocation data'}
   return
  }
  if(($ready|ConvertFrom-Json).ready -ne 1){throw 'Explicit lab observer did not start'}
  Frame @{worker_path=$copy;runtime_path=$Runtime;process_isolation=$true;evidence=@{nonce=('a'*64)}}
  $reply=Read-Frame|ConvertFrom-Json
  if($reply.ExitCode -ne 0){throw 'Revocation observer protocol failed'}
  $e=$reply.Stdout|ConvertFrom-Json
  if($e.signature_status -eq 'Valid' -or $e.signer -or $e.runtime_signature_status -ne 'Valid' -or
     $e.trust_policy -ne 'cache-only-chain-revocation-excluding-root' -or $e.trust_probe_sequence -ne 1){throw 'Missing revocation data did not fail closed'}
 }finally{
  try{if(-not $process.HasExited){$process.Kill();$process.WaitForExit()}}catch{}
  foreach($name in @('StandardInput','StandardOutput','StandardError')){try{$process.$name.Dispose()}catch{}}
  $process.Dispose()
 }
}
try{
 $root=New-SelfSignedCertificate -Type Custom -Subject 'CN=EGW Revocation Fixture Root' -KeyUsage CertSign,CRLSign,DigitalSignature -KeyExportPolicy NonExportable -HashAlgorithm SHA256 -TextExtension '2.5.29.19={critical}{text}ca=1' -CertStoreLocation Cert:\LocalMachine\My -NotBefore (Get-Date).AddMinutes(-5) -NotAfter (Get-Date).AddHours(2)
 $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');$store.Open('ReadWrite');$store.Add($root)
 $leaf=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=EGW Missing Revocation Fixture' -Signer $root -KeyExportPolicy NonExportable -HashAlgorithm SHA256 -CertStoreLocation Cert:\LocalMachine\My -NotBefore (Get-Date).AddMinutes(-5) -NotAfter (Get-Date).AddHours(1)
 $chain=New-Object Security.Cryptography.X509Certificates.X509Chain
 try{
  $chain.ChainPolicy.RevocationMode='NoCheck'
  if(-not $chain.Build($leaf)){throw 'Fixture certificate chain is invalid independently of revocation'}
 }finally{$chain.Dispose()}
 $checks+='issued-code-signing-chain-valid-without-revocation'
 $copy=Join-Path $Workspace 'issued-worker.ps1';Copy-Item -LiteralPath $Worker -Destination $copy
 $signature=Set-AuthenticodeSignature -LiteralPath $copy -Certificate $leaf -HashAlgorithm SHA256
 if(-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $leaf.Thumbprint){throw 'Fixture signing failed'}
 Probe $true;$checks+='strict-startup-rejects-missing-revocation-data'
 # Lab mode admits an untrusted startup only to observe the nonce result.
 # Production workers never use this mode.
 Probe $false;$checks+='nonce-rejects-missing-revocation-data-without-network-fallback'
 $report=@{status='passed';scope='isolated-missing-revocation-data';checks=$checks;private_keys_exported=$false}
}catch{$report=@{status='failed';checks=$checks;error_type=$_.Exception.GetType().FullName};throw}
finally{
 if($store){try{if($root){$store.Remove($root)}}finally{$store.Close()}}
 foreach($certificate in @($leaf,$root)){if($certificate){Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($certificate.Thumbprint)" -DeleteKey -Force;$certificate.Dispose()}}
 $report|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8
}
$report|ConvertTo-Json -Depth 5
