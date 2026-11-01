param([Parameter(Mandatory=$true)][string]$Worker,[Parameter(Mandatory=$true)][string]$Runtime,
      [Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop'
if(Test-Path $Workspace){throw 'Use a new native trust fixture workspace'}
[void][IO.Directory]::CreateDirectory($Workspace);$checks=@()
function Probe([string]$Path,[string]$RuntimePath=$Runtime){
 $query=@{worker_path=$Path;runtime_path=$RuntimePath;process_isolation=$true;evidence=@{nonce='fixture-challenge'}}|ConvertTo-Json -Compress
 $process=New-Object Diagnostics.Process
 try{
  $start=New-Object Diagnostics.ProcessStartInfo
  $start.FileName=$Runtime;$start.Arguments='attest';$start.UseShellExecute=$false
  $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $start.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
  $process.StartInfo=$start;[void]$process.Start()
  $read=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
  # Bypass Windows PowerShell's OEM native-pipeline encoding.
  $bytes=[Text.Encoding]::UTF8.GetBytes($query)
  $process.StandardInput.BaseStream.Write($bytes,0,$bytes.Length);$process.StandardInput.BaseStream.Close()
  if(-not $process.WaitForExit(30000)){$process.Kill();throw 'Native trust probe deadline expired'}
  $raw=$read.GetAwaiter().GetResult();[void]$errors.GetAwaiter().GetResult()
  if($process.ExitCode){throw 'Native trust probe failed'}
 }finally{
  foreach($name in @('StandardInput','StandardOutput','StandardError')){try{$process.$name.Dispose()}catch{}}
  $process.Dispose()
  foreach($task in @($read,$errors)){if($task -and $task.IsCompleted){$task.Dispose()}}
 }
 return ($raw|ConvertFrom-Json).Stdout|ConvertFrom-Json
}
try{
 $expected=Get-AuthenticodeSignature $Worker;$value=Probe $Worker
 if($value.signature_status -ne 'Valid' -or $value.signer -ne $expected.SignerCertificate.Thumbprint -or $value.current_sha256 -ne (Get-FileHash $Worker -Algorithm SHA256).Hash.ToLowerInvariant()) {throw 'Native script trust disagrees with OS cmdlet'}
 if($value.runtime_signature_status -ne 'Valid' -or $value.nonce -ne 'fixture-challenge'){throw 'Missing native runtime trust or challenge'}
 $checks+='stock-signature-and-hash-agree'
 $unicode=Join-Path $Workspace ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('0YHQutGA0LjQv9GCLnBzMQ==')));Copy-Item $Worker $unicode
 $value=Probe $unicode
 if($value.signature_status -ne 'Valid' -or $value.current_sha256 -ne (Get-FileHash $Worker -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Unicode trust path changed identity'}
 $checks+='unicode-signed-script-path'
 $copy=Join-Path $Workspace 'tampered.ps1';Copy-Item $Worker $copy
 Add-Content $copy '# changed after signing'
 $value=Probe $copy;if($value.signature_status -eq 'Valid'){throw 'Modified script accepted'}
 $checks+='signed-script-tamper-rejected'
 [IO.File]::WriteAllText($copy,"Write-Output 'unsigned'")
 $value=Probe $copy;if($value.signature_status -eq 'Valid' -or $value.signer){throw 'Unsigned script accepted'}
 $checks+='unsigned-script-rejected'
 $rejected=$false;try{[void](Probe $Worker (Join-Path $Workspace 'different-runtime.exe'))}catch{$rejected=$true}
 if(-not $rejected){throw 'Wrong running runtime identity accepted'}
 $checks+='runtime-image-identity-enforced'
 $report=@{status='passed';scope='native-authenticode-probe';checks=$checks}
}catch{$report=@{status='failed';checks=$checks;error_type=$_.Exception.GetType().FullName};throw}
finally{$report|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8}
$report|ConvertTo-Json -Depth 5
