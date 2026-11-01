param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Workspace){throw 'Use a new preparation fault workspace'}
[void][IO.Directory]::CreateDirectory($Workspace)
$checks=@();$child=$null;$taskName='EGWLabPreparation-'+[Guid]::NewGuid().ToString('N')
function Quote([string]$Value){return "'"+$Value.Replace("'","''")+"'"}
try{
 foreach($case in @('process-kill','publication-sharing-failure')){
  $root=Join-Path $Workspace $case;[void][IO.Directory]::CreateDirectory($root)
  $path=Join-Path $root 'machine_prepare.ps1';$marker=Join-Path $root 'deleted'
  $sourceText=[IO.File]::ReadAllText($Source).Replace("`$install='C:\EnclaveGateway'",('$install='+(Quote $root))).Replace('EnclaveGatewayMachinePreparation',$taskName)
  # Real Windows task and file operations; only the already-installed service
  # and forbidden MSI/media access are substituted in this scoped fixture.
  $prelude=@'
Import-Module ScheduledTasks
function Get-Service {[CmdletBinding()]param($Name);return [pscustomobject]@{Status='Running'}}
function Get-PSDrive {[CmdletBinding()]param($PSProvider);throw 'Fixture attempted MSI/media enumeration'}
'@
  if($case -eq 'process-kill'){
   $prelude+=@'
function Unregister-ScheduledTask {
 [CmdletBinding(SupportsShouldProcess=$true)]param($TaskName)
 ScheduledTasks\Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
 Remove-Item -LiteralPath READY
 [IO.File]::WriteAllText(MARKER,'deleted')
 Start-Sleep -Seconds 180
}
'@.Replace('READY',(Quote (Join-Path $root 'provision-machine.json'))).Replace('MARKER',(Quote $marker))
  }
  # Keep param() first, and the exact same source bytes for both invocations.
  $boundary=$sourceText.IndexOf("`$ErrorActionPreference='Stop'")
  $sourceText=$sourceText.Insert($boundary,$prelude+"`r`n")
  [IO.File]::WriteAllText($path,$sourceText,(New-Object Text.UTF8Encoding($true)))
  @{revision=1;guest_agent_sha256=('a'*64);completion_mode='StartupTask'}|ConvertTo-Json|Set-Content (Join-Path $root 'provision-media.json') -Encoding UTF8
  @{revision=1;status='machine_ready';architecture='x86_64';approved_sha256=('a'*64);qga_mode='msi-native';media_verification='sha256-pin'}|ConvertTo-Json|Set-Content (Join-Path $root 'provision-machine.json') -Encoding UTF8
  $exe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$path`" -Architecture x86_64 -CompleteSetup -WaitForSetup"
  $action=New-ScheduledTaskAction -Execute $exe -Argument $arguments
  Register-ScheduledTask -TaskName $taskName -Action $action -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest) | Out-Null
  $handle=$null
  try{
   if($case -eq 'publication-sharing-failure'){$handle=New-Object IO.FileStream((Join-Path $root 'provision-machine.json'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)}
   $child=Start-Process $exe -ArgumentList $arguments -PassThru -RedirectStandardOutput (Join-Path $root 'child.out.log') -RedirectStandardError (Join-Path $root 'child.err.log')
   $null=$child.Handle
   if($case -eq 'process-kill'){
    $until=[DateTime]::UtcNow.AddSeconds(120)
    while(-not (Test-Path $marker)){if($child.HasExited -or [DateTime]::UtcNow -gt $until){throw 'Deletion barrier not reached'};Start-Sleep -Milliseconds 50}
    $child.Kill();$child.WaitForExit()
    if(Test-Path (Join-Path $root 'provision-machine.json')){throw 'Killed preparation published readiness'}
   }else{
    if(-not $child.WaitForExit(120000) -or $child.ExitCode -eq 0){throw 'Publication sharing failure was not observed'}
    if((Get-Content (Join-Path $root 'provision-machine.json') -Raw|ConvertFrom-Json).revision -ne 1){throw 'Failed publication changed readiness'}
   }
   $child.Dispose();$child=$null
  }finally{if($handle){$handle.Dispose()}}
  if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Fixture task was not removed'}
  $recover="$arguments -RecoverOnly"
  $child=Start-Process $exe -ArgumentList $recover -PassThru -RedirectStandardOutput (Join-Path $root 'recovery.out.log') -RedirectStandardError (Join-Path $root 'recovery.err.log')
  $null=$child.Handle
  if(-not $child.WaitForExit(120000) -or $child.ExitCode -ne 0){throw 'Journal recovery failed'}
  $child.Dispose();$child=$null
  $ready=Get-Content (Join-Path $root 'provision-machine.json') -Raw|ConvertFrom-Json
  if($ready.revision -ne 2 -or -not $ready.completion_task_removed -or (Test-Path (Join-Path $root 'machine-prepare-failed.json'))){throw 'Recovery did not finalize'}
  $checks+=($case+'-real-task-removed-journal-recovers-without-msi')
 }
 $report=@{status='passed';scope='disposable-windows-preparation-faults';checks=$checks}
}catch{$report=@{status='failed';checks=$checks;error_type=$_.Exception.GetType().FullName};throw}
finally{
 if($child){try{if(-not $child.HasExited){$child.Kill();$child.WaitForExit()}}finally{$child.Dispose()}}
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
 $report|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8
}
$report|ConvertTo-Json -Depth 5
