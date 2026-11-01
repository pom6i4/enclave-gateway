param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string[]]$TrustedThumbprints,
      [Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Workspace){throw 'Use a new migration workspace'}
[void][IO.Directory]::CreateDirectory($Workspace)
$installer=Join-Path $Package 'install_windows.ps1';$legacy=Join-Path $Workspace 'legacy';$target=Join-Path $Workspace 'managed'
[void][IO.Directory]::CreateDirectory($legacy)
# Deliberately malicious legacy paths and ordering must never be interpreted.
$legacyText='{"revision":1,"current":"..\\untrusted.ps1","max_sequence":2147483647,"channel":"attacker"}'
[IO.File]::WriteAllText((Join-Path $legacy 'installation.json'),$legacyText)
[IO.File]::WriteAllText((Join-Path $legacy 'untrusted.ps1'),"throw 'Legacy executable was invoked'")
function Snapshot {return ((Get-ChildItem -LiteralPath $legacy -File -Recurse|Sort-Object FullName|ForEach-Object {$_.Name+':'+(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}) -join '|')}
$before=Snapshot;$checks=@();$child=$null
function Invoke-Migration([string]$Action='Migrate',[switch]$DryRun,[string]$Destination=$target,[string]$Source=$legacy,[string]$InputPackage=$Package,[string[]]$Pins=$TrustedThumbprints){
 & $installer -Action $Action -LegacyDir $Source -InstallDir $Destination -PackageDir $InputPackage -TrustedThumbprints $Pins -DryRun:$DryRun | Out-String | ConvertFrom-Json
}
try{
 $plan=Invoke-Migration -DryRun
 if($plan.status -ne 'migration_plan_valid' -or $plan.changes_made -or (Test-Path $target) -or (Snapshot) -ne $before){throw 'Dry run mutated an installation'}
 $checks+='dry-run-verifies-package-without-writing'
 $bad=Join-Path $Workspace 'tampered';Copy-Item $Package $bad -Recurse;Add-Content (Join-Path $bad 'bastion_worker.ps1') '# fixture tamper'
 foreach($case in @('tamper','pin','overlap')){
  $rejected=$false
  try{
   if($case -eq 'tamper'){[void](Invoke-Migration -InputPackage $bad)}
   elseif($case -eq 'pin'){[void](Invoke-Migration -Pins @('0'*40))}
   else{[void](Invoke-Migration -Destination (Join-Path $legacy 'nested'))}
  }catch{$rejected=$true}
  if(-not $rejected -or (Test-Path $target) -or (Snapshot) -ne $before){throw 'Rejected migration changed state'}
  $checks+=($case+'-rejected-before-target-creation')
 }
 $first=Invoke-Migration
 $selection=Get-Content (Join-Path $target 'installation.json') -Raw|ConvertFrom-Json
 if($first.status -ne 'installed_files_only' -or $first.worker_started -or $selection.revision -ne 2 -or $selection.channel -eq 'attacker' -or (Snapshot) -ne $before){throw 'Legacy trust was promoted or source changed'}
 $checks+='v1-untrusted-metadata-not-promoted'
 $again=Invoke-Migration
 if($again.release_id -ne $first.release_id){throw 'Migration resume changed release'}
 $checks+='idempotent-resume'
 $rollback=Invoke-Migration -Action MigrateRollback
 if($rollback.status -ne 'migration_withdrawn' -or (Test-Path (Join-Path $target 'installation.json')) -or -not (Test-Path (Join-Path $target 'migration-withdrawn.json')) -or (Snapshot) -ne $before){throw 'Migration rollback did not preserve both generations'}
 $checks+='rollback-withdraws-new-path-preserves-both-generations'
 $resumed=Invoke-Migration
 if($resumed.release_id -ne $first.release_id){throw 'Withdrawn migration did not resume'}
 $checks+='withdrawn-migration-resumes-with-preserved-high-water-mark'
 $crash=Join-Path $Workspace 'interrupted';$marker=Join-Path $Workspace 'copy-started'
 function Quote([string]$Value){return "'"+$Value.Replace("'","''")+"'"}
 $command=@'
function global:Copy-Item {
 param([string]$LiteralPath,[string]$Destination)
 Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination
 if($Destination.Contains('.stage-')){[IO.File]::WriteAllText(MARKER,'copied');Start-Sleep -Seconds 180}
}
& INSTALLER -Action Migrate -LegacyDir LEGACY -InstallDir TARGET -PackageDir PACKAGE -TrustedThumbprints PINS | Out-Null
'@
 $command=$command.Replace('MARKER',(Quote $marker)).Replace('INSTALLER',(Quote $installer)).Replace('LEGACY',(Quote $legacy)).Replace('TARGET',(Quote $crash)).Replace('PACKAGE',(Quote $Package)).Replace('PINS',('@('+(@($TrustedThumbprints|ForEach-Object {Quote $_}) -join ',')+')'))
 $child=Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command)))) -PassThru
 $until=[DateTime]::UtcNow.AddSeconds(120)
 while(-not (Test-Path $marker)){if($child.HasExited -or [DateTime]::UtcNow -gt $until){throw 'Migration crash barrier not reached'};Start-Sleep -Milliseconds 50}
 $child.Kill();$child.WaitForExit();$child.Dispose();$child=$null
 if(Test-Path (Join-Path $crash 'installation.json')){throw 'Interrupted migration published a selection'}
 [void](Invoke-Migration -Destination $crash)
 & $installer -Action Recover -InstallDir $crash -TrustedThumbprints $TrustedThumbprints | Out-Null
 if((Snapshot) -ne $before -or @(Get-ChildItem (Join-Path $crash 'versions') -Directory -Filter '.stage-*').Count){throw 'Migration recovery failed'}
 $checks+='actual-child-crash-and-resume-without-legacy-mutation'
 $report=@{status='passed';scope='isolated-v1-to-v2-migration';checks=$checks;legacy_executed=$false;worker_started=$false}
}catch{$report=@{status='failed';checks=$checks;error_type=$_.Exception.GetType().FullName};throw}
finally{
 if($child){try{if(-not $child.HasExited){$child.Kill();$child.WaitForExit()}}finally{$child.Dispose()}}
 $report|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8
}
$report|ConvertTo-Json -Depth 5
