param([Parameter(Mandatory=$true)][string]$PackageV1,[Parameter(Mandatory=$true)][string]$PackageV2,
      [Parameter(Mandatory=$true)][string[]]$TrustedThumbprints,[Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Workspace){throw 'Use a new disposable qualification workspace'}
[void][IO.Directory]::CreateDirectory($Workspace)
$installed=Join-Path $Workspace 'installed';$installer=Join-Path $PackageV2 'install_windows.ps1'
$checks=@();$child=$null
function Invoke-Managed([string]$Package,[string]$Action='Install',[string]$Target=$installed){
    $arguments=@{TrustedThumbprints=$TrustedThumbprints;InstallDir=$Target;Action=$Action}
    if($Package){$arguments.PackageDir=$Package}
    return (& $installer @arguments | Out-String | ConvertFrom-Json)
}
function Current([string]$Target=$installed){return (Get-Content (Join-Path $Target 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json).current}
$report=@{status='running';scope='disposable-windows-versioned-install';checks=@()}
try{
    $first=Invoke-Managed $PackageV1;$oldRuntime=$first.runtime_path;$oldHash=(Get-FileHash $oldRuntime -Algorithm SHA256).Hash
    $second=Invoke-Managed $PackageV2
    if($first.release_id -eq $second.release_id -or (Current) -ne $second.release_id){throw 'Distinct upgrade not selected'}
    if((Get-FileHash $oldRuntime -Algorithm SHA256).Hash -ne $oldHash){throw 'Previous pinned runtime changed'}
    $checks+='upgrade-keeps-previous-generation'
    $rollback=Invoke-Managed '' 'Rollback'
    if($rollback.release_id -ne $first.release_id){throw 'Rollback selected wrong generation'}
    $checks+='rollback'
    $tampered=Join-Path $Workspace 'tampered';Copy-Item $PackageV2 $tampered -Recurse
    Add-Content (Join-Path $tampered 'bastion_worker.ps1') '# tampered fixture'
    $rejected=$false;try{[void](Invoke-Managed $tampered)}catch{$rejected=$true}
    if(-not $rejected -or (Current) -ne $first.release_id){throw 'Tampered upgrade changed selection'}
    $checks+='tamper-preserves-current'
    $handle=New-Object IO.FileStream((Join-Path $installed 'installation.json'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try{$rejected=$false;try{[void](Invoke-Managed $PackageV2)}catch{$rejected=$true};if(-not $rejected){throw 'Locked publication unexpectedly succeeded'}}finally{$handle.Dispose()}
    if((Current) -ne $first.release_id){throw 'Locked publication changed current version'}
    $checks+='publication-sharing-failure-preserves-current'
    $crashTarget=Join-Path $Workspace 'crash-installed';[void](Invoke-Managed $PackageV1 'Install' $crashTarget)
    $marker=Join-Path $Workspace 'copy-started.txt'
    function Quote([string]$Value){return "'"+$Value.Replace("'","''")+"'"}
    $script=@'
function global:Copy-Item {
 param([string]$LiteralPath,[string]$Destination)
 Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination
 if($Destination.Contains('.stage-')){[IO.File]::WriteAllText(MARKER,'stage-copy-started');Start-Sleep -Seconds 180}
}
& INSTALLER -PackageDir PACKAGE -TrustedThumbprints TRUST -InstallDir TARGET | Out-Null
'@
    $script=$script.Replace('MARKER',(Quote $marker)).Replace('INSTALLER',(Quote $installer)).Replace('PACKAGE',(Quote $PackageV2)).Replace('TARGET',(Quote $crashTarget)).Replace('TRUST',('@('+(@($TrustedThumbprints|ForEach-Object {Quote $_}) -join ',')+')'))
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $child=Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -PassThru
    $until=[DateTime]::UtcNow.AddSeconds(120)
    while(-not (Test-Path $marker)){
        if($child.HasExited -or [DateTime]::UtcNow -gt $until){throw 'Crash observer did not reach staging'}
        Start-Sleep -Milliseconds 50
    }
    $child.Kill();$child.WaitForExit();$child.Dispose();$child=$null
    if((Current $crashTarget) -ne $first.release_id){throw 'Killed staging selected a partial version'}
    [void](Invoke-Managed '' 'Recover' $crashTarget)
    if((Current $crashTarget) -ne $first.release_id -or @(Get-ChildItem (Join-Path $crashTarget 'versions') -Directory -Filter '.stage-*').Count){throw 'Interrupted stage recovery failed'}
    $checks+='actual-process-crash-during-staging'
    $lock=New-Object IO.FileStream((Join-Path $installed '.deployment.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{$rejected=$false;try{[void](Invoke-Managed '' 'Status')}catch{$rejected=$true};if(-not $rejected){throw 'Concurrent deployment lock ignored'}}finally{$lock.Dispose()}
    $checks+='concurrent-deployment-rejected'
    $previous=Join-Path (Join-Path (Join-Path $installed 'versions') $second.release_id) 'agents\bastion_worker.ps1'
    Add-Content $previous '# broken previous generation fixture'
    $rejected=$false;try{[void](Invoke-Managed '' 'Rollback')}catch{$rejected=$true}
    if(-not $rejected -or (Current) -ne $first.release_id){throw 'Invalid previous generation selected'}
    $checks+='corrupt-rollback-target-rejected'
    $damagedTarget=Join-Path $Workspace 'damaged-current'
    [void](Invoke-Managed $PackageV1 'Install' $damagedTarget)
    $damaged=Invoke-Managed $PackageV2 'Install' $damagedTarget
    Add-Content (Join-Path $damaged.agents_path 'bastion_worker.ps1') '# damaged selected generation fixture'
    $repaired=Invoke-Managed '' 'Rollback' $damagedTarget
    if($repaired.release_id -ne $first.release_id){throw 'Damaged current version blocked verified rollback'}
    $checks+='corrupt-current-can-rollback-to-verified-previous'
    $report=@{status='passed';scope='disposable-windows-versioned-install';checks=$checks;first_release=$first.release_id;second_release=$second.release_id;production_signing='not_qualified'}
} catch {$report=@{status='failed';scope='disposable-windows-versioned-install';checks=$checks;error_type=$_.Exception.GetType().Name};throw}
finally{
    if($child){try{if(-not $child.HasExited){$child.Kill();$child.WaitForExit()}}finally{$child.Dispose()}}
    $report|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8
}
$report|ConvertTo-Json -Depth 5
