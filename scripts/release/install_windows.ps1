param([string]$PackageDir, [Parameter(Mandatory=$true)][string[]]$TrustedThumbprints,
      [string]$InstallDir="$env:LOCALAPPDATA\EnclaveGateway",
      [ValidateSet('Install','Rollback','Status','Recover')][string]$Action='Install')
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'Managed installation requires Windows'}
$InstallDir=[IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir))
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {$sid=$identity.User.Value;$administrative=(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} finally {$identity.Dispose()}
function Assert-NoReparse([string]$Path) {
    $current=$Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Managed paths cannot contain reparse points'}
        }
        $parent=Split-Path $current -Parent
        if ($parent -eq $current) {break};$current=$parent
    }
}
function Protect-Directory([string]$Path) {
    $directory=Get-Item -LiteralPath $Path -Force
    # Persist the DACL alone. Set-Acl with a new complete descriptor can request
    # SACL privileges unavailable to the standard account installing its files.
    $acl=$directory.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
    $acl.SetAccessRuleProtection($true,$false)
    foreach($rule in @($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))) {$acl.RemoveAccessRuleSpecific($rule)}
    foreach($owner in @($sid,'S-1-5-18')) {
        $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($owner)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    $directory.SetAccessControl($acl)
}
function Read-Selection {
    $path=Join-Path $InstallDir 'installation.json'
    if (-not (Test-Path -LiteralPath $path)) {return $null}
    $value=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    if ($value.revision -ne 2 -or $value.max_sequence -isnot [int] -or $value.max_sequence -lt 1 -or $value.channel -cnotmatch '^[a-z0-9][a-z0-9-]{0,31}$' -or $value.highest_release -notmatch '^[a-f0-9]{64}$' -or $value.current -notmatch '^[a-f0-9]{64}$' -or ($value.previous -and $value.previous -notmatch '^[a-f0-9]{64}$')) {throw 'Invalid installation selection'}
    return $value
}
function Assert-Version([string]$Version) {
    if ($Version -notmatch '^[a-f0-9]{64}$') {throw 'Invalid release identity'}
    $directory=Join-Path (Join-Path $InstallDir 'versions') $Version
    Assert-NoReparse $directory
    $release=Join-Path $directory 'release'
    if ((Get-FileHash (Join-Path $release 'signature-manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Version) {throw 'Installed manifest identity mismatch'}
    # Use this approved entry point's verifier, not a verifier selected by metadata.
    & (Join-Path $PSScriptRoot 'verify_windows.ps1') -PackageDir $release -TrustedThumbprints $TrustedThumbprints | Out-Null
    $manifest=Get-Content (Join-Path $release 'signature-manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json
    foreach($item in $manifest.files) {
        if ($item.file -in @('egw-runtime.exe','egw-askpass.exe')) {$deployed=Join-Path (Join-Path $directory 'bin') $item.file}
        elseif($item.file -in @('bastion_worker.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1')) {$deployed=Join-Path (Join-Path $directory 'agents') $item.file}
        else {continue}
        Assert-NoReparse $deployed
        if ((Get-FileHash -LiteralPath $deployed -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.sha256) {throw 'Installed payload hash mismatch'}
    }
    return $directory
}
function Select-Version([string]$Current,[string]$Previous,[int]$Maximum,[string]$Highest,[string]$Channel) {
    $temporary=Join-Path $InstallDir ('.selection-'+[Guid]::NewGuid().ToString('N'))
    $path=Join-Path $InstallDir 'installation.json'
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes((@{revision=2;current=$Current;previous=$Previous;max_sequence=$Maximum;highest_release=$Highest;channel=$Channel}|ConvertTo-Json -Compress))
        $stream=New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
        if(Test-Path -LiteralPath $path) {[IO.File]::Replace($temporary,$path,[NullString]::Value)} else {[IO.File]::Move($temporary,$path)}
    } finally {if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
Assert-NoReparse $InstallDir
if (Test-Path -LiteralPath $InstallDir) {
    $owner=(Get-Acl -LiteralPath $InstallDir).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($sid,'S-1-5-18') -and -not ($administrative -and $owner -eq 'S-1-5-32-544')) {throw 'Installation directory belongs to a different account'}
} else {[void][IO.Directory]::CreateDirectory($InstallDir)}
Protect-Directory $InstallDir
$lock=$null;$stage=$null
try {
    $lock=New-Object IO.FileStream((Join-Path $InstallDir '.deployment.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $versions=Join-Path $InstallDir 'versions';Assert-NoReparse $versions
    [void][IO.Directory]::CreateDirectory($versions);Protect-Directory $versions
    $selection=Read-Selection
    if ($selection -and $Action -ne 'Rollback') {[void](Assert-Version $selection.current)}
    if ($Action -eq 'Install') {
        if (-not $PackageDir) {throw 'PackageDir is required for Install'}
        & (Join-Path $PSScriptRoot 'verify_windows.ps1') -PackageDir $PackageDir -TrustedThumbprints $TrustedThumbprints | Out-Null
        $version=(Get-FileHash (Join-Path $PackageDir 'signature-manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $metadata=Get-Content (Join-Path $PackageDir 'signature-manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json
        if($selection){
            if($metadata.channel -cne $selection.channel){throw 'Release channel change requires a separate installation'}
            if($version -ne $selection.current -and ($metadata.sequence -lt $selection.max_sequence -or ($metadata.sequence -eq $selection.max_sequence -and $version -ne $selection.highest_release))){throw 'Release downgrade or sequence reuse rejected; use explicit Rollback for the verified previous generation'}
        }
        $maximum=[int]$metadata.sequence;$highest=$version
        if($selection -and $selection.max_sequence -gt $maximum){$maximum=$selection.max_sequence;$highest=$selection.highest_release}
        $destination=Join-Path $versions $version
        if (-not (Test-Path -LiteralPath $destination)) {
            $stage=Join-Path $versions ('.stage-'+[Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($stage);Protect-Directory $stage
            foreach($name in @('release','bin','agents')) {[void][IO.Directory]::CreateDirectory((Join-Path $stage $name))}
            foreach($name in @('bastion_worker.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1','verify_windows.ps1','install_windows.ps1','egw-runtime.exe','egw-askpass.exe','signature-manifest.json','signature-manifest.p7s')) {
                Copy-Item -LiteralPath (Join-Path $PackageDir $name) -Destination (Join-Path (Join-Path $stage 'release') $name)
            }
            & (Join-Path $PSScriptRoot 'verify_windows.ps1') -PackageDir (Join-Path $stage 'release') -TrustedThumbprints $TrustedThumbprints | Out-Null
            foreach($name in @('bastion_worker.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1')) {Copy-Item -LiteralPath (Join-Path (Join-Path $stage 'release') $name) -Destination (Join-Path (Join-Path $stage 'agents') $name)}
            foreach($name in @('egw-runtime.exe','egw-askpass.exe')) {Copy-Item -LiteralPath (Join-Path (Join-Path $stage 'release') $name) -Destination (Join-Path (Join-Path $stage 'bin') $name)}
            [IO.Directory]::Move($stage,$destination);$stage=$null
        }
        [void](Assert-Version $version)
        if (-not $selection -or $selection.current -ne $version) {
            Select-Version $version $(if($selection){$selection.current}else{''}) $maximum $highest $metadata.channel
        }
    } elseif($Action -eq 'Rollback') {
        if (-not $selection -or -not $selection.previous) {throw 'No previous installed version'}
        [void](Assert-Version $selection.previous)
        Select-Version $selection.previous $selection.current $selection.max_sequence $selection.highest_release $selection.channel
    } elseif(-not $selection) {throw 'No selected installed version'}
    if($Action -eq 'Recover') {
        foreach($abandoned in @(Get-ChildItem -LiteralPath $versions -Directory -Filter '.stage-*')) {
            if($abandoned.Name -notmatch '^\.stage-[a-f0-9]{32}$'){continue}
            Assert-NoReparse $abandoned.FullName
            foreach($item in @(Get-ChildItem -LiteralPath $abandoned.FullName -Recurse -Force)) {
                if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Abandoned stage contains a reparse point'}
            }
            Remove-Item -LiteralPath $abandoned.FullName -Recurse -Force
        }
    }
    $selected=Read-Selection;$directory=Assert-Version $selected.current
    # Existing pinned paths keep their old generation. Switching the selection
    # never launches a worker, changes VPN state, or rewrites release pins.
    @{status='installed_files_only';action=$Action;worker_started=$false;release_id=$selected.current;previous_release_id=$selected.previous;
      helper_path=(Join-Path (Join-Path $directory 'bin') 'egw-askpass.exe');runtime_path=(Join-Path (Join-Path $directory 'bin') 'egw-runtime.exe');
      agents_path=(Join-Path $directory 'agents');activation='explicit_repin_and_startup_required'}|ConvertTo-Json
} finally {
    if($stage -and (Test-Path -LiteralPath $stage)){Remove-Item -LiteralPath $stage -Recurse -Force}
    if($lock){$lock.Dispose()}
}
