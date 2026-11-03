param(
    [ValidateSet('Standard','Enterprise','Custom')][string]$Mode = 'Custom',
    [bool]$ProcessIsolation = ($env:OS -eq 'Windows_NT'),
    [bool]$RequireSignedAgents = $true,
    [string]$SourceSpool = "\\tsclient\C\EnclaveGateway\spool",
    [string]$InstallDir = "$env:LOCALAPPDATA\EnclaveGateway",
    [string]$WorkerPath = '',
    [string]$StopFile = '',
    [string]$StateRoot = '',
    [ValidateSet('Files','Stream')][string]$SpoolProtocol = 'Files',
    [ValidateRange(250,30000)][int]$HeartbeatIntervalMs = 5000,
    [switch]$MigrateLegacyState,
    [string]$RuntimeHelper = '',
    [string[]]$TrustedSignerThumbprints = @(),
    [string]$TrustedSignerThumbprintsCsv = '',
    [switch]$AllowUnsignedLab,
    [switch]$RegisterAutostart,
    [switch]$UseAutostartConfiguration,
    [switch]$RegisterStartup,
    [switch]$UseStartupConfiguration
)
$ErrorActionPreference='Stop'
function Assert-AutostartLocalPath([string]$Path) {
    if(-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or $Path.IndexOfAny([char[]]@('"',"`r","`n",[char]0)) -ge 0){throw 'Autostart requires a local absolute path without control characters'}
    $p=New-Object IO.DirectoryInfo($Path)
    while($p){if($p.Exists -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked autostart path rejected'};$p=$p.Parent}
    if([IO.File]::Exists($Path) -and ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked autostart file rejected'}
}
function Write-AutostartFile([string]$Path,[byte[]]$Bytes,[string]$CopyFrom='') {
    Assert-AutostartLocalPath $Path
    $temporary=$Path+'.incoming-'+[Guid]::NewGuid().ToString('N')
    try {
        if($CopyFrom){[IO.File]::Copy($CopyFrom,$temporary,$false)}else{
            $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        }
        if([IO.File]::Exists($Path)){[IO.File]::Replace($temporary,$Path,[NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
    }finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
function Register-UserAutostart {
    if($env:OS -ne 'Windows_NT'){throw 'HKCU autostart requires Windows'}
    if($Mode -eq 'Custom' -or $AllowUnsignedLab){throw 'Autostart requires named Standard/Enterprise mode without unsigned lab overrides'}
    $script:InstallDir=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([Environment]::ExpandEnvironmentVariables($InstallDir))
    Assert-AutostartLocalPath $InstallDir
    $appData=[IO.Path]::GetFullPath([Environment]::GetFolderPath('LocalApplicationData')).TrimEnd('\')+'\'
    if(-not [IO.Path]::GetFullPath($InstallDir).StartsWith($appData,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') -eq $appData.TrimEnd('\')){throw 'Per-user autostart InstallDir must be a child of LocalApplicationData'}
    $starter=Join-Path $InstallDir 'start_worker.ps1';$settingsPath=Join-Path $InstallDir 'autostart.json'
    Assert-AutostartLocalPath $starter;Assert-AutostartLocalPath $settingsPath
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $policy=if($RequireSignedAgents -or (Get-ExecutionPolicy -Scope Process) -eq 'AllSigned'){' -ExecutionPolicy AllSigned'}elseif($Mode -eq 'Standard' -and (Get-ExecutionPolicy -Scope Process) -eq 'RemoteSigned'){' -ExecutionPolicy RemoteSigned'}else{''}
    $runCommand='"'+$shell+'" -NoProfile -NonInteractive'+$policy+' -File "'+$starter+'" -Mode '+$Mode+' -UseAutostartConfiguration'
    if($runCommand.Length -gt 260){throw 'HKCU Run command exceeds 260 characters; choose a shorter local InstallDir or the signed managed startup task'}
    [void][IO.Directory]::CreateDirectory($InstallDir)
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$sid=$identity.User} finally {$identity.Dispose()}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach($owner in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))){
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($owner,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    # Persist only the owner/DACL sections changed above. PowerShell's Set-Acl
    # also requests SACL access on an existing directory, which unnecessarily
    # requires SeSecurityPrivilege for a normal per-user registration refresh.
    [IO.Directory]::SetAccessControl($InstallDir,$acl)
    $workerHash=(Get-FileHash -LiteralPath $workerSrc -Algorithm SHA256).Hash.ToLowerInvariant()
    $bootstrapHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$generation=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($workerHash+':'+$bootstrapHash)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    $root=Join-Path $InstallDir 'autostart-agents';Assert-AutostartLocalPath $root;[void][IO.Directory]::CreateDirectory($root)
    $lease=Join-Path $root '.bundle-lease'
    if(-not [IO.File]::Exists($lease)){try{$f=[IO.File]::Open($lease,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$f.Dispose()}catch{if(-not [IO.File]::Exists($lease)){throw}}}
    Assert-AutostartLocalPath $lease
    $target=Join-Path $root $generation;$incoming=Join-Path $root ('.incoming-'+[Guid]::NewGuid().ToString('N'))
    Assert-AutostartLocalPath $target
    try {
        if(-not [IO.Directory]::Exists($target)){
            [void][IO.Directory]::CreateDirectory($incoming)
            [IO.File]::Copy($workerSrc,(Join-Path $incoming 'bastion_worker.ps1'),$false)
            [IO.File]::Copy($PSCommandPath,(Join-Path $incoming 'bastion_bootstrap.ps1'),$false)
            [IO.Directory]::Move($incoming,$target)
        }
    }finally{if([IO.Directory]::Exists($incoming)){[IO.Directory]::Delete($incoming,$true)}}
    $localWorker=Join-Path $target 'bastion_worker.ps1';$localBootstrap=Join-Path $target 'bastion_bootstrap.ps1'
    foreach($entry in @(@{path=$localWorker;hash=$workerHash},@{path=$localBootstrap;hash=$bootstrapHash})){
        Assert-AutostartLocalPath $entry.path
        if((Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.hash){throw 'Autostart generation content mismatch'}
        if($RequireSignedAgents){Assert-TrustedScript $entry.path}
    }
    # Copy the bootstrap byte-for-byte: an approved Authenticode signature survives.
    # Settings are data; persistent invocations never carry a migration/lab switch.
    Write-AutostartFile $starter ([byte[]]@()) $localBootstrap
    if($RequireSignedAgents){Assert-TrustedScript $starter}
    $settings=@{revision=1;mode=$Mode;worker_path=$localWorker;worker_sha256=$workerHash;bootstrap_sha256=$bootstrapHash;source_spool=$SourceSpool;state_root=$StateRoot;spool_protocol=$SpoolProtocol;heartbeat_interval_ms=$HeartbeatIntervalMs;process_isolation=$ProcessIsolation;require_signed_agents=$RequireSignedAgents;runtime_helper=$RuntimeHelper;trusted_signers=@($trusted)}|ConvertTo-Json -Depth 5 -Compress
    Write-AutostartFile $settingsPath ([Text.UTF8Encoding]::new($false).GetBytes($settings))
    $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
    try{$key.SetValue('EnclaveGatewayWorker',$runCommand,[Microsoft.Win32.RegistryValueKind]::String);if($key.GetValue('EnclaveGatewayWorker') -cne $runCommand){throw 'Autostart registration readback failed'}}finally{$key.Dispose()}
    $script:workerSrc=$localWorker
}

if(($RegisterAutostart -or $UseAutostartConfiguration) -and ($RegisterStartup -or $UseStartupConfiguration -or $AllowUnsignedLab)){throw 'Autostart modes cannot be mixed with managed/unsigned startup'}
if($RegisterAutostart -and $UseAutostartConfiguration){throw 'Autostart registration and replay are separate modes'}
if($UseAutostartConfiguration){
    if($MigrateLegacyState){throw 'Persistent startup never repeats legacy migration'}
    $InstallDir=$PSScriptRoot
    $settingsFile=Join-Path $PSScriptRoot 'autostart.json';Assert-AutostartLocalPath $settingsFile
    $settings=[IO.File]::ReadAllText($settingsFile)|ConvertFrom-Json
    if($settings.revision -ne 1 -or $settings.mode -cne $Mode -or $Mode -notin @('Standard','Enterprise')){throw 'Invalid autostart mode/configuration'}
    if($settings.process_isolation -isnot [bool] -or $settings.require_signed_agents -isnot [bool]){throw 'Autostart security flags must be boolean'}
    $ProcessIsolation=$settings.process_isolation;$RequireSignedAgents=$settings.require_signed_agents
    if($Mode -eq 'Enterprise' -and (-not $ProcessIsolation -or -not $RequireSignedAgents)){throw 'Enterprise autostart cannot weaken isolation/signatures'}
    $WorkerPath=[string]$settings.worker_path;Assert-AutostartLocalPath $WorkerPath
    $allowed=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'autostart-agents'))+[IO.Path]::DirectorySeparatorChar
    if(-not [IO.Path]::GetFullPath($WorkerPath).StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Autostart worker outside local generations'}
    foreach($pair in @(@{path=$WorkerPath;hash=$settings.worker_sha256},@{path=$PSCommandPath;hash=$settings.bootstrap_sha256})){
        if($pair.hash -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $pair.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pair.hash){throw 'Autostart script content mismatch'}
    }
    $SourceSpool=[string]$settings.source_spool;$StateRoot=[string]$settings.state_root;$RuntimeHelper=[string]$settings.runtime_helper
    $SpoolProtocol=[string]$settings.spool_protocol;$HeartbeatIntervalMs=[int]$settings.heartbeat_interval_ms
    if($SpoolProtocol -notin @('Files','Stream') -or $HeartbeatIntervalMs -lt 250 -or $HeartbeatIntervalMs -gt 30000 -or -not $SourceSpool){throw 'Invalid autostart worker settings'}
    $TrustedSignerThumbprints=@($settings.trusted_signers);$TrustedSignerThumbprintsCsv=''
}
if(($RegisterStartup -or $UseStartupConfiguration) -and $MigrateLegacyState){throw 'Migrate legacy state in foreground before configuring persistent startup'}
if ($Mode -eq 'Standard') {
    if (-not $UseAutostartConfiguration -and -not $PSBoundParameters.ContainsKey('ProcessIsolation')) {$ProcessIsolation=$false}
    if (-not $UseAutostartConfiguration -and -not $PSBoundParameters.ContainsKey('RequireSignedAgents')) {$RequireSignedAgents=$false}
    if ($AllowUnsignedLab -or $RegisterStartup) {throw 'Standard rejects unsigned lab overrides and managed startup tasks; use -RegisterAutostart for per-user logon startup, or Enterprise for a managed signed task'}
}
if ($Mode -eq 'Enterprise' -and ($AllowUnsignedLab -or -not $ProcessIsolation -or -not $RequireSignedAgents)) {
    throw 'Enterprise bootstrap cannot disable signatures or native process isolation'
}
if ($UseStartupConfiguration) {
    if ($RegisterStartup -or $AllowUnsignedLab) {throw 'Invalid persistent startup mode'}
    $settings=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'bastion_startup.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($settings.revision -notin @(1,2,3,4) -or -not $settings.source_spool -or -not $settings.runtime_helper -or -not $settings.trusted_signers.Count) {throw 'Invalid startup configuration'}
    $Mode=if($settings.revision -ge 2){[string]$settings.mode}else{'Custom'}
    if($settings.revision -ge 3){$StateRoot=[string]$settings.state_root;if($settings.heartbeat_interval_ms){$HeartbeatIntervalMs=[int]$settings.heartbeat_interval_ms}}
    if($settings.revision -ge 4){$SpoolProtocol=[string]$settings.spool_protocol;if($SpoolProtocol -notin @('Files','Stream')){throw 'Invalid startup spool protocol'}}
    if($Mode -notin @('Enterprise','Custom')){throw 'Persistent startup requires a signed mode'}
    $ProcessIsolation=$true;$RequireSignedAgents=$true
    $SourceSpool=[string]$settings.source_spool
    $WorkerPath=Join-Path $PSScriptRoot 'bastion_worker.ps1'
    $RuntimeHelper=[string]$settings.runtime_helper
    $TrustedSignerThumbprints=@($settings.trusted_signers)
    $TrustedSignerThumbprintsCsv=''
}
if ($AllowUnsignedLab -and $RegisterStartup) { throw 'Unsigned lab mode cannot register persistent startup' }
$trusted=@($TrustedSignerThumbprints)
if ($TrustedSignerThumbprintsCsv) { $trusted+=@($TrustedSignerThumbprintsCsv.Split(',')) }
$trusted=@($trusted | ForEach-Object { $_.Replace(' ','').ToUpperInvariant() })
foreach ($thumbprint in $trusted) {
    if ($thumbprint -notmatch '^[A-F0-9]{40,64}$') { throw 'Invalid trusted signer identifier' }
}
if (-not $RuntimeHelper) {$RuntimeHelper=Join-Path $InstallDir 'bin\egw-runtime.exe'}
$RuntimeHelper=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([Environment]::ExpandEnvironmentVariables($RuntimeHelper))
$workerSrc=if ($WorkerPath) { $WorkerPath } else { Join-Path $SourceSpool 'bastion_worker.ps1' }
if (-not (Test-Path -LiteralPath $workerSrc -PathType Leaf)) { throw 'Worker file is missing' }
function Assert-TrustedScript([string]$Path) {
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -notin $trusted) {
        throw 'Runtime requires a valid signature from an explicitly trusted publisher'
    }
}
if ($RequireSignedAgents -and -not $AllowUnsignedLab) {
    Assert-TrustedScript $workerSrc
    if($Mode -ne 'Custom'){Assert-TrustedScript $PSCommandPath}
}
if ($ProcessIsolation -and -not $AllowUnsignedLab) {Assert-TrustedScript $RuntimeHelper}
if($RegisterAutostart){Register-UserAutostart}
if ($RegisterStartup) {
    if(-not $ProcessIsolation -or -not $RequireSignedAgents){throw 'Managed startup requires signed native process isolation'}
    Assert-TrustedScript $PSCommandPath
    foreach ($value in @($SourceSpool,$InstallDir,$RuntimeHelper)) {
        if ($value.IndexOfAny([char[]]@('"',"`r","`n")) -ge 0) { throw 'Invalid startup path' }
    }
    $InstallDir=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([Environment]::ExpandEnvironmentVariables($InstallDir))
    $SourceSpool=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([Environment]::ExpandEnvironmentVariables($SourceSpool))
    $workerDst=Join-Path $InstallDir 'bastion_worker.ps1'
    $bootstrapDst=Join-Path $InstallDir 'bastion_bootstrap.ps1'
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments="-NoProfile -NonInteractive -File `"$bootstrapDst`" -UseStartupConfiguration"
    if ($arguments.Length+$shell.Length -gt 32760) {throw 'Startup command exceeds the process command-line limit'}
    [void][IO.Directory]::CreateDirectory($InstallDir)
    Copy-Item -LiteralPath $workerSrc -Destination $workerDst -Force
    Copy-Item -LiteralPath $PSCommandPath -Destination $bootstrapDst -Force
    Assert-TrustedScript $workerDst
    Assert-TrustedScript $bootstrapDst
    $settings=@{revision=4;spool_protocol=$SpoolProtocol;mode=$Mode;state_root=$StateRoot;heartbeat_interval_ms=$HeartbeatIntervalMs;source_spool=$SourceSpool;runtime_helper=$RuntimeHelper;trusted_signers=$trusted}|ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $InstallDir 'bastion_startup.json'),$settings,(New-Object Text.UTF8Encoding($false)))
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$sid=$identity.User.Value;$accountName=$identity.Name} finally {$identity.Dispose()}
    $taskName="EnclaveBastionWorker_$sid"
    $action=New-ScheduledTaskAction -Execute $shell -Argument $arguments -WorkingDirectory $InstallDir
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
    $reconnectClass=Get-CimClass -Namespace 'Root/Microsoft/Windows/TaskScheduler' -ClassName 'MSFT_TaskSessionStateChangeTrigger'
    $reconnect=New-CimInstance -CimClass $reconnectClass -ClientOnly -Property @{StateChange=[uint32]3;UserId=$accountName;Enabled=$true}
    $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
    $options=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger,$reconnect) -Principal $principal -Settings $options -Force | Out-Null
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'EnclaveBastionWorker' -ErrorAction SilentlyContinue
    # One managed resident instance owns this SID's startup and reconnects.
    # Deployment restarts that instance; it must not launch a second foreground
    # worker alongside the scheduled one.
    Stop-ScheduledTask -TaskName $taskName
    $until=[DateTime]::UtcNow.AddSeconds(10)
    while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
        if ([DateTime]::UtcNow -ge $until) {throw 'Previous managed worker did not stop'}
        Start-Sleep -Milliseconds 100
    }
    Start-ScheduledTask -TaskName $taskName
    @{status='startup_registered';task_name=$taskName;worker_health='requires_fresh_attestation'} | ConvertTo-Json -Compress
    return
}
if (($UseStartupConfiguration -or $UseAutostartConfiguration) -and $SourceSpool.StartsWith('\\tsclient\',[StringComparison]::OrdinalIgnoreCase)) {
    $share=[IO.Path]::GetPathRoot($SourceSpool)
    $until=[DateTime]::UtcNow.AddSeconds(30)
    while(-not (Test-Path -LiteralPath $share)) {
        if([DateTime]::UtcNow -ge $until) {throw 'Redirected startup drive unavailable'}
        Start-Sleep -Milliseconds 200
    }
}
# A normal worker return (including an acknowledged stop) ends supervision.
# Only a typed channel fault with a previously validated local journal can retry.
$approvedWorkerHash=(Get-FileHash -LiteralPath $workerSrc -Algorithm SHA256).Hash
$expectedBinding=''
$supervisorMutex=$null;$supervisorHeld=$false
try{
if($SpoolProtocol -eq 'Stream'){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$key=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($SourceSpool).TrimEnd([char[]]'\/').ToLowerInvariant()))).Replace('-','')}finally{$sha.Dispose()}
    $supervisorMutex=New-Object Threading.Mutex($false,('EnclaveGateway.Supervisor.'+$key))
    try{$supervisorHeld=$supervisorMutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$supervisorHeld=$true}
    if(-not $supervisorHeld){throw 'WORKER_ALREADY_RUNNING: one supervisor per spool is allowed'}
}
while($true){
    if($StopFile -and [IO.File]::Exists($StopFile)){break}
    try{
        if((Get-FileHash -LiteralPath $workerSrc -Algorithm SHA256).Hash -cne $approvedWorkerHash){throw 'Worker bytes changed during supervision; restage the approved package'}
        if($RequireSignedAgents -and -not $AllowUnsignedLab){Assert-TrustedScript $workerSrc;Assert-TrustedScript $PSCommandPath}
        if($ProcessIsolation -and -not $AllowUnsignedLab){Assert-TrustedScript $RuntimeHelper}
        & $workerSrc -Mode $Mode -ProcessIsolation:$ProcessIsolation -SpoolDir $SourceSpool -StopFile $StopFile -StateRoot $StateRoot -ExpectedStorageBinding $expectedBinding -SpoolProtocol $SpoolProtocol -HeartbeatIntervalMs $HeartbeatIntervalMs -MigrateLegacyState:$MigrateLegacyState -RuntimeHelper $RuntimeHelper -TrustedSignerThumbprints $trusted -AllowUnsignedLab:$AllowUnsignedLab
        break
    }catch{
        $fault=$_.Exception
        while($fault -and $fault.Data['EGW.StreamDisconnected'] -ne $true){$fault=$fault.InnerException}
        if($SpoolProtocol -ne 'Stream' -or -not $fault -or $fault.Data['EGW.StorageBinding'] -cnotmatch '^[a-f0-9]{64}$'){throw}
        $bindingHash=[string]$fault.Data['EGW.StorageBinding']
        if($expectedBinding -and $expectedBinding -cne $bindingHash){throw 'WORKER_JOURNAL_IDENTITY_MISMATCH: supervisor binding changed'}
        $expectedBinding=$bindingHash;$MigrateLegacyState=$false
        Write-Warning ('STREAM_RECOVERING: '+$fault.Message+' (win32_code='+$fault.Data['EGW.ChannelError']+'); waiting for the same spool and local journal. Reconcile pending transactions; commands are never replayed.')
    }
    $attempt=0
    while($true){
        $delay=@(1000,2000,5000)[[Math]::Min($attempt,2)];$attempt++
        $until=[DateTime]::UtcNow.AddMilliseconds($delay)
        while([DateTime]::UtcNow -lt $until){
            if($StopFile -and [IO.File]::Exists($StopFile)){return}
            Start-Sleep -Milliseconds 100
        }
        if(-not [IO.Directory]::Exists($SourceSpool)){continue}
        $probe=$null
        try{
            $probe=[IO.File]::Open(([IO.Path]::Combine($SourceSpool,'.worker-session')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            break
        }catch{
            $cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException}
            if($cause -isnot [IO.IOException] -or ($cause.HResult -band 65535) -notin @(2,3,6,32,33,53,55,59,64,67,1167,1231,2250)){throw}
        }finally{if($probe){$probe.Dispose()}}
    }
}
}finally{
    if($supervisorHeld){$supervisorMutex.ReleaseMutex()}
    if($supervisorMutex){$supervisorMutex.Dispose()}
}
