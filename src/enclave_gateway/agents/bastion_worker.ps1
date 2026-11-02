param(
    [ValidateSet('Standard','Enterprise','Custom')][string]$Mode = 'Custom',
    [string]$SpoolDir = "\\tsclient\C\EnclaveGateway\spool",
    [int]$PollIntervalMs = 20,
    [ValidateRange(250,30000)][int]$HeartbeatIntervalMs = 5000,
    [ValidateRange(100,60000)][int]$RecoveryScanIntervalMs = 5000,
    [int]$ParallelStreams = 4,
    [int]$MaxMuxSessions = 256,
    [int]$MaxRequestsPerTick = 32,
    [int]$MaxTransactionRecords = 100000,
    [string]$StopFile = "",
    [string]$StateRoot = "",
    [switch]$MigrateLegacyState,
    [bool]$ProcessIsolation = ($env:OS -eq 'Windows_NT'),
    [string]$RuntimeHelper = "$env:LOCALAPPDATA\EnclaveGateway\bin\egw-runtime.exe",
    [string[]]$TrustedSignerThumbprints = @(),
    [switch]$Diagnostics,
    [switch]$AllowUnsignedLab
)

if ($Mode -eq 'Standard' -and -not $PSBoundParameters.ContainsKey('ProcessIsolation')) {$ProcessIsolation=$false}
if ($Mode -eq 'Enterprise') {
    if ($AllowUnsignedLab -or -not $ProcessIsolation -or -not $TrustedSignerThumbprints.Count) {
        throw 'Enterprise worker requires signed native process isolation and explicit trusted publishers'
    }
    $signature=Get-AuthenticodeSignature -LiteralPath $PSCommandPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -notin $TrustedSignerThumbprints) {
        throw 'Enterprise worker signature is not trusted'
    }
}

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'BastionWorker requires a policy-approved FullLanguage script; constrained execution is unsupported'
}
if ($ParallelStreams -lt 1 -or $ParallelStreams -gt 64 -or $MaxMuxSessions -lt 1 -or $MaxRequestsPerTick -lt 1 -or $MaxTransactionRecords -lt 1) {
    throw 'Invalid worker resource limits'
}
$ErrorActionPreference = 'Stop'

$ProgressPreference='SilentlyContinue'
function Move-WorkerFile([string]$Source,[string]$Destination) {
    if([IO.File]::Exists($Destination)){[IO.File]::Replace($Source,$Destination,[NullString]::Value)}else{[IO.File]::Move($Source,$Destination)}
}
function Write-DurableText([string]$Path, [string]$Text) {
    $bytes=[Text.Encoding]::UTF8.GetBytes($Text)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Get-TextHash([string]$Value){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
$instanceLease=$null;$workerMutex=$null;$mutexHeld=$false
try {
[void][IO.Directory]::CreateDirectory($SpoolDir)
$spoolIdentity=Get-TextHash ([IO.Path]::GetFullPath($SpoolDir).TrimEnd([char[]]'\/').ToLowerInvariant())
$workerMutex=New-Object Threading.Mutex($false,('EnclaveGateway.Worker.'+$spoolIdentity))
try{$mutexHeld=$workerMutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$mutexHeld=$true}
if(-not $mutexHeld){throw 'WORKER_ALREADY_RUNNING: one worker per spool is allowed'}
try{$instanceLease=[IO.File]::Open(([IO.Path]::Combine($SpoolDir,'.worker-session')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
catch{throw 'WORKER_ALREADY_RUNNING: spool session lease is busy'}
$stateDir=[IO.Path]::Combine($SpoolDir,'.transactions')
$journalLocation='spool-local'
if($StateRoot -or $SpoolDir.StartsWith('\\')){
    $journalLocation='bastion-local'
    if(-not $StateRoot){
        if(-not $env:LOCALAPPDATA){throw 'A local StateRoot is required for a redirected spool'}
        $StateRoot=[IO.Path]::Combine($env:LOCALAPPDATA,'EnclaveGateway\state')
    }
    $StateRoot=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($StateRoot))
    if($StateRoot.StartsWith('\\')){throw 'The durable worker journal must be local to Bastion'}
    if($env:OS -eq 'Windows_NT' -and (New-Object IO.DriveInfo([IO.Path]::GetPathRoot($StateRoot))).DriveType -eq [IO.DriveType]::Network){throw 'The durable worker journal cannot use a mapped network drive'}
    $parent=New-Object IO.DirectoryInfo($StateRoot)
    while($parent){if($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked journal root rejected'};$parent=$parent.Parent}
    $sid=if($env:OS -eq 'Windows_NT'){
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$identity.User.Value}finally{$identity.Dispose()}
    }else{[Environment]::UserName}
    $owner=Get-TextHash ([Environment]::MachineName+"`n"+$sid)
    $binding=[IO.Path]::Combine($SpoolDir,'worker_storage.json')
    if(-not [IO.File]::Exists($binding)){
        $legacy=@()
        if([IO.Directory]::Exists($stateDir)){$legacy=@([IO.Directory]::EnumerateFiles($stateDir))}
        if(($legacy.Count -or [IO.File]::Exists(([IO.Path]::Combine($SpoolDir,'worker_state.json')))) -and -not $MigrateLegacyState){throw 'LEGACY_STATE_MIGRATION_REQUIRED: stop the old worker and explicitly approve MigrateLegacyState'}
        if($legacy.Count -gt 2*$MaxTransactionRecords){throw 'Legacy journal exceeds migration capacity'}
        $storage=[Guid]::NewGuid().ToString('N');$local=[IO.Path]::Combine($StateRoot,$storage)
        [void][IO.Directory]::CreateDirectory($local)
        if($env:OS -eq 'Windows_NT'){
            $acl=New-Object Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true,$false)
            foreach($principal in @($sid,'S-1-5-18')){
                $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($principal)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $local -AclObject $acl
        }
        foreach($file in $legacy){
            $name=[IO.Path]::GetFileName($file)
            if($name -notmatch '^[A-Za-z0-9_-]{1,128}\.(json|cancel)$' -or (([IO.File]::GetAttributes($file)) -band [IO.FileAttributes]::ReparsePoint)){throw 'Unrecognized legacy journal entry; preserve it for manual reconciliation'}
            $text=[IO.File]::ReadAllText($file)
            if($name.EndsWith('.json')){
                $record=$text|ConvertFrom-Json
                if([string]$record.tx_id -ne [IO.Path]::GetFileNameWithoutExtension($file) -or $record.state -notin @('running','completed','failed','indeterminate','cancelled')){throw 'Invalid legacy journal record'}
            }
            Write-DurableText ([IO.Path]::Combine($local,$name)) $text
        }
        $metadata=@{protocol=2;storage_id=$storage;owner_sha256=$owner}|ConvertTo-Json -Compress
        Write-DurableText ([IO.Path]::Combine($local,'storage.json')) $metadata
        $temporary=$binding+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
        try{Write-DurableText $temporary $metadata;[IO.File]::Move($temporary,$binding)}finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
    }
    $record=[IO.File]::ReadAllText($binding)|ConvertFrom-Json
    if($record.protocol -ne 2 -or $record.storage_id -notmatch '^[a-f0-9]{32}$' -or $record.owner_sha256 -cne $owner){throw 'WORKER_JOURNAL_IDENTITY_MISMATCH: restore the original Bastion account and journal'}
    $stateDir=[IO.Path]::Combine($StateRoot,$record.storage_id)
    if([IO.Directory]::Exists($stateDir) -and ([IO.File]::GetAttributes($stateDir) -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked journal directory rejected'}
    $localMetadata=[IO.Path]::Combine($stateDir,'storage.json')
    if(-not [IO.File]::Exists($localMetadata)){throw 'WORKER_JOURNAL_MISSING: restore local durable state; an empty replacement is forbidden'}
    $localRecord=[IO.File]::ReadAllText($localMetadata)|ConvertFrom-Json
    if($localRecord.protocol -ne 2 -or $localRecord.storage_id -cne $record.storage_id -or $localRecord.owner_sha256 -cne $owner){throw 'WORKER_JOURNAL_IDENTITY_MISMATCH'}
}
[void][IO.Directory]::CreateDirectory($stateDir)
$pendingHints=@{};$knownHints=@{};$hintToken='';$hintSeen=$false;$lastRecovery=-60000
$heartbeatState=$null;$lastHeartbeatMs=0;$lastHintMs=0;$lastDirectoryMs=0;$lastJournalMs=0;$lastResponseMs=0;$lastClaimMs=0;$lastReadMs=0
$stopRequested=$false;$lastMaintenance=-60000;$scanCount=0;$lastScanMs=0;$lastLoopMs=0

[Console]::OutputEncoding = [Text.Encoding]::UTF8
Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
[void][IO.Directory]::CreateDirectory($SpoolDir)
# The selected durable journal has already been opened before allocating runspaces.
$Global:EnclaveMuxSockets = @{}
$pendingMux = New-Object Collections.Generic.List[object]
$activeTxJobs = New-Object Collections.Generic.List[object]
function New-WorkerSlot {
    $runspace=[runspacefactory]::CreateRunspace()
    $runspace.ThreadOptions='ReuseThread'
    $runspace.Open()
    return @{Runspace=$runspace;Busy=$false}
}
# Own each resident runspace directly so scheduling and disposal have explicit
# lifetimes instead of depending on asynchronous pool acquisition resources.
$executionSlots=@(for($index=0;$index -lt $ParallelStreams;$index++){New-WorkerSlot})
$attestationSlot=New-WorkerSlot
$powerShellPath=''
if ($ProcessIsolation) {
    $self=[Diagnostics.Process]::GetCurrentProcess()
    try {$powerShellPath=$self.MainModule.FileName} finally {$self.Dispose()}
}
$clock = [Diagnostics.Stopwatch]::StartNew()
$lastHeartbeat = -30000
$completedCount = 0
$nativeCompletedSinceCleanup = 0
$nativeCleanupCycles = 0
$readRetryCount=0
$workerInstance=[Guid]::NewGuid().ToString('N')
$loadedWorkerHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$workerSignatureStatus='NotSupported'
$workerSigner=''
$runtimeHash=''
$workerSid=''
$workerSessionId=0
if ($env:OS -eq 'Windows_NT') {
    $signature=Get-AuthenticodeSignature -LiteralPath $PSCommandPath
    $workerSignatureStatus=[string]$signature.Status
    if ($signature.SignerCertificate) { $workerSigner=$signature.SignerCertificate.Thumbprint }
    foreach($certificate in @($signature.SignerCertificate,$signature.TimeStamperCertificate)) {if($certificate) {$certificate.Dispose()}}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$workerSid=$identity.User.Value} finally {$identity.Dispose()}
    $self=[Diagnostics.Process]::GetCurrentProcess()
    try {$workerSessionId=$self.SessionId} finally {$self.Dispose()}
}
if ($ProcessIsolation) {
    if (-not (Test-Path -LiteralPath $RuntimeHelper -PathType Leaf)) { throw 'Install the managed runtime before isolated execution' }
    $runtimeHash=(Get-FileHash -LiteralPath $RuntimeHelper -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $AllowUnsignedLab) {
        $signature=Get-AuthenticodeSignature -LiteralPath $RuntimeHelper
        try {
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -notin $TrustedSignerThumbprints) { throw 'Untrusted process runtime' }
        } finally {
            foreach($certificate in @($signature.SignerCertificate,$signature.TimeStamperCertificate)) {if($certificate) {$certificate.Dispose()}}
        }
    }
}
$trustProcess=$null;$trustError=$null
$trustState=[hashtable]::Synchronized(@{Process=$null;Cancelled=$false;Stage='starting'})
$nativeTrust={
    param($Query,$Timeout,$State)
    $ErrorActionPreference='Stop';$read=$null
    try{
        if($State.Cancelled -or $State.Process.HasExited){throw 'Native trust host unavailable'}
        $State.Stage='writing'
        $read=$State.Process.StandardOutput.ReadLineAsync()
        $frame=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Query))
        $State.Process.StandardInput.WriteLine($frame);$State.Process.StandardInput.Flush()
        $State.Stage='waiting'
        if(-not $read.Wait($Timeout)){throw 'Native trust deadline expired'}
        $value=$read.Result|ConvertFrom-Json
        if($value.ExitCode -isnot [int] -or $value.Stdout -isnot [string] -or $value.Stderr -isnot [string]){throw 'Invalid native trust response'}
        $State.Stage='ready';return $value
    }catch{
        $State.Cancelled=$true
        try{if(-not $State.Process.HasExited){$State.Process.Kill()}}catch{}
        return @{ExitCode=125;Stdout='';Stderr='Native trust unavailable';Indeterminate=$true}
    }finally{if($read -and $read.IsCompleted){$read.Dispose()}}
}
function Start-WorkerPipeline($Pipe) {
    # Windows PowerShell retains implicit BeginInvoke input buffers until GC.
    # Own both buffers so their wait handles are released on every completion.
    $inputBuffer=New-Object 'Management.Automation.PSDataCollection[psobject]'
    $outputBuffer=New-Object 'Management.Automation.PSDataCollection[psobject]'
    $inputBuffer.Complete()
    try {return @{Handle=$Pipe.BeginInvoke($inputBuffer,$outputBuffer);Input=$inputBuffer;Output=$outputBuffer}}
    catch {$inputBuffer.Dispose();$outputBuffer.Dispose();throw}
}

function Close-WorkerPipeline($Job) {
    $Job.Input.Dispose(); $Job.Output.Dispose()
    try {$Job.Handle.AsyncWaitHandle.Close()} catch {}
    if ($Job.StopHandle) {try {$Job.StopHandle.AsyncWaitHandle.Close()} catch {}}
    # PowerShell.Dispose owns the error/output buffers, but the remaining
    # PSDataStreams collections also own native wait handles on Windows 5.1.
    # Release these completed, caller-owned streams before discarding a job.
    foreach ($name in @('Debug','Verbose','Warning','Progress','Information','Error')) {
        $stream=$Job.Pipe.Streams.$name
        if ($null -ne $stream) {$stream.Dispose()}
    }
    $Job.Pipe.Dispose()
    $Job.Slot.Busy=$false
}

function Stop-Execution($Job) {
    $Job.Cancelled=$true
    if ($Job.Native) {
        $Job.NativeState.Cancelled=$true
        try {$process=$Job.NativeState.Process; if ($process -and -not $process.HasExited) {$process.Kill()}} catch {}
    }
    else { $Job.StopHandle=$Job.Pipe.BeginStop($null,$null) }
}
$transactionCount = @([IO.Directory]::EnumerateFiles($stateDir,'*.json') | Where-Object {[IO.Path]::GetFileName($_) -ne 'storage.json'}).Count


function Write-State {
    param([string]$TxId, [string]$State)
    $journalStarted=$clock.ElapsedMilliseconds
    $path = [IO.Path]::Combine($stateDir,"$TxId.json")
    $temporary = "$path.tmp"
    $newRecord = -not [IO.File]::Exists($path)
    $json = @{ tx_id=$TxId; state=$State; updated_utc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress
    Write-DurableText $temporary $json
    Move-WorkerFile $temporary $path
    if ($newRecord) { $script:transactionCount++ }
    $script:lastJournalMs=$clock.ElapsedMilliseconds-$journalStarted
}

function Write-Response {
    param([string]$TxId, [int]$ExitCode=0, [string]$Stdout='', [string]$Stderr='', [int]$DurationMs=0, [string]$State='completed', [bool]$StoreState=$true)
    $responseStarted=$clock.ElapsedMilliseconds
    $result = @{ tx_id=$TxId; exit_code=$ExitCode; state=$State; worker_instance=$workerInstance; worker_sha256=$loadedWorkerHash;
        stdout_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Stdout));
        stderr_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Stderr)); duration_ms=$DurationMs }
    $temporary = [IO.Path]::Combine($SpoolDir,"res_$TxId.tmp")
    $path = [IO.Path]::Combine($SpoolDir,"res_$TxId.json")
    [IO.File]::WriteAllText($temporary,($result | ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
    if ($StoreState) { Write-State $TxId $State }
    # A failed rename is retried by maintenance; execution is never replayed.
    try { Move-WorkerFile $temporary $path } catch {}
    $script:completedCount++
    $script:lastResponseMs=$clock.ElapsedMilliseconds-$responseStarted
}

function Close-Mux {
    param([string]$ConnectionId)
    if ($Global:EnclaveMuxSockets.ContainsKey($ConnectionId)) {
        try { $Global:EnclaveMuxSockets[$ConnectionId].Client.Close() } catch {}
        $Global:EnclaveMuxSockets.Remove($ConnectionId)
    }
}

$execute = {
    param([string]$ScriptText)
    $ErrorActionPreference = 'Stop'
    $global:LASTEXITCODE = 0
    try {
        $items = @(& ([scriptblock]::Create($ScriptText)) 2>&1)
        $outLines = New-Object Collections.Generic.List[string]
        $errLines = New-Object Collections.Generic.List[string]
        foreach ($item in $items) {
            if ($item -is [Management.Automation.ErrorRecord]) { $errLines.Add($item.ToString()) }
            elseif ($null -ne $item) { $outLines.Add($item.ToString()) }
        }
        return @{ ExitCode=[int]$LASTEXITCODE; Stdout=($outLines -join "`n"); Stderr=($errLines -join "`n") }
    } catch { return @{ ExitCode=1; Stdout=''; Stderr=($_ | Out-String) } }
}

# Native process creation and pipe writes can block on OS policy or backpressure.
# Keep them in bounded runspaces so the dispatcher continues mux/cancellation turns.
$nativeExecute={
    param($Runtime,$PowerShell,$Child,$Timeout,$State,$Mode='run')
    $ErrorActionPreference='Stop'
    $proc=New-Object Diagnostics.Process
    try {
        if ($State.Cancelled) {return @{ExitCode=125;Stdout='';Stderr='Cancelled before native launch';Indeterminate=$true}}
        $psi=New-Object Diagnostics.ProcessStartInfo
        $psi.FileName=$Runtime; $psi.Arguments=$Mode; $psi.UseShellExecute=$false
        $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
        $psi.StandardOutputEncoding=New-Object Text.UTF8Encoding($false); $psi.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
        $proc.StartInfo=$psi; $State.Process=$proc
        $State.Stage='starting'
        [void]$proc.Start()
        if ($State.Cancelled) {$proc.Kill();return @{ExitCode=125;Stdout='';Stderr='Cancelled during native launch';Indeterminate=$true}}
        $output=$proc.StandardOutput.ReadToEndAsync(); $errorOutput=$proc.StandardError.ReadToEndAsync()
        $bootstrap='[Console]::InputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'
        $query=@{command=@($PowerShell,'-NoProfile','-NonInteractive','-Command',$bootstrap);timeout_ms=$Timeout;stdin_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Child))}|ConvertTo-Json -Compress
        if($Mode -eq 'attest'){$query=$Child}
        $State.Stage='writing'
        $proc.StandardInput.WriteLine($query); $proc.StandardInput.Close()
        $State.Stage='waiting'
        if (-not $proc.WaitForExit($Timeout+2000)) {$proc.Kill();throw 'Owned process deadline expired'}
        $State.Stage='reading'
        $raw=$output.GetAwaiter().GetResult()
        [void]$errorOutput.GetAwaiter().GetResult()
        if ($proc.ExitCode -in @(124,125)) {return @{ExitCode=125;Stdout='';Stderr='Owned process interrupted';Indeterminate=$true}}
        if ($proc.ExitCode -ne 0) {throw 'Owned process failed'}
        $result=$raw | ConvertFrom-Json
        if ($null -eq $result -or $result -is [array] -or $result.ExitCode -isnot [int] -or $result.Stdout -isnot [string] -or $result.Stderr -isnot [string]) {
            throw 'Invalid owned process result'
        }
        return $result
    } catch {
        # A child can have completed an effect before its stdout is damaged or
        # the helper exits without a valid envelope. Never call that definitive.
        return @{ExitCode=125;Stdout='';Stderr='Owned process outcome unavailable';Indeterminate=$true}
    } finally {
        try {if (-not $proc.HasExited) {$proc.Kill()}} catch {}
        # Process.Dispose on Windows PowerShell/.NET Framework does not reliably
        # close readers used through ReadToEndAsync; release them explicitly.
        try {$proc.StandardOutput.Dispose()} catch {}
        try {$proc.StandardError.Dispose()} catch {}
        try {$proc.StandardInput.Dispose()} catch {}
        $State.Process=$null; $proc.Dispose()
        foreach($task in @($output,$errorOutput)) {if ($task -and $task.IsCompleted) {$task.Dispose()}}
    }
}


function Complete-WorkerJobs {
        # Reap shell pipelines without waiting for incomplete work.
        foreach ($job in @($activeTxJobs.ToArray())) {
            if (-not $job.Handle.IsCompleted -and $job.Timer.ElapsedMilliseconds -ge $job.TimeoutMs -and -not $job.Cancelled) {
                Stop-Execution $job
            }
            if (-not $job.Handle.IsCompleted) { continue }
            $activeTxJobs.Remove($job) | Out-Null
            $values=$null
            try {
                [void]$job.Pipe.EndInvoke($job.Handle)
                $values=$job.Output
                if ($values.Count -eq 1 -and $values[0].Indeterminate) {$job.Cancelled=$true}
                if ($job.Cancelled) { throw 'Execution interrupted; external effects may continue' }
                if ($values.Count -ne 1) { throw 'Execution ended without a result' }
                $value=$values[0]
                $state=if ($value.ExitCode -eq 0) { 'completed' } else { 'failed' }
                Write-Response $job.TxId $value.ExitCode $value.Stdout $value.Stderr ([int]$job.Timer.ElapsedMilliseconds) $state
            } catch {
                $state=if ($job.Cancelled) { 'indeterminate' } else { 'failed' }
                $code=if ($job.Cancelled) { 125 } else { 1 }
                Write-Response $job.TxId $code '' ($_ | Out-String) ([int]$job.Timer.ElapsedMilliseconds) $state
            } finally {
                if ($job.StopHandle -and $job.StopHandle.IsCompleted) { try { $job.Pipe.EndStop($job.StopHandle) } catch {} }
                Close-WorkerPipeline $job
                if ($job.Native) {$script:nativeCompletedSinceCleanup++}
            }
        }

}
# EGW_BUNDLE_LEASE_V1: retain a shared lease for this managed generation's lifetime.
$bundleLease=$null
try {
    $generation=Get-Item -LiteralPath (Split-Path -Parent $PSCommandPath)
    if ($generation.Name -cmatch '^[a-f0-9]{64}$' -and $generation.Parent.Name -eq 'agents') {
        $leasePath=[IO.Path]::Combine($generation.Parent.FullName,'.bundle-lease')
        if((Get-Item -LiteralPath $leasePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked bundle lease rejected'}
        $bundleLease=[IO.File]::Open($leasePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $loadedWorkerHash){throw 'Worker bundle changed during startup'}
    }
if($ProcessIsolation){
    $trustProcess=New-Object Diagnostics.Process
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$RuntimeHelper;$start.Arguments="attest-server $PID";$start.UseShellExecute=$false
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
    $trustProcess.StartInfo=$start
    try{
        [void]$trustProcess.Start();$trustState.Process=$trustProcess
        $trustError=$trustProcess.StandardError.ReadToEndAsync()
        $initial=@{worker_path=$PSCommandPath;runtime_path=$RuntimeHelper;worker_sha256=$loadedWorkerHash;runtime_sha256=$runtimeHash;require_signed=(-not $AllowUnsignedLab)}|ConvertTo-Json -Compress
        $trustProcess.StandardInput.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($initial)));$trustProcess.StandardInput.Flush()
        $ready=$trustProcess.StandardOutput.ReadLineAsync()
        if(-not $ready.Wait(120000)){throw 'Native trust host did not become ready'}
        $identity=$ready.Result|ConvertFrom-Json
        if($identity.ready -ne 1){throw "Native trust host initialization failed ($($identity.error):$($identity.native_code))"}
        $trustState.InitializationMs=$identity.initialization_ms
        $ready.Dispose();$trustState.Stage='ready'
    }catch{
        try{if(-not $trustProcess.HasExited){$trustProcess.Kill();$trustProcess.WaitForExit()}}catch{}
        $trustProcess.Dispose();throw
    }
}
    while (-not $stopRequested -and (-not $StopFile -or -not [IO.File]::Exists($StopFile))) {
        $loopStart=$clock.ElapsedMilliseconds
        Complete-WorkerJobs
        $scanStart=$clock.ElapsedMilliseconds
        try{
            $hfile=[IO.File]::Open(([IO.Path]::Combine($SpoolDir,'request_index.json')),[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try{
                if($hfile.Length -gt 65536){throw 'Oversized queue hint'}
                $hreader=New-Object IO.StreamReader($hfile)
                try{$hint=$hreader.ReadToEnd()|ConvertFrom-Json}finally{$hreader.Dispose()}
            }finally{$hfile.Dispose()}
            if($hint.revision -eq 1 -and $hint.token -match '^[a-f0-9]{32}$' -and @($hint.files).Count -le 128 -and $hint.token -cne $hintToken){
                $next=@{}
                foreach($name in @($hint.files)){
                    if($name -isnot [string] -or $name -notmatch '^(req|cancel)_[A-Za-z0-9_-]{1,128}\.json$'){continue}
                    $next[$name]=$true
                    if(-not $knownHints.ContainsKey($name)){$pendingHints[([IO.Path]::Combine($SpoolDir,$name))]=$true}
                }
                $knownHints=$next;$hintToken=$hint.token;$hintSeen=$true
            }
        }catch{}
        $lastHintMs=$clock.ElapsedMilliseconds-$scanStart
        $spoolFiles=@($pendingHints.Keys)
        if(-not $hintSeen -or $clock.ElapsedMilliseconds-$lastRecovery -ge $RecoveryScanIntervalMs){
            $directoryStart=$clock.ElapsedMilliseconds
            $spoolFiles=@([IO.Directory]::EnumerateFiles($SpoolDir))
            $lastDirectoryMs=$clock.ElapsedMilliseconds-$directoryStart
            $scanCount++;$lastRecovery=$clock.ElapsedMilliseconds
        }
        $lastScanMs=$clock.ElapsedMilliseconds-$scanStart
        # Cancellation files have priority over new work. They contain no code.
        foreach ($cancelFile in @($spoolFiles | Where-Object {[IO.Path]::GetFileName($_) -like 'cancel_*.json'} | Select-Object -First $MaxRequestsPerTick)) {
            try {
                $cancel = [IO.File]::ReadAllText($cancelFile) | ConvertFrom-Json
                $cancelId = [string]$cancel.tx_id
                if ($cancelId -notmatch '^[A-Za-z0-9_-]{1,128}$' -or ([IO.Path]::GetFileName($cancelFile)) -ne "cancel_$cancelId.json") { continue }
                [IO.File]::WriteAllText(([IO.Path]::Combine($stateDir,"$cancelId.cancel")), '')
                foreach ($job in @($activeTxJobs.ToArray())) {
                    if ($job.TxId -eq $cancelId -and -not $job.Cancelled) {
                        Stop-Execution $job
                    }
                }
                foreach ($job in @($pendingMux.ToArray())) { if ($job.TxId -eq $cancelId) { $job.Cancelled=$true } }
            } catch {} finally { try{[IO.File]::Delete($cancelFile)}catch{};$pendingHints.Remove($cancelFile) }
        }

        Complete-WorkerJobs

        if ($PSVersionTable.PSEdition -eq 'Desktop' -and $nativeCompletedSinceCleanup -ge 32) {
            # Windows PowerShell/.NET Framework retains internal async-pipe
            # Event handles in finalizable objects even after public Dispose.
            # Bound that backlog by native completions, including sustained
            # load; request collection without waiting on the finalizer thread.
            [GC]::Collect(2,[GCCollectionMode]::Forced,$false)
            $nativeCompletedSinceCleanup=0
            $nativeCleanupCycles++
        }

        # One bounded nonblocking turn per connection. Slow connects/writers never
        # hold the main dispatcher while another connection is ready.
        foreach ($job in @($pendingMux.ToArray())) {
            $done=$false
            try {
                if ($job.Cancelled) { throw 'Mux request cancelled' }
                if ($job.Timer.ElapsedMilliseconds -ge $job.TimeoutMs) { throw 'Mux request deadline expired' }
                $entry=$Global:EnclaveMuxSockets[$job.ConnectionId]
                if (-not $entry) { throw 'Mux session closed' }
                if ($job.Action -eq 'open') {
                    if (-not $job.ConnectHandle.IsCompleted) { continue }
                    $entry.Client.EndConnect($job.ConnectHandle)
                    $entry.Client.NoDelay=$true
                    $entry.Client.Client.Blocking=$false
                    $entry.State='open'
                    Write-Response $job.TxId 0 "MUX_OPEN_OK:$($job.ConnectionId)" '' ([int]$job.Timer.ElapsedMilliseconds)
                    $done=$true
                } else {
                    $socket=$entry.Client.Client
                    if ($job.Offset -lt $job.Bytes.Length -and $socket.Poll(0, [Net.Sockets.SelectMode]::SelectWrite)) {
                        try {
                            $count=$socket.Send($job.Bytes, $job.Offset, [Math]::Min(16384, $job.Bytes.Length-$job.Offset), [Net.Sockets.SocketFlags]::None)
                            if ($count -le 0) { throw 'Mux send made no progress' }
                            $job.Offset+=$count
                        } catch [Net.Sockets.SocketException] {
                            if ($_.Exception.SocketErrorCode -notin @([Net.Sockets.SocketError]::WouldBlock, [Net.Sockets.SocketError]::IOPending, [Net.Sockets.SocketError]::NoBufferSpaceAvailable)) { throw }
                        }
                    }
                    if (-not $entry.ReadEof -and $job.Receive.Length -lt $job.MaxRead -and $socket.Poll(0, [Net.Sockets.SelectMode]::SelectRead)) {
                        $buffer=New-Object byte[] ([Math]::Min(16384, $job.MaxRead-[int]$job.Receive.Length))
                        try {
                            $count=$socket.Receive($buffer, 0, $buffer.Length, [Net.Sockets.SocketFlags]::None)
                            if ($count -eq 0) { $entry.ReadEof=$true } else { $job.Receive.Write($buffer, 0, $count) }
                        } catch [Net.Sockets.SocketException] {
                            if ($_.Exception.SocketErrorCode -ne [Net.Sockets.SocketError]::WouldBlock) { throw }
                        }
                    }
                    if ($job.Offset -eq $job.Bytes.Length) {
                        if ($job.ReadStarted -lt 0) { $job.ReadStarted=$job.Timer.ElapsedMilliseconds }
                        if ($entry.ReadEof -or $job.Receive.Length -gt 0 -or ($job.Timer.ElapsedMilliseconds-$job.ReadStarted) -ge $job.WaitMs) {
                            $prefix=if ($entry.ReadEof) { 'MUX_EOF:' } else { 'MUX_DATA:' }
                            $output=$prefix + [Convert]::ToBase64String($job.Receive.ToArray())
                            Write-Response $job.TxId 0 $output '' ([int]$job.Timer.ElapsedMilliseconds)
                            $done=$true
                        }
                    }
                }
                $entry.LastActive=$clock.ElapsedMilliseconds
            } catch {
                Close-Mux $job.ConnectionId
                Write-Response $job.TxId 1 '' ($_ | Out-String) ([int]$job.Timer.ElapsedMilliseconds) 'failed'
                $done=$true
            } finally {
                if ($done) {
                    if ($job.ConnectHandle) { $job.ConnectHandle.AsyncWaitHandle.Close() }
                    if ($job.Receive) { $job.Receive.Dispose() }
                    if ($Global:EnclaveMuxSockets.ContainsKey($job.ConnectionId)) { $Global:EnclaveMuxSockets[$job.ConnectionId].Busy=$false }
                    $pendingMux.Remove($job) | Out-Null
                }
            }
        }

        foreach ($file in @($spoolFiles | Where-Object {[IO.Path]::GetFileName($_) -like 'req_*.json'} | Sort-Object | Select-Object -First $MaxRequestsPerTick)) {
            # Capture identity before rename; FileInfo metadata can be refreshed
            # against the now-missing original pathname on Windows PowerShell.
            $requestPath=$file
            $filename=[IO.Path]::GetFileName($file)
            $txId=$filename.Substring(4,$filename.Length-9)
            $claim="$requestPath.processing";$requeued=$false
            $claimStart=$clock.ElapsedMilliseconds
            try { [IO.File]::Move($requestPath,$claim);$lastClaimMs=$clock.ElapsedMilliseconds-$claimStart } catch [IO.FileNotFoundException] {$pendingHints.Remove($requestPath);continue} catch {continue}
            try {
                if ($txId -notmatch '^[A-Za-z0-9_-]{1,128}$') {throw 'Invalid transaction filename'}
                try {
                    $readStart=$clock.ElapsedMilliseconds
                    $stream=[IO.File]::Open($claim,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                    try {
                        if ($stream.Length -gt 8388608) {throw 'Envelope exceeds size limit'}
                        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
                        try {$request=$reader.ReadToEnd() | ConvertFrom-Json} finally {$reader.Dispose()}
                    } finally {$stream.Dispose();$lastReadMs=$clock.ElapsedMilliseconds-$readStart}
                } catch {
                    $cause=$_.Exception
                    while($cause.InnerException) {$cause=$cause.InnerException}
                    if (($cause.HResult -band 65535) -in @(32,33)) {
                        # Only reading is retried, before any journal dispatch or
                        # payload execution. ACL denial and malformed data fail.
                        [IO.File]::Move($claim,$requestPath);$requeued=$true
                        $readRetryCount++
                        continue
                    }
                    throw
                }
                if ([string]$request.tx_id -ne $txId) {throw 'Transaction identifier does not match filename'}
                if ($request.expected_worker_instance -and ($request.expected_worker_instance -ne $workerInstance -or $request.expected_worker_sha256 -ne $loadedWorkerHash)) {
                    Write-Response $txId 125 '' 'Worker instance/release changed before dispatch' 0 'cancelled'
                    continue
                }
                if ([IO.File]::Exists(([IO.Path]::Combine($stateDir,"$txId.cancel")))) {
                    Write-Response $txId 125 '' 'Cancelled before dispatch' 0 'cancelled'
                    continue
                }
                $stateFile=[IO.Path]::Combine($stateDir,"$txId.json")
                if ([IO.File]::Exists($stateFile)) {
                    # Never execute a reused request id, including after a restart.
                    if (-not ([IO.File]::Exists(([IO.Path]::Combine($SpoolDir,"res_$txId.json"))))) {
                        Write-Response $txId 125 '' 'Existing transaction; query the Host journal' 0 'indeterminate'
                    }
                    continue
                }
                if ($transactionCount -ge $MaxTransactionRecords) {
                    Write-Response $txId 75 '' 'Transaction capacity reached; explicit spool archival is required' 0 'failed' $false
                    continue
                }
                $timeout=if ($request.timeout_ms) { [int]$request.timeout_ms } else { 120000 }
                if ($timeout -lt 1 -or $timeout -gt 86400000) { throw 'Invalid request timeout' }
                if ($request.expires_unix_ms) {
                    $remaining=[double]$request.expires_unix_ms-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                    if ($remaining -le 0) { Write-Response $txId 125 '' 'Deadline expired before dispatch' 0 'cancelled'; continue }
                    $timeout=[int][Math]::Max(1,[Math]::Min($timeout,$remaining))
                } elseif ($ProcessIsolation) { throw 'Isolated execution requires a request deadline' }
                if($request.op -eq 'stop'){
                    if($activeTxJobs.Count -or $pendingMux.Count -or $Global:EnclaveMuxSockets.Count){Write-Response $txId 75 '' 'WORKER_BUSY: close active streams and wait for jobs before stopping' 0 'failed';continue}
                    Write-Response $txId 0 'WORKER_STOP_ACCEPTED' '' 0 'completed'
                    $stopRequested=$true;break
                }
                $action=[string]$request.mux_action
                $slot=$null
                if($request.op -eq 'attest') {
                    if(-not $attestationSlot.Busy){$slot=$attestationSlot}
                } elseif(-not $action) {
                    foreach($available in $executionSlots){if(-not $available.Busy){$slot=$available;break}}
                }
                if ((-not $action -or $request.op -eq 'attest') -and $null -eq $slot) {
                    # Leave queued requests unexecuted until a slot is free;
                    # their original absolute deadline remains authoritative.
                    [IO.File]::Move($claim,$requestPath);$requeued=$true
                    continue
                }
                Write-State $txId 'running'
                if ($request.op -eq 'attest') {
                    $nonce=[string]$request.attestation_nonce
                    if ($nonce -notmatch '^[a-f0-9]{64}$') { throw 'Invalid attestation challenge' }
                    $evidence=@{ protocol_revision=1; version='0.3.0'; runtime_loaded_sha256=$runtimeHash; runtime_current_sha256='';
                        trust_initialization_ms=$trustState.InitializationMs;
                        nonce=$nonce; instance_id=$workerInstance; pid=$PID; session_id=$workerSessionId;
                        spool_kind=if ($SpoolDir.StartsWith('\\tsclient\',[StringComparison]::OrdinalIgnoreCase)) {'redirected'} else {'local'}; loaded_sha256=$loadedWorkerHash; current_sha256='';
                        signature_status='NotSupported'; signer=''; loaded_signature_status=$workerSignatureStatus; loaded_signer=$workerSigner;
                        os_user=[Environment]::UserName; sid=$workerSid;
                        execution_model=if ($ProcessIsolation) {'owned-process-job'} else {'runspace'} }
                    $query=@{ evidence=$evidence; worker_path=$PSCommandPath; runtime_path=$RuntimeHelper; process_isolation=$ProcessIsolation } | ConvertTo-Json -Compress -Depth 5
                    $query64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($query))
                    # OS trust/revocation providers can block and retain native
                    # resources. Windows verification uses an owned child;
                    # neither its lifetime nor its handles belong to the dispatcher.
                    $probe=@'
param($Encoded)
$q=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded)) | ConvertFrom-Json
$e=$q.evidence
$e.current_sha256=(Get-FileHash -LiteralPath $q.worker_path -Algorithm SHA256).Hash.ToLowerInvariant()
if ($q.process_isolation) { $e.runtime_current_sha256=(Get-FileHash -LiteralPath $q.runtime_path -Algorithm SHA256).Hash.ToLowerInvariant() }
if ($env:OS -eq 'Windows_NT') {
    $s=Get-AuthenticodeSignature -LiteralPath $q.worker_path
    $e.signature_status=[string]$s.Status
    if ($s.SignerCertificate) {$e.signer=$s.SignerCertificate.Thumbprint}
    foreach($certificate in @($s.SignerCertificate,$s.TimeStamperCertificate)) {if($certificate) {$certificate.Dispose()}}
    if ($q.process_isolation) {
        $s=Get-AuthenticodeSignature -LiteralPath $q.runtime_path
        $e | Add-Member -NotePropertyName runtime_signature_status -NotePropertyValue ([string]$s.Status)
        $e | Add-Member -NotePropertyName runtime_signer -NotePropertyValue $(if ($s.SignerCertificate) {$s.SignerCertificate.Thumbprint} else {''})
        foreach($certificate in @($s.SignerCertificate,$s.TimeStamperCertificate)) {if($certificate) {$certificate.Dispose()}}
    }
}
$e | ConvertTo-Json -Compress -Depth 5
'@
                    $probe64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe))
                    $text="& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$probe64')))) '$query64'"
                    $pipe=[powershell]::Create(); $pipe.Runspace=$slot.Runspace
                    $nativeState=$null
                    if($ProcessIsolation){
                        if((Get-FileHash -LiteralPath $RuntimeHelper -Algorithm SHA256).Hash.ToLowerInvariant() -ne $runtimeHash){throw 'Runtime changed before trust probe launch'}
                        $nativeState=$trustState
                        [void]$pipe.AddScript($nativeTrust).AddArgument($query).AddArgument($timeout).AddArgument($nativeState)
                    }else{[void]$pipe.AddScript($execute).AddArgument($text)}
                    try {$invocation=Start-WorkerPipeline $pipe} catch {$pipe.Dispose();throw}
                    $slot.Busy=$true
                    $activeTxJobs.Add(@{Slot=$slot;TxId=$txId;Attestation=$true;Native=$ProcessIsolation;NativeState=$nativeState;Pipe=$pipe;Handle=$invocation.Handle;Input=$invocation.Input;Output=$invocation.Output;StopHandle=$null;Timer=[Diagnostics.Stopwatch]::StartNew();TimeoutMs=$timeout;Cancelled=$false})
                } elseif ($action) {
                    $connectionId=[string]$request.conn_id
                    if ($connectionId -notmatch '^mux_[0-9a-f]+$' -and $action -ne 'close_all') { throw 'Invalid mux identifier' }
                    if ($action -eq 'open') {
                        if ($Global:EnclaveMuxSockets.Count -ge $MaxMuxSessions -or $Global:EnclaveMuxSockets.ContainsKey($connectionId)) { throw 'Mux session limit or duplicate id' }
                        $hostName=[string]$request.target_host
                        $port=[int]$request.target_port
                        if (-not $hostName -or $port -lt 1 -or $port -gt 65535) { throw 'Invalid mux endpoint' }
                        $family=if ($hostName.Contains(':')) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
                        $client=New-Object Net.Sockets.TcpClient($family)
                        try { $handle=$client.BeginConnect($hostName, $port, $null, $null) } catch { $client.Close(); throw }
                        $Global:EnclaveMuxSockets[$connectionId]=@{ Client=$client; State='connecting'; Busy=$true; ReadEof=$false; LastActive=$clock.ElapsedMilliseconds }
                        $pendingMux.Add(@{ TxId=$txId; ConnectionId=$connectionId; Action='open'; ConnectHandle=$handle; Timer=[Diagnostics.Stopwatch]::StartNew(); TimeoutMs=$timeout; Cancelled=$false; Receive=$null })
                    } elseif ($action -eq 'io') {
                        if (-not $Global:EnclaveMuxSockets.ContainsKey($connectionId)) { Write-Response $txId 0 'MUX_EOF:'; continue }
                        $entry=$Global:EnclaveMuxSockets[$connectionId]
                        if ($entry.Busy -or $entry.State -ne 'open') { throw 'Concurrent I/O on one mux session is not supported' }
                        $bytes=[Convert]::FromBase64String([string]$request.tx_b64)
                        $maxRead=if ($request.max_read_bytes) { [int]$request.max_read_bytes } else { 65536 }
                        $wait=if ($null -ne $request.read_wait_ms) { [int]$request.read_wait_ms } else { 100 }
                        if ($bytes.Length -gt 1048576 -or $maxRead -lt 1 -or $maxRead -gt 4194304 -or $wait -lt 0 -or $wait -gt 1000) { throw 'Invalid mux buffer limits' }
                        $entry.Busy=$true
                        $pendingMux.Add(@{ TxId=$txId; ConnectionId=$connectionId; Action='io'; ConnectHandle=$null; Timer=[Diagnostics.Stopwatch]::StartNew(); TimeoutMs=$timeout; Cancelled=$false;
                            Bytes=$bytes; Offset=0; MaxRead=$maxRead; WaitMs=$wait; ReadStarted=-1; Receive=(New-Object IO.MemoryStream) })
                    } elseif ($action -eq 'close_all') {
                        foreach ($id in @($Global:EnclaveMuxSockets.Keys)) { Close-Mux $id }
                        Write-Response $txId 0 'MUX_CLOSED_ALL'
                    } elseif ($action -eq 'close') {
                        Close-Mux $connectionId
                        Write-Response $txId 0 'MUX_CLOSED'
                    } elseif ($action -eq 'shutdown_write') {
                        if ($Global:EnclaveMuxSockets.ContainsKey($connectionId)) { $Global:EnclaveMuxSockets[$connectionId].Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send) }
                        Write-Response $txId 0 'MUX_SHUTDOWN_OK'
                    } else { throw 'Unsupported mux action' }
                } else {
                    $scriptText=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$request.payload_b64))
                    if ($scriptText -match '\$Global:EnclaveMuxSockets|\$Global:EnclaveRunspacePool') { throw 'Worker state is accessible only through structured mux operations' }
                    if ($ProcessIsolation) {
                        $encodedScript=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($scriptText))
                        $child="[Console]::OutputEncoding=New-Object Text.UTF8Encoding(`$false); & { $($execute.ToString()) } ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encodedScript'))) | ConvertTo-Json -Compress"
                        $state=[hashtable]::Synchronized(@{Process=$null;Cancelled=$false;Stage='queued'})
                        $pipe=[powershell]::Create(); $pipe.Runspace=$slot.Runspace
                        [void]$pipe.AddScript($nativeExecute).AddArgument($RuntimeHelper).AddArgument($powerShellPath).AddArgument($child).AddArgument($timeout).AddArgument($state)
                        try {$invocation=Start-WorkerPipeline $pipe} catch {$pipe.Dispose();throw}
                        $slot.Busy=$true
                        $activeTxJobs.Add(@{Slot=$slot;TxId=$txId;Native=$true;NativeState=$state;Pipe=$pipe;Handle=$invocation.Handle;Input=$invocation.Input;Output=$invocation.Output;StopHandle=$null;Timer=[Diagnostics.Stopwatch]::StartNew();TimeoutMs=$timeout;Cancelled=$false})
                    } else {
                        $pipe=[powershell]::Create()
                        $pipe.Runspace=$slot.Runspace
                        [void]$pipe.AddScript($execute).AddArgument($scriptText)
                        try {$invocation=Start-WorkerPipeline $pipe} catch {$pipe.Dispose();throw}
                        $slot.Busy=$true
                        $activeTxJobs.Add(@{ Slot=$slot; TxId=$txId; Pipe=$pipe; Handle=$invocation.Handle; Input=$invocation.Input; Output=$invocation.Output; StopHandle=$null; Timer=[Diagnostics.Stopwatch]::StartNew(); TimeoutMs=$timeout; Cancelled=$false })
                    }
                }
            } catch {
                if ($txId -match '^[A-Za-z0-9_-]{1,128}$') { Write-Response $txId 1 '' ($_ | Out-String) 0 'failed' }
            } finally { try{[IO.File]::Delete($claim)}catch{};if(-not $requeued){$pendingHints.Remove($requestPath)};Complete-WorkerJobs }
        }

        if ($clock.ElapsedMilliseconds-$lastHeartbeat -ge $HeartbeatIntervalMs) {
            foreach ($file in @($spoolFiles | Where-Object {[IO.Path]::GetFileName($_) -like 'res_*.tmp'})) {
                try {Move-WorkerFile $file ([IO.Path]::ChangeExtension($file,'json'))} catch {}
            }
            foreach ($id in @($Global:EnclaveMuxSockets.Keys)) {
                if (-not $Global:EnclaveMuxSockets[$id].Busy -and $clock.ElapsedMilliseconds-$Global:EnclaveMuxSockets[$id].LastActive -gt 300000) {Close-Mux $id}
            }
            if($clock.ElapsedMilliseconds-$lastMaintenance -ge 60000){
                foreach($file in @($spoolFiles | Where-Object {[IO.Path]::GetFileName($_) -like 'res_*.json'} | Select-Object -First 4)){
                    try{if(([DateTime]::UtcNow-[IO.File]::GetLastWriteTimeUtc($file)).TotalSeconds -gt 300){[IO.File]::Delete($file)}}catch{}
                }
                $lastMaintenance=$clock.ElapsedMilliseconds
            }
            $nativeStages=@{}
            foreach($job in $activeTxJobs.ToArray()) {if($job.Native) {$stage=[string]$job.NativeState.Stage; $nativeStages[$stage]=1+[int]$nativeStages[$stage]}}
            $self=[Diagnostics.Process]::GetCurrentProcess()
            $heartbeatState=@{ status='running';protocol_revision=2;heartbeat_interval_ms=$HeartbeatIntervalMs;last_heartbeat_ms=$lastHeartbeatMs;last_hint_ms=$lastHintMs;last_directory_ms=$lastDirectoryMs;last_journal_ms=$lastJournalMs;last_response_ms=$lastResponseMs;last_claim_ms=$lastClaimMs;last_read_ms=$lastReadMs;journal_location=$journalLocation;directory_scans=$scanCount;last_scan_ms=$lastScanMs;last_loop_ms=$lastLoopMs;trust_initialization_ms=$trustState.InitializationMs; read_retry_count=$readRetryCount; native_stages=$nativeStages; working_set_bytes=$self.WorkingSet64; handles=$self.HandleCount; threads=$self.Threads.Count; pid=$PID; language_mode=[string]$ExecutionContext.SessionState.LanguageMode; powershell_edition=[string]$PSVersionTable.PSEdition; uptime_sec=[int]$clock.Elapsed.TotalSeconds;
                security_mode=$Mode.ToLowerInvariant(); execution_model=if ($ProcessIsolation) {"owned-process-job"} else {"runspace"}; parallel_streams=$ParallelStreams; active_mux_streams=$Global:EnclaveMuxSockets.Count; active_tx_jobs=$activeTxJobs.Count;
                pending_mux=$pendingMux.Count; completed_transactions=$completedCount; native_cleanup_cycles=$nativeCleanupCycles; transaction_records=$transactionCount; transaction_capacity=$MaxTransactionRecords; last_heartbeat_utc=(Get-Date).ToUniversalTime().ToString('o') }
            $self.Dispose()
            if ($Diagnostics) {
                $heartbeatState.pending_mux_details=@($pendingMux.ToArray() | ForEach-Object {@{tx_id=$_.TxId;action=$_.Action;elapsed_ms=$_.Timer.ElapsedMilliseconds;offset=$_.Offset;bytes=$_.Bytes.Length;read_started=$_.ReadStarted;wait_ms=$_.WaitMs;received=$_.Receive.Length}})
            }
            $heartbeatStart=$clock.ElapsedMilliseconds
            $temporary=[IO.Path]::Combine($SpoolDir,'worker_state.tmp')
            [IO.File]::WriteAllText($temporary, ($heartbeatState | ConvertTo-Json -Compress -Depth 5), (New-Object Text.UTF8Encoding($false)))
            try{Move-WorkerFile $temporary ([IO.Path]::Combine($SpoolDir,'worker_state.json'))}catch{}
            $lastHeartbeat=$clock.ElapsedMilliseconds
            $lastHeartbeatMs=$lastHeartbeat-$heartbeatStart
        }
        $lastLoopMs=$clock.ElapsedMilliseconds-$loopStart
        Start-Sleep -Milliseconds ([Math]::Max(1, [Math]::Min($PollIntervalMs, 50)))
    }
} finally {
    try {
    if($trustProcess){
        try{if(-not $trustProcess.HasExited){$trustProcess.Kill();$trustProcess.WaitForExit()}}catch{}
        foreach($name in @('StandardInput','StandardOutput','StandardError')){try{$trustProcess.$name.Dispose()}catch{}}
        $trustProcess.Dispose()
        if($trustError -and $trustError.IsCompleted){$trustError.Dispose()}
    }
    foreach ($job in @($activeTxJobs.ToArray())) {
        try {Stop-Execution $job; $job.Pipe.Stop()}
        catch {} finally {
            Close-WorkerPipeline $job
        }
    }
    foreach ($job in @($pendingMux.ToArray())) {
        if ($job.ConnectHandle) { $job.ConnectHandle.AsyncWaitHandle.Close() }
        if ($job.Receive) { $job.Receive.Dispose() }
    }
    foreach ($id in @($Global:EnclaveMuxSockets.Keys)) { Close-Mux $id }
    foreach($slot in $executionSlots){$slot.Runspace.Close();$slot.Runspace.Dispose()}
    $attestationSlot.Runspace.Close()
    $attestationSlot.Runspace.Dispose()
    } finally {if($bundleLease){$bundleLease.Dispose()}}
}

} finally {
    try {
        if($instanceLease){
            if($heartbeatState -isnot [hashtable]){$heartbeatState=@{}}
            $heartbeatState.status='stopped';$heartbeatState.protocol_revision=2;$heartbeatState.last_heartbeat_utc=[DateTime]::UtcNow.ToString('o');$heartbeatState.instance_id=$workerInstance
            $stoppedJson=$heartbeatState|ConvertTo-Json -Compress -Depth 5
            $temporary=[IO.Path]::Combine($SpoolDir,('worker_state.'+[Guid]::NewGuid().ToString('N')+'.tmp'))
            try{[IO.File]::WriteAllText($temporary,$stoppedJson,(New-Object Text.UTF8Encoding($false)));Move-WorkerFile $temporary ([IO.Path]::Combine($SpoolDir,'worker_state.json'))}catch{}
        }
    }finally{
        if($instanceLease){$instanceLease.Dispose()}
        if($mutexHeld){$workerMutex.ReleaseMutex()}
        if($workerMutex){$workerMutex.Dispose()}
    }
}
