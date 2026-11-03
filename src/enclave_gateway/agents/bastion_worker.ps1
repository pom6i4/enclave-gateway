param(
    [ValidateSet('Standard','Enterprise','Custom')][string]$Mode = 'Custom',
    [string]$SpoolDir = "\\tsclient\C\EnclaveGateway\spool",
    [int]$PollIntervalMs = 20,
    [ValidateSet('Files','Stream')][string]$SpoolProtocol = 'Files',
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
    for($attempt=0;$true;$attempt++){
        try{
            if([IO.File]::Exists($Destination)){[IO.File]::Replace($Source,$Destination,[NullString]::Value)}else{[IO.File]::Move($Source,$Destination)}
            return
        }catch{
            $cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException}
            if(($cause.HResult -band 65535) -notin @(32,33) -or $attempt -ge 19){throw}
            Start-Sleep -Milliseconds 10
        }
    }
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
    if($streamTxIds.ContainsKey($TxId)){
        try{
            if($StoreState){Write-State $TxId $State}
            Send-StreamResponse $result
        }catch{
            # Delivery/storage failure after execution is indeterminate to the
            # caller. Never fabricate an execution failure or replay its payload.
            $streamState.Error='Stream response publication failed; reconcile the transaction journal'
            $streamState.Stop=$true
        }
        $streamTxIds.Remove($TxId)
        $script:completedCount++;$script:lastResponseMs=$clock.ElapsedMilliseconds-$responseStarted
        return
    }
    $temporary = [IO.Path]::Combine($SpoolDir,"res_$TxId.tmp")
    $path = [IO.Path]::Combine($SpoolDir,"res_$TxId.json")
    [IO.File]::WriteAllText($temporary,($result | ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
    if ($StoreState) { Write-State $TxId $State }
    # A failed rename is retried by maintenance; execution is never replayed.
    try { Move-WorkerFile $temporary $path } catch {}
    $script:completedCount++
    $script:lastResponseMs=$clock.ElapsedMilliseconds-$responseStarted
}


# EGW_STREAM_V1: keep redirected handles warm; only local durable journal
# writes precede dispatch. Hashes seal frames, not the channel's identity.
$streamState=$null;$streamReservedBytes=0;$streamPipes=@();$streamTxIds=@{};$streamPending=New-Object Collections.Generic.Queue[object]
function Start-StreamPipe($Code,$Shared) {
    $pipe=[powershell]::Create()
    [void]$pipe.AddScript($Code).AddArgument($Shared)
    try{$handle=$pipe.BeginInvoke()}catch{$pipe.Dispose();throw}
    $script:streamPipes+=@{Pipe=$pipe;Handle=$handle}
}
function Initialize-StreamIpc {
    $requestPath=[IO.Path]::Combine($SpoolDir,('ipc_req_'+$workerInstance+'.bin'))
    foreach($path in @($requestPath)){
        $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));$file.Dispose()
    }
    $script:streamState=[hashtable]::Synchronized(@{Stop=$false;Error='';In=(New-Object 'Collections.Concurrent.ConcurrentQueue[object]');Out=(New-Object 'Collections.Concurrent.ConcurrentQueue[object]');RequestPath=$requestPath;Spool=$SpoolDir;Instance=$workerInstance;Heartbeat='';HighWater=[long]0;NextTicket=[long]0;Prepared=(New-Object 'Collections.Concurrent.ConcurrentDictionary[long,object]');Opening=(New-Object 'Collections.Concurrent.ConcurrentDictionary[long,bool]');Expected=(New-Object 'Collections.Concurrent.ConcurrentDictionary[long,bool]');ReadMs=0;WriteMs=0;WriteOpenMs=0;WriteIoMs=0;HeartbeatMs=0;FramesIn=0;FramesOut=0;ReaderReady=$false;WriterReady=$false})
    Start-StreamPipe {
        param($Shared)
        $ErrorActionPreference='Stop';$file=$null;$sha=[Security.Cryptography.SHA256]::Create()
        try{
            $file=[IO.File]::Open($Shared.RequestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            [void]($sha.ComputeHash((New-Object byte[] 0)));[void]('{"ready":true}'|ConvertFrom-Json)
            $Shared.ReaderReady=$true;$bytes=New-Object byte[] 65536;$buffer='';$offset=[long]0
            while(-not $Shared.Stop){
                if($Shared.In.Count -ge 128){Start-Sleep -Milliseconds 5;continue}
                $timer=[Diagnostics.Stopwatch]::StartNew();$count=$file.Read($bytes,0,$bytes.Length);$Shared.ReadMs=$timer.ElapsedMilliseconds
                if($count){$buffer += [Text.Encoding]::ASCII.GetString($bytes,0,$count)}
                while($buffer.Length){
                    $start=$buffer.IndexOf('EGWS1 ',[StringComparison]::Ordinal)
                    if($start -lt 0){$drop=[Math]::Max(0,$buffer.Length-5);$offset+=$drop;$buffer=$buffer.Substring($drop);break}
                    if($start){$offset+=$start;$buffer=$buffer.Substring($start)}
                    $end=$buffer.IndexOf("`n")
                    if($end -lt 0){if($buffer.Length -gt 1398176){$offset+=6;$buffer=$buffer.Substring(6);continue};break}
                    # A producer may have died mid-frame. A fresh marker cannot
                    # occur in Base64, so recover the next independently sealed frame.
                    $next=$buffer.IndexOf('EGWS1 ',6,[StringComparison]::Ordinal)
                    if($next -ge 0 -and $next -lt $end){$offset+=$next;$buffer=$buffer.Substring($next);continue}
                    $frameStart=$offset;$offset+=$end+1;$line=$buffer.Substring(0,$end);$buffer=$buffer.Substring($end+1)
                    if($line.Length -gt 1398175 -or $line -cnotmatch '^EGWS1 ([0-9a-f]{64}) ([A-Za-z0-9+/]*={0,2})$'){continue}
                    $digest=$Matches[1];$encoded=$Matches[2]
                    try{
                        $body=[Convert]::FromBase64String($encoded)
                        if($body.Length -gt 1048576){continue}
                        $actual=[BitConverter]::ToString($sha.ComputeHash($body)).Replace('-','').ToLowerInvariant()
                        if($actual -cne $digest){continue}
                        $value=([Text.UTF8Encoding]::new($false,$true)).GetString($body)|ConvertFrom-Json
                        if($value -isnot [Management.Automation.PSCustomObject]){continue}
                        $compound=@($value.PSObject.Properties|Where-Object {$v=$_.Value;$null -ne $v -and ($v -is [Management.Automation.PSCustomObject] -or ($v -is [Collections.IEnumerable] -and $v -isnot [string]))})
                        if($compound.Count -or $frameStart%4096 -ne 0){continue}
                        $ticket=[long]($frameStart/4096)
                        $nextBlock=[long][Math]::Ceiling($offset/4096.0)
                        if([string]$value.tx_id -notmatch '^[A-Za-z0-9_-]{1,128}$'){continue}
                        if($value.op -ne 'cancel'){[void]$Shared.Expected.TryAdd($ticket,$true)}
                        $value|Add-Member -NotePropertyName __stream_ticket -NotePropertyValue $ticket -Force
                        [Threading.Monitor]::Enter($Shared.SyncRoot)
                        try{if($nextBlock -gt $Shared.HighWater){$Shared.HighWater=$nextBlock}}finally{[Threading.Monitor]::Exit($Shared.SyncRoot)}
                        $Shared.In.Enqueue($value);$Shared.FramesIn++
                    }catch{}
                }
                if(-not $count){Start-Sleep -Milliseconds 5}
            }
        }catch{$Shared.Error='Stream request reader failed';$Shared.Stop=$true}finally{if($file){$file.Dispose()};$sha.Dispose()}
    } $streamState
    # Bounded lookahead hides redirected CreateFile latency from command delivery.
    # A ticket is the physical 4 KiB request block, never a mutable Host counter.
    for($preparer=0;$preparer -lt 4;$preparer++){
    Start-StreamPipe {
        param($Shared)
        $ErrorActionPreference='Stop';$file=$null
        try{
            while(-not $Shared.Stop){
                foreach($key in @($Shared.Prepared.Keys)){
                    if($key -lt $Shared.HighWater -and -not $Shared.Expected.ContainsKey($key)){
                        $unused=$null
                        if($Shared.Prepared.TryRemove($key,[ref]$unused)){$unused.Dispose()}
                    }
                }
                $ticket=[long]-1
                [Threading.Monitor]::Enter($Shared.SyncRoot)
                try{
                    if($Shared.NextTicket -lt $Shared.HighWater){$Shared.NextTicket=$Shared.HighWater}
                    # Keep the initial reserve ready before advertising the
                    # worker. Afterwards, avoid four metadata opens competing
                    # with every result while the reserve is still healthy.
                    $prepareLimit=if($Shared.HighWater -eq 0 -or $Shared.Prepared.Count -lt 8){4}else{1}
                    if($Shared.Opening.Count -lt $prepareLimit -and $Shared.NextTicket -lt 16384 -and $Shared.NextTicket -lt $Shared.HighWater+32 -and $Shared.Prepared.Count+$Shared.Opening.Count -lt 32){
                        $candidate=[long]$Shared.NextTicket;$Shared.NextTicket++
                        if($Shared.Opening.TryAdd($candidate,$true)){$ticket=$candidate}
                    }
                }finally{[Threading.Monitor]::Exit($Shared.SyncRoot)}
                if($ticket -lt 0){Start-Sleep -Milliseconds 5;continue}
                try{
                    $path=[IO.Path]::Combine($Shared.Spool,('ipc_res_'+$Shared.Instance+'_'+$ticket+'.bin'))
                    $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                    if(-not $Shared.Prepared.TryAdd($ticket,$file)){throw 'Response ticket collision'}
                    $file=$null
                }finally{$removed=$false;[void]$Shared.Opening.TryRemove($ticket,[ref]$removed)}
            }
        }catch{$Shared.Error='Stream response preparation failed';$Shared.Stop=$true}finally{if($file){$file.Dispose()}}
    } $streamState
    }
    for($writer=0;$writer -lt [Math]::Min(4,$ParallelStreams);$writer++){
    Start-StreamPipe {
        param($Shared)
        $ErrorActionPreference='Stop';$file=$null
        try{
            $Shared.WriterReady=$true
            while(-not $Shared.Stop -or $Shared.Out.Count){
                $item=$null
                if($Shared.Out.TryDequeue([ref]$item)){
                    $ticket=[long]$item.Ticket
                    if($ticket -lt 0 -or $ticket -ge 16384){throw 'Invalid response ticket'}
                    $bytes=[Text.Encoding]::ASCII.GetBytes($item.Frame)
                    $timer=[Diagnostics.Stopwatch]::StartNew();$deadline=[DateTime]::UtcNow.AddSeconds(30)
                    while($null -eq $file){
                        if($Shared.Prepared.TryRemove($ticket,[ref]$file)){break}
                        $openHere=$false
                        [Threading.Monitor]::Enter($Shared.SyncRoot)
                        try{
                            if(-not $Shared.Prepared.ContainsKey($ticket) -and -not $Shared.Opening.ContainsKey($ticket)){
                                $openHere=$Shared.Opening.TryAdd($ticket,$true)
                            }
                        }finally{[Threading.Monitor]::Exit($Shared.SyncRoot)}
                        if($openHere){
                            try{
                                $path=[IO.Path]::Combine($Shared.Spool,('ipc_res_'+$Shared.Instance+'_'+$ticket+'.bin'))
                                $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                            }finally{$removed=$false;[void]$Shared.Opening.TryRemove($ticket,[ref]$removed)}
                        }elseif($Shared.Stop -or [DateTime]::UtcNow -ge $deadline){throw 'Response preparation unavailable'}
                        else{Start-Sleep -Milliseconds 5}
                    }
                    $removed=$false;[void]$Shared.Expected.TryRemove($ticket,[ref]$removed)
                    $Shared.WriteOpenMs=$timer.ElapsedMilliseconds;$ioTimer=[Diagnostics.Stopwatch]::StartNew()
                    try{$file.Write($bytes,0,$bytes.Length);$file.Flush()}finally{$file.Dispose();$file=$null}
                    $Shared.WriteIoMs=$ioTimer.ElapsedMilliseconds;$Shared.WriteMs=$timer.ElapsedMilliseconds
                    [Threading.Monitor]::Enter($Shared.SyncRoot)
                    try{$Shared.FramesOut++}finally{[Threading.Monitor]::Exit($Shared.SyncRoot)}
                }else{Start-Sleep -Milliseconds 5}
            }
        }catch{$Shared.Error='Stream response writer failed';$Shared.Stop=$true}finally{if($file){$file.Dispose()}}
    } $streamState
    }
    Start-StreamPipe {
        param($Shared)
        $ErrorActionPreference='Stop';$last='';$slot='a';$initial=$true
        try{
            while(-not $Shared.Stop){
                $json=$Shared.Heartbeat
                if($json -and $json -cne $last){
                    $timer=[Diagnostics.Stopwatch]::StartNew()
                    # One slot remains readable while the other is published.
                    # QGA's read-only sharing must not serialize a request behind
                    # a redirected File.Replace of its heartbeat.
                    $pulse=[IO.Path]::Combine($Shared.Spool,('worker_pulse_'+$Shared.Instance+'_'+$slot+'.json'))
                    $published=$false
                    for($attempt=0;$attempt -lt 20;$attempt++){
                        try{[IO.File]::WriteAllText($pulse,$json,[Text.UTF8Encoding]::new($false));$published=$true;break}catch{
                            $cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException}
                            if(($cause.HResult -band 65535) -notin @(32,33)){throw}
                            Start-Sleep -Milliseconds 10
                        }
                    }
                    if(-not $published){continue}
                    if($initial){
                        # Compatibility marker for startup observers. In stream
                        # mode the alternating snapshots carry live telemetry.
                        $temporary=[IO.Path]::Combine($Shared.Spool,'worker_state.tmp');$target=[IO.Path]::Combine($Shared.Spool,'worker_state.json')
                        [IO.File]::WriteAllText($temporary,$json,[Text.UTF8Encoding]::new($false))
                        if([IO.File]::Exists($target)){[IO.File]::Replace($temporary,$target,[NullString]::Value)}else{[IO.File]::Move($temporary,$target)}
                        $initial=$false
                    }
                    $Shared.HeartbeatMs=$timer.ElapsedMilliseconds;$last=$json;$slot=if($slot -eq 'a'){'b'}else{'a'}
                }
                Start-Sleep -Milliseconds 25
            }
        }catch{$Shared.Error='Stream heartbeat publisher failed';$Shared.Stop=$true}
    } $streamState
    $readyDeadline=$clock.ElapsedMilliseconds+30000
    while(-not $streamState.ReaderReady -or -not $streamState.WriterReady -or $streamState.Prepared.Count -lt 32){
        if($streamState.Stop -or $clock.ElapsedMilliseconds -gt $readyDeadline){throw 'Stream handles did not become ready'}
        Start-Sleep -Milliseconds 10
    }
    $descriptor=@{revision=3;block_bytes=4096;instance=$workerInstance;worker_sha256=$loadedWorkerHash}|ConvertTo-Json -Compress
    $temporary=[IO.Path]::Combine($SpoolDir,'ipc_descriptor.tmp')
    [IO.File]::WriteAllText($temporary,$descriptor,[Text.UTF8Encoding]::new($false))
    Move-WorkerFile $temporary ([IO.Path]::Combine($SpoolDir,'ipc_descriptor.json'))
}
function Send-StreamResponse($Result) {
    $json=$Result|ConvertTo-Json -Compress -Depth 8
    $bytes=[Text.Encoding]::UTF8.GetBytes($json)
    # Keep a bounded control reserve. Near capacity, deliver output through
    # its existing immutable response file and enqueue only a small marker.
    $estimatedFrame=72+4*[Math]::Ceiling($bytes.Length/3.0)
    if($bytes.Length -gt 32768 -or $script:streamReservedBytes+$estimatedFrame -gt 66060288){
        $path=[IO.Path]::Combine($SpoolDir,('res_'+$Result.tx_id+'.json'));$temporary=$path+'.tmp'
        [IO.File]::WriteAllBytes($temporary,$bytes);Move-WorkerFile $temporary $path
        $json=@{tx_id=$Result.tx_id;legacy_result=$true;worker_instance=$workerInstance;worker_sha256=$loadedWorkerHash}|ConvertTo-Json -Compress
        $bytes=[Text.Encoding]::UTF8.GetBytes($json)
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    if($streamState.Out.Count -ge 256){throw 'Stream response backlog reached capacity; reconcile the Host journal'}
    $frame='EGWS1 '+$digest+' '+[Convert]::ToBase64String($bytes)+"`n"
    if($script:streamReservedBytes+$frame.Length -gt 67108864){throw 'Stream response capacity reached'}
    $script:streamReservedBytes+=$frame.Length
    $streamState.Out.Enqueue(@{Ticket=[long]$streamTxIds[$Result.tx_id];Frame=$frame})
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
    if($SpoolProtocol -eq 'Stream'){
        # Ready means resident parsers and Standard execution slots are warm;
        # the first request must not pay module discovery or codec JIT costs.
        foreach($slot in @($executionSlots)+@($attestationSlot)){
            $warm=[powershell]::Create();$warm.Runspace=$slot.Runspace
            try{
                [void]$warm.AddScript("[void]('{`"ready`":true}'|ConvertFrom-Json);[void](@{ready=1}|ConvertTo-Json -Compress);Write-Output 'EGW_READY'")
                [void]$warm.Invoke();if($warm.Streams.Error.Count){throw 'Resident slot initialization failed'}
            }finally{$warm.Dispose()}
        }
        Initialize-StreamIpc
    }
    while (-not $stopRequested -and (-not $StopFile -or -not [IO.File]::Exists($StopFile))) {
        $loopStart=$clock.ElapsedMilliseconds
        Complete-WorkerJobs
        if($streamState -and $streamState.Stop){throw $streamState.Error}
        $scanStart=$clock.ElapsedMilliseconds
        if($SpoolProtocol -eq 'Files'){
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
        }else{$spoolFiles=@()}
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

        $dispatchItems=New-Object Collections.Generic.List[object]
        if($SpoolProtocol -eq 'Stream'){
            # Read new control messages before revisiting occupied execution
            # slots. A full pending batch must never starve cancellation.
            $incoming=$null;$incomingCount=0
            while($incomingCount -lt 128 -and $streamState.In.TryDequeue([ref]$incoming)){
                $incomingCount++
                if($incoming.op -eq 'cancel'){$dispatchItems.Add(@{Stream=$true;Value=$incoming})}
                elseif($streamPending.Count -lt 128){$streamPending.Enqueue($incoming)}
                else{
                    $busyId=[string]$incoming.tx_id
                    if($busyId -match '^[A-Za-z0-9_-]{1,128}$'){
                        $streamTxIds[$busyId]=[long]$incoming.__stream_ticket
                        if([IO.File]::Exists(([IO.Path]::Combine($stateDir,($busyId+'.json'))))){Write-Response $busyId 125 '' 'Existing transaction; query the Host journal' 0 'indeterminate' $false}
                        else{Write-Response $busyId 75 '' 'WORKER_BUSY: bounded stream queue is full; request was not executed' 0 'failed' $false}
                    }
                }
                $incoming=$null
            }
            $requestsThisTick=0
            while($streamPending.Count -and $requestsThisTick -lt $MaxRequestsPerTick){
                $dispatchItems.Add(@{Stream=$true;Value=$streamPending.Dequeue()});$requestsThisTick++
            }
        }else{
            foreach($path in @($spoolFiles | Where-Object {[IO.Path]::GetFileName($_) -like 'req_*.json'} | Sort-Object | Select-Object -First $MaxRequestsPerTick)){$dispatchItems.Add(@{Stream=$false;Path=$path})}
        }
        foreach ($item in $dispatchItems) {
            $file=$item.Path
            if($item.Stream){
                $request=$item.Value;$txId=[string]$request.tx_id
                if($txId -notmatch '^[A-Za-z0-9_-]{1,128}$'){continue}
                if($request.op -eq 'cancel'){
                    Write-DurableText ([IO.Path]::Combine($stateDir,"$txId.cancel")) ''
                    foreach($job in @($activeTxJobs.ToArray())){if($job.TxId -eq $txId -and -not $job.Cancelled){Stop-Execution $job}}
                    foreach($job in @($pendingMux.ToArray())){if($job.TxId -eq $txId){$job.Cancelled=$true}}
                    continue
                }
                $streamTxIds[$txId]=[long]$request.__stream_ticket;$claim=$null;$requestPath=$null;$requeued=$false
            }else{
            # Capture identity before rename; FileInfo metadata can be refreshed
            # against the now-missing original pathname on Windows PowerShell.
            $requestPath=$file
            $filename=[IO.Path]::GetFileName($file)
            $txId=$filename.Substring(4,$filename.Length-9)
            $claim="$requestPath.processing";$requeued=$false
            $claimStart=$clock.ElapsedMilliseconds
            try { [IO.File]::Move($requestPath,$claim);$lastClaimMs=$clock.ElapsedMilliseconds-$claimStart } catch [IO.FileNotFoundException] {$pendingHints.Remove($requestPath);continue} catch {continue}
            }
            try {
                if ($txId -notmatch '^[A-Za-z0-9_-]{1,128}$') {throw 'Invalid transaction filename'}
                if(-not $item.Stream){
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
                    if($item.Stream){$streamPending.Enqueue($request)}else{[IO.File]::Move($claim,$requestPath)};$requeued=$true
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
            } finally { if(-not $item.Stream){try{[IO.File]::Delete($claim)}catch{};if(-not $requeued){$pendingHints.Remove($requestPath)}};Complete-WorkerJobs }
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
            $heartbeatState=@{ status='running';instance_id=$workerInstance;worker_sha256=$loadedWorkerHash;spool_protocol=$SpoolProtocol.ToLowerInvariant();protocol_revision=2;heartbeat_interval_ms=$HeartbeatIntervalMs;last_heartbeat_ms=$lastHeartbeatMs;last_hint_ms=$lastHintMs;last_directory_ms=$lastDirectoryMs;last_journal_ms=$lastJournalMs;last_response_ms=$lastResponseMs;last_claim_ms=$lastClaimMs;last_read_ms=$lastReadMs;journal_location=$journalLocation;directory_scans=$scanCount;last_scan_ms=$lastScanMs;last_loop_ms=$lastLoopMs;trust_initialization_ms=$trustState.InitializationMs; read_retry_count=$readRetryCount; native_stages=$nativeStages; working_set_bytes=$self.WorkingSet64; handles=$self.HandleCount; threads=$self.Threads.Count; pid=$PID; language_mode=[string]$ExecutionContext.SessionState.LanguageMode; powershell_edition=[string]$PSVersionTable.PSEdition; uptime_sec=[int]$clock.Elapsed.TotalSeconds;
                security_mode=$Mode.ToLowerInvariant(); execution_model=if ($ProcessIsolation) {"owned-process-job"} else {"runspace"}; parallel_streams=$ParallelStreams; active_mux_streams=$Global:EnclaveMuxSockets.Count; active_tx_jobs=$activeTxJobs.Count;
                pending_mux=$pendingMux.Count; completed_transactions=$completedCount; native_cleanup_cycles=$nativeCleanupCycles; transaction_records=$transactionCount; transaction_capacity=$MaxTransactionRecords; last_heartbeat_utc=(Get-Date).ToUniversalTime().ToString('o') }
            $self.Dispose()
            if ($Diagnostics) {
                $heartbeatState.pending_mux_details=@($pendingMux.ToArray() | ForEach-Object {@{tx_id=$_.TxId;action=$_.Action;elapsed_ms=$_.Timer.ElapsedMilliseconds;offset=$_.Offset;bytes=$_.Bytes.Length;read_started=$_.ReadStarted;wait_ms=$_.WaitMs;received=$_.Receive.Length}})
            }
            $heartbeatStart=$clock.ElapsedMilliseconds
            if($SpoolProtocol -eq 'Stream'){$heartbeatState.stream=@{request_read_ms=$streamState.ReadMs;response_write_ms=$streamState.WriteMs;response_open_ms=$streamState.WriteOpenMs;response_io_ms=$streamState.WriteIoMs;heartbeat_ms=$streamState.HeartbeatMs;frames_in=$streamState.FramesIn;frames_out=$streamState.FramesOut;prepared_responses=$streamState.Prepared.Count;preparing_responses=$streamState.Opening.Count};$streamState.Heartbeat=$heartbeatState|ConvertTo-Json -Compress -Depth 5}else{
            $temporary=[IO.Path]::Combine($SpoolDir,'worker_state.tmp')
            [IO.File]::WriteAllText($temporary, ($heartbeatState | ConvertTo-Json -Compress -Depth 5), (New-Object Text.UTF8Encoding($false)))
            try{Move-WorkerFile $temporary ([IO.Path]::Combine($SpoolDir,'worker_state.json'))}catch{}
            }
            $lastHeartbeat=$clock.ElapsedMilliseconds
            $lastHeartbeatMs=$lastHeartbeat-$heartbeatStart
        }
        $lastLoopMs=$clock.ElapsedMilliseconds-$loopStart
        Start-Sleep -Milliseconds ([Math]::Max(1, [Math]::Min($PollIntervalMs, 50)))
    }
} finally {
    try {
    if($streamState){
        $streamState.Stop=$true
        try{
            foreach($job in $streamPipes){
                try{[void]$job.Pipe.EndInvoke($job.Handle)}finally{$job.Pipe.Dispose()}
            }
        }finally{
            foreach($prepared in @($streamState.Prepared.Values)){$prepared.Dispose()}
            $streamState.Prepared.Clear()
        }
        # Endpoints are immutable per instance; retain them for reconciliation.
        # A stopped descriptor cannot authorize a new worker instance.
    }
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
            $heartbeatState.status='stopped';if($streamState -and $streamState.Error){$heartbeatState.stream_error=$streamState.Error};$heartbeatState.protocol_revision=2;$heartbeatState.last_heartbeat_utc=[DateTime]::UtcNow.ToString('o');$heartbeatState.instance_id=$workerInstance
            $stoppedJson=$heartbeatState|ConvertTo-Json -Compress -Depth 5
            if($streamState){
                foreach($slot in @('a','b')){
                    try{[IO.File]::WriteAllText(([IO.Path]::Combine($SpoolDir,('worker_pulse_'+$workerInstance+'_'+$slot+'.json'))),$stoppedJson,[Text.UTF8Encoding]::new($false))}catch{}
                }
            }
            $temporary=[IO.Path]::Combine($SpoolDir,('worker_state.'+[Guid]::NewGuid().ToString('N')+'.tmp'))
            try{[IO.File]::WriteAllText($temporary,$stoppedJson,(New-Object Text.UTF8Encoding($false)));Move-WorkerFile $temporary ([IO.Path]::Combine($SpoolDir,'worker_state.json'))}catch{}
        }
    }finally{
        if($instanceLease){$instanceLease.Dispose()}
        if($mutexHeld){$workerMutex.ReleaseMutex()}
        if($workerMutex){$workerMutex.Dispose()}
    }
}
