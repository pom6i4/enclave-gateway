param(
    [string]$SpoolDir='\\tsclient\C\EnclaveGateway\spool',
    [Parameter(Mandatory=$true)][string]$PolicyPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PolicySha256,
    [bool]$RequireSignedAgents=$true,
    [string[]]$TrustedSignerThumbprints=@(),
    [ValidateRange(1,3600)][int]$LeaseSeconds=900,
    [string]$StopFile=''
)
# Foreground only. Fixed operations use system OpenSSH; request text is never
# evaluated by PowerShell. The approved policy is provisioned independently.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:OS -ne 'Windows_NT'){throw 'The structured worker requires Windows system OpenSSH'}
function Assert-PlainPath([string]$Path,[bool]$Local=$false){
    if(-not [IO.Path]::IsPathRooted($Path) -or ($Local -and $Path.StartsWith('\\'))){throw 'An approved absolute path is required'}
    $parent=if([IO.Directory]::Exists($Path)){New-Object IO.DirectoryInfo($Path)}else{New-Object IO.FileInfo($Path)}
    while($parent){if($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked worker paths are forbidden'};$parent=if($parent -is [IO.FileInfo]){$parent.Directory}else{$parent.Parent}}
}
function Hash-File([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Hash-Text([string]$Text){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function Quote-Windows([string]$Value){
    if($Value.Contains([char]0)){throw 'Invalid argument'}
    # CommandLineToArgvW-compatible quoting; no shell is started on Bastion.
    return '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'
}
function Quote-Posix([string]$Value){return "'"+$Value.Replace("'",("'"+'"'+"'"+'"'+"'"))+"'"}
function Write-Atomic([string]$Path,[string]$Text){
    Assert-PlainPath $Path
    $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try{
        $bytes=[Text.Encoding]::UTF8.GetBytes($Text)
        $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
        if([IO.File]::Exists($Path)){[IO.File]::Replace($temporary,$Path,[NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
    }finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
function Assert-Signature([string]$Path,[bool]$Microsoft=$false){
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate){throw 'An approved valid signature is required'}
    if($Microsoft){
        if($signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -notin @('Microsoft Windows','Microsoft Corporation')){throw 'System OpenSSH must be signed by Microsoft'}
    }elseif($signature.SignerCertificate.Thumbprint -notin $TrustedSignerThumbprints){throw 'Worker publisher is not approved'}
    return $signature
}
Assert-PlainPath $PSCommandPath
Assert-PlainPath $PolicyPath $true
Assert-PlainPath $SpoolDir
if(-not [IO.Directory]::Exists($SpoolDir)){throw 'Provision the private redirected spool before starting the worker'}
# Hold the policy and script against writes/replacement for this invocation.
$policyLease=$null;$scriptLease=$null;$sessionLease=$null
$instance=[Guid]::NewGuid().ToString('N')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$statePath=[IO.Path]::Combine($SpoolDir,'worker_state.json')
$journal=[IO.Path]::Combine($SpoolDir,'.structured-transactions')
$started=[Diagnostics.Stopwatch]::StartNew();$loadedHash='';$signatureStatus='NotSigned';$signer=''
try{
    $policyLease=[IO.File]::Open($PolicyPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $scriptLease=[IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if((Hash-File $PolicyPath) -cne $PolicySha256){throw 'Approved worker policy hash mismatch'}
    $loadedHash=Hash-File $PSCommandPath
    if($RequireSignedAgents){$signature=Assert-Signature $PSCommandPath;$signatureStatus='Valid';$signer=$signature.SignerCertificate.Thumbprint}
    $acl=Get-Acl -LiteralPath $PolicyPath
    $ownerSid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if($ownerSid -notin @('S-1-5-18','S-1-5-32-544')){throw 'Policy must be owned by SYSTEM or Administrators'}
    foreach($rule in $acl.Access){
        $writer=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if($rule.AccessControlType -eq 'Allow' -and ([int]$rule.FileSystemRights -band 852310) -ne 0 -and $writer -notin @('S-1-5-18','S-1-5-32-544')){throw 'Policy must not be writable by an unapproved principal'}
    }
    $policy=[IO.File]::ReadAllText($PolicyPath)|ConvertFrom-Json
    if($policy.revision -ne 1 -or -not $policy.targets -or $policy.owner_sid -cne $sid){throw 'Invalid policy or worker SID'}
    $ssh=[IO.Path]::Combine([Environment]::GetFolderPath('System'),'OpenSSH\ssh.exe')
    Assert-PlainPath $ssh $true
    [void](Assert-Signature $ssh $true)
    $sessionLease=[IO.File]::Open(([IO.Path]::Combine($SpoolDir,'.worker-session')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    Assert-PlainPath $journal
    $binding=[IO.Path]::Combine($SpoolDir,'worker_structured_storage.json')
    $owner=Hash-Text ($sid+'|'+[Environment]::MachineName)
    if([IO.File]::Exists($binding)){
        $storage=[IO.File]::ReadAllText($binding)|ConvertFrom-Json
        if($storage.revision -ne 1 -or $storage.owner_sha256 -cne $owner -or -not [IO.Directory]::Exists($journal)){throw 'Structured journal identity missing or changed; restore its evidence'}
    }else{
        if([IO.Directory]::Exists($journal)){throw 'Unbound journal requires administrator reconciliation'}
        [void][IO.Directory]::CreateDirectory($journal)
        Write-Atomic $binding (@{revision=1;owner_sha256=$owner}|ConvertTo-Json -Compress)
    }
    function Heartbeat([string]$Status='running'){
        Write-Atomic $statePath (@{status=$Status;instance_id=$instance;worker_sha256=$loadedHash;execution_profile='structured_only';
            spool_protocol='files';execution_model='foreground-openssh';journal_location='redirected-durable';
            last_heartbeat_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress)
        $script:lastPulse=$started.ElapsedMilliseconds
    }
    function Response([string]$Id,[int]$Code,[string]$Output,[string]$ErrorText,[string]$State='completed'){
        $value=@{tx_id=$Id;exit_code=$Code;state=$State;worker_instance=$instance;worker_sha256=$loadedHash;
            stdout_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Output));
            stderr_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ErrorText));duration_ms=[int]$requestTimer.ElapsedMilliseconds}
        Write-Atomic ([IO.Path]::Combine($SpoolDir,('res_'+$Id+'.json'))) ($value|ConvertTo-Json -Compress)
    }
    function Target($Request){
        if([string]$Request.target -cnotmatch '^[A-Za-z0-9_.-]{1,80}$'){throw 'Invalid target identifier'}
        $entry=$policy.targets.PSObject.Properties[[string]$Request.target]
        if(-not $entry){throw 'Target is not in the independently approved policy'}
        $node=$entry.Value
        if($Request.expected_host -ine $node.host -or $Request.expected_port -ne $node.port -or $Request.expected_user -cne $node.user){throw 'Configured target differs from the independently approved policy'}
        if([string]$node.host -notmatch '^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$' -or [string]$node.user -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$' -or
           ($node.port -isnot [int] -and $node.port -isnot [long]) -or $node.port -lt 1 -or $node.port -gt 65535){throw 'Invalid approved SSH endpoint'}
        foreach($path in @($node.key_path,$node.known_hosts_path)){Assert-PlainPath $path $true;if(-not [IO.File]::Exists($path)){throw 'Approved SSH trust material missing'}}
        return $node
    }
    function Run-Ssh($Node,[string]$Remote,[string]$InputFile,[string]$InputText,[string]$OutputFile,[int]$Timeout,[string]$Id){
        $arguments=@('-F','NUL','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes',
            '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','PermitLocalCommand=no',
            '-o','ProxyCommand=none','-o','IdentityAgent=none','-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','ConnectTimeout=15',
            '-o',('UserKnownHostsFile="'+$Node.known_hosts_path.Replace('\','/')+'"'),'-i',$Node.key_path,'-p',[string]$Node.port,
            ($Node.user+'@'+$Node.host),$Remote)
        $psi=New-Object Diagnostics.ProcessStartInfo
        $psi.FileName=$ssh;$psi.Arguments=($arguments|ForEach-Object{Quote-Windows $_}) -join ' '
        $psi.WorkingDirectory=[IO.Path]::GetDirectoryName($ssh)
        $psi.UseShellExecute=$false;$psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
        # Ignore inherited askpass configuration. This profile never asks for passwords.
        foreach($key in @('SSH_ASKPASS','SSH_ASKPASS_REQUIRE','EGW_ASKPASS_B64','SSH_SK_PROVIDER','SSH_AUTH_SOCK')){[void]$psi.EnvironmentVariables.Remove($key)}
        $process=New-Object Diagnostics.Process;$process.StartInfo=$psi;$inputStream=$null;$outputStream=$null;$errorStream=$null
        try{
            [void]$process.Start()
            $outBuffer=New-Object byte[] 65536;$errBuffer=New-Object byte[] 65536
            $output=$process.StandardOutput.BaseStream.ReadAsync($outBuffer,0,$outBuffer.Length)
            $errors=$process.StandardError.BaseStream.ReadAsync($errBuffer,0,$errBuffer.Length)
            if($OutputFile){$outputStream=[IO.File]::Open($OutputFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)}
            else{$outputStream=New-Object IO.MemoryStream}
            $errorStream=New-Object IO.MemoryStream
            if($InputFile){$inputStream=[IO.File]::OpenRead($InputFile)}else{$inputStream=[IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($InputText))}
            $writeTask=$inputStream.CopyToAsync($process.StandardInput.BaseStream)
            $timer=[Diagnostics.Stopwatch]::StartNew();$closed=$false;$outDone=$false;$errDone=$false
            while(-not $process.HasExited -or -not $outDone -or -not $errDone){
                if(-not $outDone -and $output.IsCompleted){
                    $count=$output.GetAwaiter().GetResult()
                    if($count -eq 0){$outDone=$true}else{
                        if($outputStream.Length+$count -gt $(if($OutputFile){64*1024*1024+100}else{8*1024*1024})){throw 'SSH output limit exceeded'}
                        $outputStream.Write($outBuffer,0,$count);$output=$process.StandardOutput.BaseStream.ReadAsync($outBuffer,0,$outBuffer.Length)
                    }
                }
                if(-not $errDone -and $errors.IsCompleted){
                    $count=$errors.GetAwaiter().GetResult()
                    if($count -eq 0){$errDone=$true}else{
                        if($errorStream.Length+$count -gt 1048576){throw 'SSH error output limit exceeded'}
                        $errorStream.Write($errBuffer,0,$count);$errors=$process.StandardError.BaseStream.ReadAsync($errBuffer,0,$errBuffer.Length)
                    }
                }
                if($writeTask.IsCompleted -and -not $closed){$writeTask.GetAwaiter().GetResult();$process.StandardInput.Close();$closed=$true}
                if($timer.ElapsedMilliseconds -ge $Timeout -or $started.Elapsed.TotalSeconds -ge $LeaseSeconds -or
                   [IO.File]::Exists([IO.Path]::Combine($SpoolDir,('cancel_'+$Id+'.json'))) -or ($StopFile -and [IO.File]::Exists($StopFile))){
                    throw 'SSH interrupted; remote outcome requires reconciliation'
                }
                if($started.ElapsedMilliseconds-$script:lastPulse -ge 5000){Heartbeat}
                Start-Sleep -Milliseconds 10
            }
            if(-not $writeTask.Wait(1000) -or $writeTask.IsFaulted){throw 'SSH input stream completion unavailable'}
            if($OutputFile){$outputStream.Flush($true);$text=''}else{$text=[Text.Encoding]::UTF8.GetString($outputStream.ToArray())}
            $errorText=[Text.Encoding]::UTF8.GetString($errorStream.ToArray())
            return @{Code=$process.ExitCode;Output=$text;Error=$errorText}
        }finally{
            try{if(-not $process.HasExited){$process.Kill();[void]$process.WaitForExit(1000)}}catch{}
            $process.Dispose();if($inputStream){$inputStream.Dispose()};if($outputStream){$outputStream.Dispose()};if($errorStream){$errorStream.Dispose()}
        }
    }
    Heartbeat
    while($started.Elapsed.TotalSeconds -lt $LeaseSeconds -and -not ($StopFile -and [IO.File]::Exists($StopFile))){
        if($started.ElapsedMilliseconds-$script:lastPulse -ge 5000){Heartbeat}
        foreach($path in [IO.Directory]::EnumerateFiles($SpoolDir,'req_*.json')){
            $name=[IO.Path]::GetFileName($path)
            if($name -cnotmatch '^req_([A-Za-z0-9_]{1,128})\.json$'){continue}
            $id=$Matches[1];$record=[IO.Path]::Combine($journal,($id+'.json'));$claimed=$false;$dispatched=$false;$phase='request';$requestTimer=[Diagnostics.Stopwatch]::StartNew()
            try{
                if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -or (New-Object IO.FileInfo($path)).Length -gt 2097152){throw 'Invalid request file'}
                $request=[IO.File]::ReadAllText($path)|ConvertFrom-Json
                $allowed=@('tx_id','op','timeout_ms','expires_unix_ms','operation_id','expected_worker_instance','expected_worker_sha256','target','expected_host','expected_port','expected_user','command','as_root','transfer_id','remote_path','sha256','attestation_nonce')
                if(@($request.PSObject.Properties.Name|Where-Object{$_ -notin $allowed}).Count -or $request.tx_id -cne $id){throw 'Unsupported request fields'}
                if($request.expected_worker_instance -and $request.expected_worker_instance -cne $instance){throw 'Worker instance changed'}
                if($request.expected_worker_sha256 -and $request.expected_worker_sha256 -cne $loadedHash){throw 'Worker release changed'}
                if(($request.timeout_ms -isnot [int] -and $request.timeout_ms -isnot [long]) -or $request.timeout_ms -lt 1 -or $request.timeout_ms -gt 86400000){throw 'Invalid deadline'}
                $remaining=[double]$request.expires_unix_ms-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                if($remaining -le 0 -or [IO.File]::Exists([IO.Path]::Combine($SpoolDir,('cancel_'+$id+'.json')))){Response $id 125 '' 'Cancelled before dispatch' 'cancelled';continue}
                if(($request.PSObject.Properties.Name -contains 'as_root') -and $request.as_root -isnot [bool]){throw 'Invalid privilege option'}
                # CreateNew is a durable no-replay boundary, including after reconnect.
                Assert-PlainPath $record
                $claim=[IO.File]::Open($record,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try{$recordData=@{tx_id=$id;operation_id=[string]$request.operation_id;state='running';instance_id=$instance;started_utc=[DateTime]::UtcNow.ToString('o')};$bytes=[Text.Encoding]::UTF8.GetBytes(($recordData|ConvertTo-Json -Compress));$claim.Write($bytes,0,$bytes.Length);$claim.Flush($true)}finally{$claim.Dispose()}
                $claimed=$true
                $out='';$code=0;$err='';$state='completed'
                switch -CaseSensitive ([string]$request.op){
                    'ping' {$out='VFS_PONG'}
                    'clean' {$out='STRUCTURED_CLEAN: durable outcomes and unclaimed evidence preserved'}
                    'stop' {$out='WORKER_STOP_ACCEPTED'}
                    'attest' {
                        if([string]$request.attestation_nonce -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid challenge'}
                        $freshStatus='NotSigned';$freshSigner=''
                        if($RequireSignedAgents){$fresh=Assert-Signature $PSCommandPath;$freshStatus='Valid';$freshSigner=$fresh.SignerCertificate.Thumbprint}
                        $out=@{protocol_revision=1;version='0.3.0';nonce=$request.attestation_nonce;instance_id=$instance;loaded_sha256=$loadedHash;
                            current_sha256=(Hash-File $PSCommandPath);loaded_signature_status=$signatureStatus;loaded_signer=$signer;
                            signature_status=$freshStatus;signer=$freshSigner;sid=$sid;execution_model='foreground-openssh';
                            execution_profile='structured_only';policy_sha256=$PolicySha256}|ConvertTo-Json -Compress
                    }
                    {$_ -in @('ssh_exec','ssh_push','ssh_pull')} {
                        $phase='policy';$node=Target $request
                        if($request.as_root -and $node.allow_sudo -ne $true){throw 'sudo is not approved for this target'}
                        $prefix=if($request.as_root){'sudo -n sh -c '}else{'sh -c '}
                        $inputFile='';$outputFile='';$inputText=''
                        if($request.op -eq 'ssh_exec'){
                            if($node.allow_exec -ne $true -or $request.command -isnot [string] -or $request.command.Length -gt 1048576){throw 'Command execution is not approved'}
                            $remote=if($request.as_root){'sudo -n sh -s'}else{'sh -s'};$inputText=$request.command+"`n"
                        }else{
                            if($node.allow_transfer -ne $true -or [string]$request.transfer_id -cnotmatch '^[a-f0-9]{32}$' -or
                               $request.remote_path -isnot [string] -or -not $request.remote_path.StartsWith('/') -or $request.remote_path.IndexOfAny([char[]]@("`r","`n",[char]0)) -ge 0){throw 'Invalid or unapproved transfer'}
                            $transfer=[IO.Path]::Combine($SpoolDir,('structured_'+$request.transfer_id+'.bin'))
                            Assert-PlainPath $transfer
                            $remotePath=Quote-Posix $request.remote_path
                            if($request.op -eq 'ssh_push'){
                                if((New-Object IO.FileInfo($transfer)).Length -gt 67108864){throw 'Transfer limit exceeded'}
                                if([string]$request.sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Hash-File $transfer) -cne $request.sha256){throw 'Upload checksum mismatch'}
                                $stage=Quote-Posix ($request.remote_path+'.egw-'+$request.transfer_id)
                                $body='(umask 077; set -C; : > '+$stage+') || exit 1; trap '+(Quote-Posix ('rm -f -- '+$stage))+' 0; cat > '+$stage+' && test "$(sha256sum < '+$stage+' | cut -d " " -f 1)" = '+(Quote-Posix $request.sha256)+' && mv -f -- '+$stage+' '+$remotePath+' && printf '+(Quote-Posix ('VERIFIED:'+$request.sha256))
                                $inputFile=$transfer
                            }else{
                                $body='sha256sum < '+$remotePath+'; cat -- '+$remotePath
                                $outputFile=$transfer
                            }
                            $remote=$prefix+(Quote-Posix $body)
                        }
                        $phase='ssh';$dispatched=$true
                        $result=Run-Ssh $node $remote $inputFile $inputText $outputFile ([int][Math]::Min($request.timeout_ms,$remaining)) $id
                        $code=$result.Code;$out=$result.Output;$err=$result.Error
                        if($code){$state='failed'}
                        if($request.op -eq 'ssh_pull' -and -not $code){
                            # Split the remote hash header from the binary stream without decoding file data.
                            $source=[IO.File]::OpenRead($outputFile);$temporary=$outputFile+'.verified'
                            try{
                                $header=New-Object Text.StringBuilder
                                while($header.Length -lt 100){$byte=$source.ReadByte();if($byte -lt 0 -or $byte -eq 10){break};[void]$header.Append([char]$byte)}
                                $expected=($header.ToString() -split ' ')[0]
                                if($expected -cnotmatch '^[a-f0-9]{64}$'){throw 'Missing remote checksum'}
                                $destination=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                                try{$source.CopyTo($destination);$destination.Flush($true)}finally{$destination.Dispose()}
                            }finally{$source.Dispose()}
                            if((Hash-File $temporary) -cne $expected){throw 'Download checksum mismatch'}
                            [IO.File]::Replace($temporary,$outputFile,[NullString]::Value);$out='SHA256:'+$expected
                        }
                    }
                    default {throw 'Unsupported operation; generic PowerShell and TCP mux are forbidden'}
                }
                $recordData.state=$state;$recordData.exit_code=$code
                Write-Atomic $record ($recordData|ConvertTo-Json -Compress)
                Response $id $code $out $err $state
                if($request.op -eq 'stop'){return}
            }catch{
                $state=if($dispatched){'indeterminate'}else{'failed'}
                if($claimed){$recordData.state=$state;$recordData.failure_stage=$phase;$recordData.error_type=$_.Exception.GetType().FullName;Write-Atomic $record ($recordData|ConvertTo-Json -Compress)}
                Response $id 125 '' ('Structured operation failed at '+$phase+' ('+$_.Exception.GetType().Name+'); inspect approved policy and reconcile durable outcomes before retrying') $state
            }finally{if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
        }
        Start-Sleep -Milliseconds 100
    }
}finally{
    if($sessionLease){try{if(Get-Command Heartbeat -CommandType Function -ErrorAction SilentlyContinue){Heartbeat 'stopped'}}finally{$sessionLease.Dispose()}}
    if($scriptLease){$scriptLease.Dispose()};if($policyLease){$policyLease.Dispose()}
}
