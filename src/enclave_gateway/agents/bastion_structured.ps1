param(
    [string]$SpoolDir='\\tsclient\C\EnclaveGateway\spool',
    [Parameter(Mandatory=$true)][string]$PolicyPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PolicySha256,
    [bool]$RequireSignedAgents=$true,
    [string[]]$TrustedSignerThumbprints=@(),
    [ValidateRange(1,86400)][int]$LeaseSeconds=28800,
    [string]$StopFile='',
    [switch]$OperatorOpenSsh,
    [ValidateRange(15,300)][int]$OperatorExecMaxSec=15
)
# Foreground only. Fixed operations use system OpenSSH; request text is never
# evaluated by PowerShell. The approved policy is provisioned independently.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$utf8=[Text.UTF8Encoding]::new($false,$true)
$operatorInput=$null;$operatorOutput=$null;$operatorRequests=$null;$operatorUploadReaders=@()
$operatorSlotReaders=@()
$operatorReadTask=$null;$operatorReadBuffer=[byte[]]::new(4096);$operatorFrameData=[IO.MemoryStream]::new()
$operatorLead=[byte[]]::new(1);$operatorLeadTask=$null
$operatorSlots=@{};$operatorCursor=0L;$operatorTicket=0L;$operatorBroken=$false
$operatorQueue=[Collections.Generic.Queue[object]]::new()
$operatorCancelled=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$extendedOperator=$OperatorOpenSsh -and $OperatorExecMaxSec -gt 15
if($OperatorExecMaxSec -gt 15 -and (-not $OperatorOpenSsh -or $OperatorExecMaxSec -gt $LeaseSeconds)){throw 'Extended operator execution must fit the worker lease'}
$operatorExecInProgress=$false
$backend=if($OperatorOpenSsh){'operator'}else{'spawn'}
$model=if($OperatorOpenSsh){'operator-openssh'}else{'foreground-openssh'}
if($env:OS -ne 'Windows_NT'){throw 'The structured worker requires Windows system OpenSSH'}
function Assert-PlainPath([string]$Path,[bool]$Local=$false){
    if(-not [IO.Path]::IsPathRooted($Path) -or ($Local -and $Path.StartsWith('\\'))){throw 'An approved absolute path is required'}
    $parent=if([IO.Directory]::Exists($Path)){New-Object IO.DirectoryInfo($Path)}else{New-Object IO.FileInfo($Path)}
    while($parent){if($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked worker paths are forbidden'};$parent=if($parent -is [IO.FileInfo]){$parent.Directory}else{$parent.Parent}}
}
function Hash-File([string]$Path){
    $file=[IO.File]::OpenRead($Path)
    try{
        $sha=[Security.Cryptography.SHA256]::Create()
        try{return [BitConverter]::ToString($sha.ComputeHash($file)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    }finally{$file.Dispose()}
}
function Assert-PolicyAcl([string]$Path,[string]$WorkerSid,[bool]$AllowWorkerOwnership){
    $approvedPrincipals=@('S-1-5-18','S-1-5-32-544')
    if($AllowWorkerOwnership){$approvedPrincipals+=@($WorkerSid)}
    $acl=Get-Acl -LiteralPath $Path
    $sidType=[Security.Principal.SecurityIdentifier]
    if($acl.GetOwner($sidType).Value -cnotin $approvedPrincipals){throw 'Policy owner is outside the approved principals'}
    $rules=$acl.GetAccessRules($true,$true,$sidType)
    if(-not $rules.Count){throw 'Policy requires an explicit Windows ACL'}
    foreach($rule in $rules){
        if($rule.AccessControlType -eq 'Allow' -and ([int]$rule.FileSystemRights -band 852310) -ne 0 -and $rule.IdentityReference.Value -cnotin $approvedPrincipals){throw 'Policy must not be writable by an unapproved principal'}
    }
}
function Hash-Text([string]$Text){return Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($Text))}
function Hash-Bytes([byte[]]$Bytes){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function Quote-Windows([string]$Value){
    if($Value.Contains([char]0)){throw 'Invalid argument'}
    # CommandLineToArgvW-compatible quoting; no shell is started on Bastion.
    return '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'
}
function Quote-Posix([string]$Value){return "'"+$Value.Replace("'",("'"+'"'+"'"+'"'+"'"))+"'"}
function New-OperatorCopyCommand($Request){
    if($Request.remote_path.EndsWith('/')){throw 'Chunked copy needs a remote file path'}
    $target=Quote-Posix $Request.remote_path
    $stage=Quote-Posix ($Request.remote_path+'.egw-'+$Request.transfer_id+'.parts')
    $offset=$Request.copy_offset;$length=$Request.copy_length
    if($Request.copy_action -cin @('push_part','pull_part','push_commit')){
        if(($offset -isnot [int] -and $offset -isnot [long]) -or $offset -lt 0 -or $offset -gt 536870912){
            throw 'Invalid chunked copy offset'
        }
    }
    if($Request.copy_action -cin @('push_part','pull_part')){
        $blockSize=1048576
        if(($length -isnot [int] -and $length -isnot [long]) -or $length -lt 0 -or $length -gt $blockSize -or
           $offset % $blockSize -ne 0 -or $offset+$length -gt 536870912 -or
           ($length -eq 0 -and ($offset -ne 0 -or $Request.copy_action -ceq 'pull_part'))){
            throw 'Invalid chunked copy range'
        }
    }
    if($Request.copy_action -cin @('push_part','push_commit') -and [string]$Request.sha256 -cnotmatch '^[a-f0-9]{64}$'){
        throw 'Invalid chunked upload checksum'
    }

    $body='set -eu; export LC_ALL=C; target='+$target+'; stage='+$stage+'; payload="$stage/payload"; '
    $body+='offset='+(Quote-Posix $offset)+'; count='+(Quote-Posix $length)+'; sha='+(Quote-Posix $Request.sha256)+'; '
    $command=switch -CaseSensitive ([string]$Request.copy_action){
        'push_part' {
            @'
if test "$offset" -eq 0; then
    umask 077
    mkdir -- "$stage"
    (set -C; : > "$payload")
fi
test -d "$stage" && test ! -L "$stage" && test -f "$payload" && test ! -L "$payload" || exit 1
test "$(wc -c < "$payload")" -eq "$offset"
cat >> "$payload"
test "$(wc -c < "$payload")" -eq "$((offset+count))"
printf 'PART:%s\n' "$sha"
'@
        }
        'push_commit' {
            @'
test -d "$stage" && test ! -L "$stage" && test -f "$payload" && test ! -L "$payload" || exit 1
test "$(wc -c < "$payload")" -eq "$offset"
hash=$(sha256sum < "$payload")
test "${hash%% *}" = "$sha"
python3 -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$payload" "$target"
rmdir -- "$stage" || :
printf 'VERIFIED:%s\n' "$sha"
'@
        }
        'pull_info' {
            @'
test -f "$target"
size=$(wc -c < "$target")
test "$size" -le 536870912
hash=$(sha256sum < "$target")
printf 'FILE:%d:%s\n' "$size" "${hash%% *}"
'@
        }
        'pull_part' {
            @'
test -f "$target"
python3 -c 'import hashlib, sys
with open(sys.argv[1], "rb") as stream:
    stream.seek(int(sys.argv[2]))
    data = stream.read(int(sys.argv[3]))
out = sys.stdout.buffer
out.write(hashlib.sha256(data).hexdigest().encode("ascii") + b"\n")
out.write(data)' "$target" "$offset" "$count"
'@
        }
        default {throw 'Unsupported chunked copy action'}
    }
    return $body+$command.Replace([string][char]13,'')
}
function Write-Atomic([string]$Path,[string]$Text,[switch]$Transient){
    Assert-PlainPath $Path
    $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    $pending=$false
    try{
        $bytes=[Text.Encoding]::UTF8.GetBytes($Text)
        $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $pending=$true
        try{
            $file.Write($bytes,0,$bytes.Length)
            if(-not $Transient){$file.Flush($true)}
        }finally{$file.Dispose()}
        if([IO.File]::Exists($Path)){[IO.File]::Replace($temporary,$Path,[NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
        $pending=$false
    }finally{if($pending -and [IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
function Assert-Signature([string]$Path,[bool]$Microsoft=$false){
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate){throw 'An approved valid signature is required'}
    if($Microsoft){
        if($signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -notin @('Microsoft Windows','Microsoft Corporation')){throw 'System OpenSSH must be signed by Microsoft'}
    }elseif($signature.SignerCertificate.Thumbprint -notin $TrustedSignerThumbprints){throw 'Worker publisher is not approved'}
    return $signature
}
function Operator-Remaining([long]$Deadline){
    $left=[Math]::Min($Deadline-$requestTimer.ElapsedMilliseconds,($LeaseSeconds*1000L)-$started.ElapsedMilliseconds)
    if($left -le 0){throw 'Operator SSH deadline reached'}
    return [int]$left
}
function Wait-OperatorIO($Task,[long]$Deadline,[string]$Id){
    do{
        if($Id -and $operatorCancelled.Contains($Id)){throw 'Operator SSH cancelled'}
        if($Task.Wait([Math]::Min(100,(Operator-Remaining $Deadline)))){return}
        if($Id){Receive-OperatorFrames}
        if($operatorExecInProgress -and $started.ElapsedMilliseconds-$script:lastPulse -ge 5000){Pulse}
    }while($true)
}
function Operator-Write([byte[]]$Bytes,[long]$Deadline,[string]$Id,[int]$Offset=0,[int]$Count=-1){
    if($Count -eq -1){$Count=$Bytes.Length}
    [void](Operator-Remaining $Deadline)
    Wait-OperatorIO ($operatorInput.WriteAsync($Bytes,$Offset,$Count)) $Deadline $Id
}
function Operator-Read([int]$Length,[long]$Deadline,[string]$Id=''){
    $bytes=New-Object byte[] $Length;$at=0
    while($at -lt $Length){
        $task=$operatorOutput.ReadAsync($bytes,$at,$Length-$at)
        Wait-OperatorIO $task $Deadline $Id
        if($task.Result -le 0){throw 'Operator SSH response unavailable'}
        $at+=$task.Result
    }
    return ,$bytes
}
function Watch-OperatorPeer{
    # This read belongs to the next reply. At idle, EOF or unsolicited data
    # closes the session instead of leaving a healthy-looking heartbeat.
    $script:operatorLeadTask=$operatorOutput.ReadAsync($operatorLead,0,1)
}
function Assert-OperatorPeerIdle{
    if($operatorLeadTask.IsCompleted){throw 'Operator OpenSSH disconnected or sent unsolicited data; start a new foreground session'}
}
function Read-OperatorReplyLength([long]$Deadline,[string]$Id){
    Wait-OperatorIO $operatorLeadTask $Deadline $Id
    if($operatorLeadTask.Result -ne 1){throw 'Operator SSH response unavailable'}
    return ([Text.Encoding]::ASCII.GetString($operatorLead)+[Text.Encoding]::ASCII.GetString((Operator-Read 7 $Deadline $Id)))
}
function Read-OperatorUpload([string]$Path,[string]$Expected,[long]$Deadline){
    [void](Operator-Remaining $Deadline)
    if([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint){throw 'Linked upload stage is forbidden'}
    [void](Operator-Remaining $Deadline)
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        $length=$file.Length
        if($length -gt 67108864){throw 'Transfer limit exceeded'}
        $bytes=[byte[]]::new([int]$length)
        $position=0
        while($position -lt $bytes.Length){
            [void](Operator-Remaining $Deadline)
            $count=$file.Read($bytes,$position,$bytes.Length-$position)
            if($count -le 0){throw 'Incomplete upload stage'}
            $position+=$count
        }
        if((Hash-Bytes $bytes) -cne $Expected){throw 'Upload checksum mismatch'}
        return ,$bytes
    }finally{$file.Dispose()}
}
function Read-OperatorUploadAttachment($Readers,[long]$Offset,[int]$Length,[string]$Expected,[long]$Deadline,[int]$PlainLength,[string]$StreamToPeer,[hashtable]$Record){
    $payload=[byte[]]::new($Length)
    $parts=@()
    try{
        # On .NET Framework, ReadAsync on a synchronous FileStream runs the
        # read on the thread pool without querying the redirected file length.
        $partBytes=[int][Math]::Ceiling($Length/[double]$Readers.Count)
        for($i=0;$i -lt $Readers.Count -and $i*$partBytes -lt $Length;$i++){
            [void](Operator-Remaining $Deadline)
            $start=$i*$partBytes
            $size=[Math]::Min($partBytes,$Length-$start)
            $file=$Readers[$i]
            $file.Position=$Offset+$start
            $initial=if($StreamToPeer -and $i -eq 0){[Math]::Min($size,65536)}else{$size}
            $parts+=@{File=$file;Start=$start;Length=$size;Task=$file.ReadAsync($payload,$start,$initial)}
        }
        # The peer reads exactly input_bytes before starting the command.
        # Retain the final byte until the complete attachment passes SHA-256.
        foreach($part in $parts){
            $position=$part.Start
            $end=$position+$part.Length
            $task=$part.Task
            while($position -lt $end){
                $waitStarted=$requestTimer.ElapsedMilliseconds
                try{Wait-OperatorIO $task $Deadline $StreamToPeer}
                finally{if($Record){$Record.rdp_read_wait_ms+=$requestTimer.ElapsedMilliseconds-$waitStarted}}
                $count=$task.Result
                $next=$position+$count
                if($next -lt $end){
                    if(-not $count){Start-Sleep -Milliseconds 15}
                    [void](Operator-Remaining $Deadline)
                    $part.File.Position=$Offset+$next
                    $task=$part.File.ReadAsync($payload,$next,$end-$next)
                }
                if($count -gt 0 -and $StreamToPeer){
                    $available=[Math]::Min($count,$Length-1-$position)
                    if($available -gt 0){
                        $waitStarted=$requestTimer.ElapsedMilliseconds
                        try{Operator-Write $payload $Deadline $StreamToPeer $position $available}
                        finally{$Record.ssh_pipe_wait_ms+=$requestTimer.ElapsedMilliseconds-$waitStarted}
                    }
                }
                $position=$next
            }
        }
        [void](Operator-Remaining $Deadline)
        if($PlainLength){
            $plain=[byte[]]::new($PlainLength)
            $encoded=[IO.MemoryStream]::new($payload,$false)
            try{
                $inflater=[IO.Compression.DeflateStream]::new($encoded,[IO.Compression.CompressionMode]::Decompress)
                try{
                    $position=0
                    while($position -lt $PlainLength){
                        $count=$inflater.Read($plain,$position,$PlainLength-$position)
                        if($count -le 0){throw 'Incomplete compressed stream upload'}
                        $position+=$count
                    }
                    if($inflater.ReadByte() -ne -1){throw 'Compressed stream upload exceeds its declared size'}
                }finally{$inflater.Dispose()}
            }finally{$encoded.Dispose()}
            $payload=$plain
        }
        [void](Operator-Remaining $Deadline)
        if((Hash-Bytes $payload) -cne $Expected){throw 'Stream upload checksum mismatch'}
        if($StreamToPeer){
            if($operatorCancelled.Contains($StreamToPeer)){throw 'Cancelled before completing SSH input'}
            Operator-Write $payload $Deadline $StreamToPeer ($Length-1) 1
        }else{return ,$payload}
    }catch{
        # Partial attachment input cannot be followed by another request on
        # the same streams. Closing the pipe denies dispatch on the peer.
        $script:operatorBroken=$true
        throw
    }
}
function Get-OperatorDownload([byte[]]$Bytes,[long]$Deadline,[int]$CopyLength){
    $end=[Array]::IndexOf($Bytes,[byte]10,0,[Math]::Min(100,$Bytes.Length))
    if($end -lt 64){throw 'Missing remote checksum'}
    $expected=[Text.Encoding]::ASCII.GetString($Bytes,0,64)
    if($expected -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid remote checksum'}
    $start=$end+1;$count=$Bytes.Length-$start
    if($count -gt 67108864){throw 'Transfer limit exceeded'}
    if($CopyLength -ge 0 -and $count -ne $CopyLength){throw 'Invalid download block length'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$actual=[BitConverter]::ToString($sha.ComputeHash($Bytes,$start,$count)).Replace('-','').ToLowerInvariant()}
    finally{$sha.Dispose()}
    if($actual -cne $expected){throw 'Download checksum mismatch'}
    [void](Operator-Remaining $Deadline)
    return @{Start=$start;Count=$count;Digest=$expected}
}
function Invoke-OperatorSsh([string]$Remote,[string]$InputFile,[string]$InputText,[string]$OutputFile,[long]$Deadline,[string]$Id,[ref]$Dispatched,[string]$ExpectedUploadHash,[hashtable]$Record,[long]$UploadOffset,[int]$UploadBytes,[int]$UploadPlainBytes,[int]$SlotBytes,[int]$DownloadLength=-1,[string]$Operation){
    $readers=$operatorUploadReaders
    if($SlotBytes){$readers=$operatorSlotReaders;$UploadOffset=4096;$UploadBytes=$SlotBytes}
    $pipeline=$SlotBytes -gt 0 -or ($UploadBytes -ge 262144 -and -not $UploadPlainBytes)
    if($pipeline){$inputBytes=$UploadBytes}
    elseif($UploadBytes){
        $phaseStarted=$requestTimer.ElapsedMilliseconds
        try{[byte[]]$payload=Read-OperatorUploadAttachment $readers $UploadOffset $UploadBytes $ExpectedUploadHash $Deadline $UploadPlainBytes}
        catch{$Record.operator_failure_phase='rdp_stream_read';throw}
        finally{$Record.rdp_stream_read_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted}
    }elseif($InputFile){
        $phaseStarted=$requestTimer.ElapsedMilliseconds
        try{[byte[]]$payload=Read-OperatorUpload $InputFile $ExpectedUploadHash $Deadline}
        catch{$Record.operator_failure_phase='rdp_stage_read';throw}
        finally{$Record.rdp_stage_read_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted}
    }else{[byte[]]$payload=[Text.Encoding]::UTF8.GetBytes($InputText)}
    if(-not $pipeline){$inputBytes=$payload.Length}
    $outputLimit=if($DownloadLength -ge 0){$DownloadLength+65}elseif($OutputFile){67108964}else{8388608}
    $peerBudget=Operator-Remaining $Deadline
    if($operatorExecInProgress){
        # Reserve part of the original deadline for the pipe reply and VFS delivery.
        $reserve=[int][Math]::Min(1000,[Math]::Floor($peerBudget/4))
        if($reserve -lt 1){throw 'Insufficient time for an operator reply'}
        $Deadline=$requestTimer.ElapsedMilliseconds+$peerBudget-$reserve
        $peerBudget-=2*$reserve
    }
    $fields=@{id=$Id;command=$Remote;input_bytes=$inputBytes;output_limit=$outputLimit;timeout_ms=$peerBudget}
    if($extendedOperator){$fields.op=$Operation}
    $header=[Text.Encoding]::UTF8.GetBytes(($fields|ConvertTo-Json -Compress))
    if($header.Length -gt 2097152 -or $inputBytes -gt 67108864){throw 'Operator SSH input limit exceeded'}
    # Once pipe writing begins, a broken pipe or timeout has an unknown outcome.
    # Never reuse the connection after partial I/O or retry a dispatched operation.
    [void](Operator-Remaining $Deadline)
    Assert-OperatorPeerIdle
    if($operatorCancelled.Contains($Id)){throw 'Cancelled before SSH dispatch'}
    $Dispatched.Value=$true
    $ioPhase='ssh_write'
    $phaseStarted=$requestTimer.ElapsedMilliseconds
    try{
        Operator-Write ([Text.Encoding]::ASCII.GetBytes($header.Length.ToString('x8'))) $Deadline $Id
        Operator-Write $header $Deadline $Id
        if($pipeline){
            $Record.ssh_write_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted
            $ioPhase='rdp_ssh_pipeline';$phaseStarted=$requestTimer.ElapsedMilliseconds
            $Record.rdp_read_wait_ms=0;$Record.ssh_pipe_wait_ms=0
            Read-OperatorUploadAttachment $readers $UploadOffset $UploadBytes $ExpectedUploadHash $Deadline 0 $Id $Record
            $Record.rdp_ssh_pipeline_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted
        }else{
            if($inputBytes){Operator-Write $payload $Deadline $Id}
            $Record.ssh_write_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted
        }
        $ioPhase='ssh_reply';$phaseStarted=$requestTimer.ElapsedMilliseconds
        $lengthText=Read-OperatorReplyLength $Deadline $Id
        if($lengthText -cnotmatch '^0000[a-f0-9]{4}$'){throw 'Invalid operator SSH reply length'}
        $length=[Convert]::ToInt32($lengthText,16)
        if($length -lt 2 -or $length -gt 4096){throw 'Operator SSH reply header limit exceeded'}
        $reply=$utf8.GetString((Operator-Read $length $Deadline $Id))|ConvertFrom-Json
        if($reply.id -cne $Id -or ($reply.exit_code -isnot [int] -and $reply.exit_code -isnot [long]) -or $reply.exit_code -lt 0 -or $reply.exit_code -gt 255 -or
           ($reply.output_bytes -isnot [int] -and $reply.output_bytes -isnot [long]) -or $reply.output_bytes -lt 0 -or $reply.output_bytes -gt $outputLimit -or
            ($reply.error_bytes -isnot [int] -and $reply.error_bytes -isnot [long]) -or $reply.error_bytes -lt 0 -or $reply.error_bytes -gt 1048576){throw 'Invalid operator SSH reply'}
        $output=Operator-Read $reply.output_bytes $Deadline $Id
        $errors=Operator-Read $reply.error_bytes $Deadline $Id
        $Record.ssh_reply_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted
        if($reply.indeterminate -isnot [bool]){throw 'Invalid operator SSH reply outcome'}
        if($reply.indeterminate){
            if(-not $operatorExecInProgress -or $reply.outcome -cne 'command_timeout' -or
               $reply.exit_code -ne 125 -or $reply.output_bytes -ne 0){throw 'Remote process outcome requires reconciliation'}
            Watch-OperatorPeer
            return @{Code=125;Output='';Error=[Text.Encoding]::UTF8.GetString($errors);State='indeterminate'}
        }
        if($reply.PSObject.Properties['outcome']){throw 'Invalid operator SSH reply outcome'}
        Watch-OperatorPeer
        $ioPhase='rdp_stage_write';$phaseStarted=$requestTimer.ElapsedMilliseconds
        $data=$null
        $text=if(-not $OutputFile -and $DownloadLength -lt 0){[Text.Encoding]::UTF8.GetString($output)}
        elseif(-not $reply.exit_code){
            $verified=Get-OperatorDownload $output $Deadline $DownloadLength
            if($OutputFile){
                $file=[IO.File]::Open($OutputFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try{$file.Write($output,$verified.Start,$verified.Count)}finally{$file.Dispose()}
                $Record.rdp_stage_write_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted
            }else{
                $data=[byte[]]::new($verified.Count)
                [Array]::Copy($output,$verified.Start,$data,0,$verified.Count)
            }
            'SHA256:'+$verified.Digest
        }else{''}
        return @{Code=$reply.exit_code;Output=$text;Error=[Text.Encoding]::UTF8.GetString($errors);Data=$data}
    }catch{
        $Record.operator_failure_phase=$ioPhase
        $Record.operator_failure_phase_ms=$requestTimer.ElapsedMilliseconds-$phaseStarted
        $script:operatorBroken=$true
        throw
    }
}
function Open-OperatorPipes{
    $acl=[IO.Pipes.PipeSecurity]::new()
    $ownerSid=[Security.Principal.SecurityIdentifier]::new($sid)
    $networkSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-2')
    $acl.SetOwner($ownerSid)
    $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([IO.Pipes.PipeAccessRule]::new($networkSid,[IO.Pipes.PipeAccessRights]::FullControl,'Deny'))
    $acl.AddAccessRule([IO.Pipes.PipeAccessRule]::new($ownerSid,[IO.Pipes.PipeAccessRights]::FullControl,'Allow'))
    $flags=[IO.Pipes.PipeOptions]::Asynchronous
    $mode=[IO.Pipes.PipeTransmissionMode]::Byte
    $script:operatorInput=[IO.Pipes.NamedPipeServerStream]::new(('EgwIn'+$instance),'Out',1,$mode,$flags,65536,65536,$acl)
    $script:operatorOutput=[IO.Pipes.NamedPipeServerStream]::new(('EgwOut'+$instance),'In',1,$mode,$flags,65536,65536,$acl)
    # Local command only. All operands are from the pinned administrator policy
    # and restricted to literal cmd.exe arguments; none come from RDP envelopes.
    $target=@($policy.targets.PSObject.Properties)[0].Value
    if([string]$target.host -cnotmatch '^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$' -or
       [string]$target.user -cnotmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$' -or
       ($target.port -isnot [int] -and $target.port -isnot [long]) -or $target.port -lt 1 -or $target.port -gt 65535){throw 'Invalid approved SSH endpoint'}
    foreach($path in @($target.key_path,$target.known_hosts_path,$ssh)){
        if($path -cnotmatch '^[A-Za-z]:[\\/][A-Za-z0-9 ._\\/()-]+$'){throw 'Use literal Windows paths for operator OpenSSH'}
        Assert-PlainPath $path $true
        if(-not [IO.File]::Exists($path)){throw 'Approved SSH material missing'}
    }
    # Compression is confined to this dedicated, forwarding-disabled SSH session.
    $known=$target.known_hosts_path.Replace('\','/')
    $protocol=if($extendedOperator){2}else{1}
    $line='"'+$ssh+'" -F NUL -T -C -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitLocalCommand=no -o ProxyCommand=none -o ProxyJump=none -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes -o ConnectTimeout=15 -o "UserKnownHostsFile='+$known+'" -o GlobalKnownHostsFile=NUL -i "'+$target.key_path+'" -p '+$target.port+' '+$target.user+'@'+$target.host+' egw-operator-v'+$protocol+' < \\.\pipe\EgwIn'+$instance+' > \\.\pipe\EgwOut'+$instance
    $inTask=$operatorInput.WaitForConnectionAsync();$outTask=$operatorOutput.WaitForConnectionAsync()
    # CMD opens its redirects before OpenSSH authenticates. Use one startup
    # deadline for both events and keep the worker unavailable until the greeting.
    $requestTimer=[Diagnostics.Stopwatch]::StartNew()
    $attachDeadline=90000
    $attachPath=[IO.Path]::Combine($policy.operator_state_dir,'attach-ssh.cmd')
    Assert-PlainPath $attachPath $true
    Write-Atomic $attachPath ("@echo off`r`n"+$line+"`r`n") -Transient
    Write-Host 'Run the following in a separate CMD console in the same RDP session:'
    if($attachPath -match '[%!]'){Write-Host $line}else{Write-Host ('"'+$attachPath+'"')}
    if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($inTask,$outTask),(Operator-Remaining $attachDeadline))){throw 'Operator OpenSSH was not attached'}
    if([Text.Encoding]::ASCII.GetString((Operator-Read 8 $attachDeadline)) -cne "EGWSSH$protocol`n"){throw 'The approved Linux SSH endpoint did not start the expected operator protocol'}
}
function Open-OperatorSlot([long]$Slot){
    $name='ipc_res_'+$instance+'_'+$Slot+'.bin'
    return [IO.FileStream]::new([IO.Path]::Combine($SpoolDir,$name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,1)
}
function Start-OperatorStream{
    $name='ipc_req_'+$instance+'.bin'
    $requestPath=[IO.Path]::Combine($SpoolDir,$name)
    [IO.File]::Open($requestPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None).Dispose()
    $script:operatorRequests=[IO.FileStream]::new($requestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite,1)
    $slotPath=[IO.Path]::Combine($SpoolDir,('ipc_upload_'+$instance+'.bin'))
    $slot=[IO.File]::Open($slotPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$slot.SetLength(4096+1048576)}finally{$slot.Dispose()}
    for($i=0;$i -lt 4;$i++){
        $script:operatorUploadReaders+=[IO.FileStream]::new($requestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite,1)
        $script:operatorSlotReaders+=[IO.FileStream]::new($slotPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite,1)
    }
    $script:operatorSlots[0L]=Open-OperatorSlot 0
    $script:operatorSlots[1L]=Open-OperatorSlot 1
    Write-Atomic ([IO.Path]::Combine($SpoolDir,'ipc_descriptor.json')) (@{revision=3;block_bytes=4096;instance=$instance;worker_sha256=$loadedHash}|ConvertTo-Json -Compress) -Transient
}
function Read-OperatorFrame{
    # Cancellation and request reads share one pending I/O. Poll it without
    # making a redirected drive round trip part of waiting for an SSH reply.
    $position=$operatorCursor
    if($null -eq $operatorReadTask){
        $operatorRequests.Position=$position+$operatorFrameData.Length
        $script:operatorReadTask=$operatorRequests.ReadAsync($operatorReadBuffer,0,$operatorReadBuffer.Length)
    }
    if(-not $operatorReadTask.IsCompleted){return}
    $count=$operatorReadTask.GetAwaiter().GetResult()
    $script:operatorReadTask=$null
    if(-not $count){return}
    $end=[Array]::IndexOf($operatorReadBuffer,[byte]10,0,$count)
    $operatorFrameData.Write($operatorReadBuffer,0,$(if($end -lt 0){$count}else{$end}))
    if($operatorFrameData.Length -gt 1398176){throw 'Operator frame exceeds limit'}
    if($end -lt 0){return}

    $line=[Text.Encoding]::ASCII.GetString($operatorFrameData.ToArray())
    if($line -cnotmatch '^EGWS1 ([0-9a-f]{64}) ([A-Za-z0-9+/]*={0,2})$'){throw 'Invalid aligned operator request frame'}
    $digest=$Matches[1];$body=[Convert]::FromBase64String($Matches[2])
    if($body.Length -gt 1048576 -or (Hash-Bytes $body) -cne $digest){throw 'Operator frame checksum mismatch'}
    $value=$utf8.GetString($body)|ConvertFrom-Json
    if($value -isnot [Management.Automation.PSCustomObject] -or [string]$value.tx_id -cnotmatch '^[A-Za-z0-9_]{1,128}$'){throw 'Invalid operator request identity'}
    $offset=[long](4096*[Math]::Ceiling(($position+$operatorFrameData.Length+1)/4096.0))
    $next=$offset
    if($value.PSObject.Properties['upload_bytes']){
        $length=$value.upload_bytes
        if($value.op -cne 'ssh_push' -or ($length -isnot [int] -and $length -isnot [long]) -or
            $length -lt 1 -or $length -gt 1048576 -or $offset+$length -gt 67108864 -or
            $offset-$position+$length -gt 1398176){
            throw 'Invalid operator upload attachment length'
        }
        $next=[long](4096*[Math]::Ceiling(($offset+$length)/4096.0))
    }
    if($value.PSObject.Properties['upload_plain_bytes']){
        $plainLength=$value.upload_plain_bytes
        if(-not $value.PSObject.Properties['upload_bytes'] -or
            ($plainLength -isnot [int] -and $plainLength -isnot [long]) -or
            $plainLength -le $value.upload_bytes -or $plainLength -gt 1048576){throw 'Invalid uncompressed upload length'}
    }
    $operatorFrameData.SetLength(0)
    $script:operatorCursor=$next
    return @{Request=$value;Ticket=[long]($position/4096);UploadOffset=$offset}
}
function Receive-OperatorFrames([int]$Maximum=8){
    # Read ahead while waiting for SSH so a cancellation can close the pipe.
    # Keep pending frames in stream order and bound both pending queues.
    for($i=0;$i -lt $Maximum -and $operatorQueue.Count -lt 128;$i++){
        $frame=Read-OperatorFrame
        if($null -eq $frame){return}
        if($frame.Request.op -ceq 'cancel'){
            if($operatorCancelled.Count -ge 256){throw 'Operator cancellation capacity exceeded'}
            [void]$operatorCancelled.Add([string]$frame.Request.tx_id)
        }else{$operatorQueue.Enqueue($frame)}
    }
}
function Send-OperatorFrame($Value,[byte[]]$Data){
    $body=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Compress))
    if($body.Length -gt 32768){
        if($null -ne $Data){throw 'Download response metadata exceeds its limit'}
        $path=[IO.Path]::Combine($SpoolDir,('res_'+$Value.tx_id+'.json'))
        Write-Atomic $path ([Text.Encoding]::UTF8.GetString($body)) -Transient
        $body=[Text.Encoding]::UTF8.GetBytes((@{tx_id=$Value.tx_id;worker_instance=$instance;worker_sha256=$loadedHash;legacy_result=$true}|ConvertTo-Json -Compress))
    }
    $frame=[Text.Encoding]::ASCII.GetBytes(('EGWS1 '+(Hash-Bytes $body)+' '+[Convert]::ToBase64String($body)+"`n"))
    $file=$operatorSlots[$operatorTicket]
    if($null -eq $file){$file=Open-OperatorSlot $operatorTicket}
    try{
        $file.Write($frame,0,$frame.Length)
        if($null -ne $Data){$file.Write($Data,0,$Data.Length)}
    }finally{$file.Dispose();$operatorSlots.Remove($operatorTicket)}
}

Assert-PlainPath $PSCommandPath ([bool]$OperatorOpenSsh)
Assert-PlainPath $PolicyPath $true
Assert-PlainPath $SpoolDir
if(-not [IO.Directory]::Exists($SpoolDir)){throw 'Provision the private redirected spool before starting the worker'}
# Hold the policy and script against writes/replacement for this invocation.
$policyLease=$null;$scriptLease=$null;$sessionLease=$null;$operatorStateLease=$null
$instance=[Guid]::NewGuid().ToString('N')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$statePath=[IO.Path]::Combine($SpoolDir,'worker_state.json')
$journal=[IO.Path]::Combine($SpoolDir,'.structured-transactions')
$started=[Diagnostics.Stopwatch]::StartNew();$loadedHash='';$signatureStatus='NotSigned';$signer=''
$publishedRunning=$false
try{
    $policyLease=[IO.File]::Open($PolicyPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $scriptLease=[IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if((Hash-File $PolicyPath) -cne $PolicySha256){throw 'Approved worker policy hash mismatch'}
    $loadedHash=Hash-File $PSCommandPath
    if($RequireSignedAgents){$signature=Assert-Signature $PSCommandPath;$signatureStatus='Valid';$signer=$signature.SignerCertificate.Thumbprint}
    $policy=[IO.File]::ReadAllText($PolicyPath)|ConvertFrom-Json
    if($policy.revision -ne 1 -or -not $policy.targets -or $policy.owner_sid -cne $sid){throw 'Invalid policy or worker SID'}
    Assert-PolicyAcl $PolicyPath $sid ([bool]$OperatorOpenSsh)
    if(-not $OperatorOpenSsh -and -not $RequireSignedAgents){throw 'Spawn backend requires a signed adapter'}
    $ssh=[IO.Path]::Combine([Environment]::GetFolderPath('System'),'OpenSSH\ssh.exe')
    Assert-PlainPath $ssh $true
    [void](Assert-Signature $ssh $true)
    $sessionLease=[IO.File]::Open(([IO.Path]::Combine($SpoolDir,'.worker-session')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    if($OperatorOpenSsh){
        if(@($policy.targets.PSObject.Properties).Count -ne 1 -or ($RequireSignedAgents -and -not $TrustedSignerThumbprints.Count)){throw 'Operator backend requires one pinned SSH target and trusted publishers when adapter signing is enabled'}
        Assert-PlainPath $policy.operator_state_dir $true
        if(-not [IO.Directory]::Exists($policy.operator_state_dir)){throw 'Provision the local operator state directory'}
        if($env:OS -eq 'Windows_NT'){
            if([IO.DriveInfo]::new([IO.Path]::GetPathRoot($policy.operator_state_dir)).DriveType -eq 'Network'){
                throw 'Operator state requires a local Windows drive'
            }
            Assert-PolicyAcl $policy.operator_state_dir $sid $true
        }
        $stateLeasePath=[IO.Path]::Combine($policy.operator_state_dir,'.worker-session')
        Assert-PlainPath $stateLeasePath $true
        $operatorStateLease=[IO.File]::Open($stateLeasePath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $journal=[IO.Path]::Combine($policy.operator_state_dir,'.structured-transactions')
    }
    Assert-PlainPath $journal
    $binding=[IO.Path]::Combine($SpoolDir,'worker_structured_storage.json')
    $owner=Hash-Text ($sid+'|'+[Environment]::MachineName)
    if($OperatorOpenSsh){$owner=Hash-Text ($owner+'|operator|'+$PolicySha256)}
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
            spool_protocol=$(if($OperatorOpenSsh){'stream'}else{'files'});execution_model=$model;structured_backend=$backend;
            journal_location=$(if($OperatorOpenSsh){'bastion-local'}else{'redirected-durable'});probe_direct_reply=(-not $OperatorOpenSsh);
            last_heartbeat_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress) -Transient
        $script:lastPulse=$started.ElapsedMilliseconds
    }
    function Pulse{
        # Only startup and shutdown publish new state. Refresh its age without
        # an RDP file replacement or a partially visible JSON write.
        if([IO.File]::GetAttributes($statePath) -band [IO.FileAttributes]::ReparsePoint){throw 'Linked worker state is forbidden'}
        [IO.File]::SetLastWriteTimeUtc($statePath,[DateTime]::UtcNow)
        $script:lastPulse=$started.ElapsedMilliseconds
    }
    function Response([string]$Id,[int]$Code,[string]$Output,[string]$ErrorText,[string]$State='completed',[byte[]]$Data){
        $value=@{tx_id=$Id;exit_code=$Code;state=$State;worker_instance=$instance;worker_sha256=$loadedHash;
            stdout_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Output));
            stderr_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ErrorText));duration_ms=[int]$requestTimer.ElapsedMilliseconds}
        if($OperatorOpenSsh){Send-OperatorFrame $value $Data;return}
        $path=[IO.Path]::Combine($SpoolDir,('res_'+$Id+'.json'))
        $text=$value|ConvertTo-Json -Compress
        if($directProbeReply){
            # Only unique read-only replies use direct publication. Polling
            # readers wait for a complete JSON envelope and verify its nonce.
            Assert-PlainPath $SpoolDir
            try{$reply=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)}
            catch [IO.IOException]{if([IO.File]::Exists($path)){return};throw}
            try{
                $bytes=[Text.Encoding]::UTF8.GetBytes($text)
                $reply.Write($bytes,0,$bytes.Length)
            }finally{$reply.Dispose()}
        }else{
            Write-Atomic $path $text -Transient:($Id.StartsWith('probe_',[StringComparison]::Ordinal))
        }
    }
    function Target($Request){
        if([string]$Request.target -cnotmatch '^[A-Za-z0-9_.-]{1,80}$'){throw 'Invalid target identifier'}
        $entry=$policy.targets.PSObject.Properties[[string]$Request.target]
        if(-not $entry){throw 'Target is not in the independently approved policy'}
        $node=$entry.Value
        if($Request.expected_host -ine $node.host -or $Request.expected_port -ne $node.port -or $Request.expected_user -cne $node.user){throw 'Configured target differs from the independently approved policy'}
        if([string]$node.host -notmatch '^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$' -or [string]$node.user -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$' -or
           ($node.port -isnot [int] -and $node.port -isnot [long]) -or $node.port -lt 1 -or $node.port -gt 65535){throw 'Invalid approved SSH endpoint'}
        if($OperatorOpenSsh){return $node}
        foreach($path in @($node.key_path,$node.known_hosts_path)){Assert-PlainPath $path $true;if(-not [IO.File]::Exists($path)){throw 'Approved SSH trust material missing'}}
        return $node
    }
    function Run-Ssh($Node,[string]$Remote,[string]$InputFile,[string]$InputText,[string]$OutputFile,[double]$Deadline,[string]$Id,[ref]$Dispatched){
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
            $cancelPath=[IO.Path]::Combine($SpoolDir,('cancel_'+$Id+'.json'))
            if([IO.File]::Exists($cancelPath) -or ($StopFile -and [IO.File]::Exists($StopFile)) -or
               $started.Elapsed.TotalSeconds -ge $LeaseSeconds -or $requestTimer.ElapsedMilliseconds -ge $Deadline){
                throw 'SSH deadline or cancellation reached before dispatch'
            }
            $Dispatched.Value=$true
            [void]$process.Start()
            $outBuffer=New-Object byte[] 65536;$errBuffer=New-Object byte[] 65536
            $output=$process.StandardOutput.BaseStream.ReadAsync($outBuffer,0,$outBuffer.Length)
            $errors=$process.StandardError.BaseStream.ReadAsync($errBuffer,0,$errBuffer.Length)
            if($OutputFile){$outputStream=[IO.File]::Open($OutputFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)}
            else{$outputStream=New-Object IO.MemoryStream}
            $errorStream=New-Object IO.MemoryStream
            if($InputFile){$inputStream=[IO.File]::OpenRead($InputFile)}else{$inputStream=[IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($InputText))}
            $writeTask=$inputStream.CopyToAsync($process.StandardInput.BaseStream)
            $closed=$false;$outDone=$false;$errDone=$false
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
                if($requestTimer.ElapsedMilliseconds -ge $Deadline -or $started.Elapsed.TotalSeconds -ge $LeaseSeconds -or
                   [IO.File]::Exists($cancelPath) -or ($StopFile -and [IO.File]::Exists($StopFile))){
                    throw 'SSH interrupted; remote outcome requires reconciliation'
                }
                if($started.ElapsedMilliseconds-$script:lastPulse -ge 5000){Pulse}
                Start-Sleep -Milliseconds 10
            }
            if(-not $writeTask.Wait(1000) -or $writeTask.IsFaulted){throw 'SSH input stream completion unavailable'}
            if($OutputFile){$outputStream.Flush($true);$text=''}else{$text=[Text.Encoding]::UTF8.GetString($outputStream.ToArray())}
            $errorText=[Text.Encoding]::UTF8.GetString($errorStream.ToArray())
            return @{Code=$process.ExitCode;Output=$text;Error=$errorText}
        }finally{
            try{if($Dispatched.Value -and -not $process.HasExited){$process.Kill();[void]$process.WaitForExit(1000)}}catch{}
            $process.Dispose();if($inputStream){$inputStream.Dispose()};if($outputStream){$outputStream.Dispose()};if($errorStream){$errorStream.Dispose()}
        }
    }
    if($OperatorOpenSsh){
        Heartbeat 'starting'
        Open-OperatorPipes
        Watch-OperatorPeer
        Start-OperatorStream
        Assert-OperatorPeerIdle
        # Start the reader before publishing readiness so a cold read can
        # begin before the host starts the first attestation deadline.
        Receive-OperatorFrames 1
    }
    Heartbeat
    $publishedRunning=$true
    while($started.Elapsed.TotalSeconds -lt $LeaseSeconds -and -not ($StopFile -and [IO.File]::Exists($StopFile))){
        if($OperatorOpenSsh){
            Assert-OperatorPeerIdle
            $queue=@()
            Receive-OperatorFrames 1
            Assert-OperatorPeerIdle
            if($operatorQueue.Count){$queue=@($operatorQueue.Dequeue())}
        }else{
            $directory=[IO.DirectoryInfo]::new($SpoolDir)
            $queue=$directory.EnumerateFiles('req_*.json')
        }
        foreach($item in $queue){
            $path=''
            if($OperatorOpenSsh){
                $request=$item.Request;$id=$request.tx_id;$operatorTicket=$item.Ticket
            }else{
                $fileInfo=$item;$name=$fileInfo.Name
                if($name -cnotmatch '^req_([A-Za-z0-9_]{1,128})\.json$'){continue}
                $path=$fileInfo.FullName;$id=$Matches[1]
            }
            $record=[IO.Path]::Combine($journal,($id+'.json'));$claimed=$false;$dispatched=$false;$directProbeReply=$false;$phase='request';$requestTimer=[Diagnostics.Stopwatch]::StartNew()
            try{
                if(-not $OperatorOpenSsh){
                    if(($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $fileInfo.Length -gt 2097152){throw 'Invalid request file'}
                    $request=[IO.File]::ReadAllText($path)|ConvertFrom-Json
                }
                $allowed=@('tx_id','op','timeout_ms','expires_unix_ms','operation_id','expected_worker_instance','expected_worker_sha256','target','expected_host','expected_port','expected_user','command','as_root','transfer_id','remote_path','sha256','attestation_nonce','probe_direct_reply')
                if($OperatorOpenSsh){$allowed+=@('upload_bytes','upload_plain_bytes','upload_slot_bytes','copy_action','copy_offset','copy_length')}
                if(@($request.PSObject.Properties.Name|Where-Object{$_ -notin $allowed}).Count -or $request.tx_id -cne $id){throw 'Unsupported request fields'}
                if($OperatorOpenSsh -and (-not $request.expected_worker_instance -or -not $request.expected_worker_sha256)){throw 'Operator stream requires worker identity'}
                if($request.expected_worker_instance -and $request.expected_worker_instance -cne $instance){throw 'Worker instance changed'}
                if($request.expected_worker_sha256 -and $request.expected_worker_sha256 -cne $loadedHash){throw 'Worker release changed'}
                if(($request.timeout_ms -isnot [int] -and $request.timeout_ms -isnot [long]) -or $request.timeout_ms -lt 1 -or $request.timeout_ms -gt 86400000){throw 'Invalid deadline'}
                if($request.expires_unix_ms -isnot [int] -and $request.expires_unix_ms -isnot [long]){throw 'Invalid request expiry'}
                $remaining=[double]$request.expires_unix_ms-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                $operatorExecInProgress=$extendedOperator -and $request.op -ceq 'ssh_exec'
                $limit=if($operatorExecInProgress){[Math]::Min($request.timeout_ms,$OperatorExecMaxSec*1000)}
                       elseif($OperatorOpenSsh){[Math]::Min($request.timeout_ms,15000)}else{$request.timeout_ms}
                $deadline=$requestTimer.ElapsedMilliseconds+[Math]::Min($limit,$remaining)
                if($remaining -le 0 -or ($OperatorOpenSsh -and $operatorCancelled.Contains($id)) -or (-not $OperatorOpenSsh -and [IO.File]::Exists([IO.Path]::Combine($SpoolDir,('cancel_'+$id+'.json'))))){Response $id 125 '' 'Cancelled before dispatch' 'cancelled';continue}
                if(($request.PSObject.Properties.Name -contains 'as_root') -and $request.as_root -isnot [bool]){throw 'Invalid privilege option'}
                if($request.PSObject.Properties['upload_slot_bytes'] -and (
                    $request.op -cne 'ssh_copy' -or $request.copy_action -cne 'push_part' -or
                    ($request.upload_slot_bytes -isnot [int] -and $request.upload_slot_bytes -isnot [long]) -or
                    $request.upload_slot_bytes -lt 1 -or $request.upload_slot_bytes -gt 1048576 -or
                    $request.upload_slot_bytes -ne $request.copy_length)){throw 'Invalid upload slot request'}
                $probe=$id.StartsWith('probe_',[StringComparison]::Ordinal)
                if($probe -and [string]$request.op -cnotin @('attest','ping')){throw 'Probe IDs are reserved for attestation and ping'}
                if($request.PSObject.Properties.Name -contains 'probe_direct_reply'){
                    if(-not $probe -or $request.probe_direct_reply -isnot [bool]){throw 'Direct replies require a read-only probe'}
                    $directProbeReply=$request.probe_direct_reply
                }
                if(-not $probe){
                    # CreateNew is a durable no-replay boundary, including after reconnect.
                    Assert-PlainPath $record
                    $claim=[IO.File]::Open($record,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                    try{
                        $recordData=@{tx_id=$id;operation_id=[string]$request.operation_id;state='running';instance_id=$instance;started_utc=[DateTime]::UtcNow.ToString('o')}
                        $bytes=[Text.Encoding]::UTF8.GetBytes(($recordData|ConvertTo-Json -Compress))
                        $claim.Write($bytes,0,$bytes.Length)
                        $claim.Flush($true)
                    }finally{$claim.Dispose()}
                    $claimed=$true
                }
                $out='';$code=0;$err='';$state='completed';$data=$null
                switch -CaseSensitive ([string]$request.op){
                    'ping' {$out='VFS_PONG'}
                    'clean' {$out='STRUCTURED_CLEAN: durable outcomes and unclaimed evidence preserved'}
                    'stop' {$out='WORKER_STOP_ACCEPTED'}
                    'attest' {
                        if([string]$request.attestation_nonce -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid challenge'}
                        $freshStatus='NotSigned';$freshSigner=''
                        if($RequireSignedAgents){$fresh=Assert-Signature $PSCommandPath;$freshStatus='Valid';$freshSigner=$fresh.SignerCertificate.Thumbprint}
                        $evidence=@{protocol_revision=1;version='0.3.0';nonce=$request.attestation_nonce;instance_id=$instance;loaded_sha256=$loadedHash;
                            current_sha256=(Hash-File $PSCommandPath);loaded_signature_status=$signatureStatus;loaded_signer=$signer;
                            signature_status=$freshStatus;signer=$freshSigner;sid=$sid;execution_model=$model;
                            execution_profile='structured_only';policy_sha256=$PolicySha256;stream_upload_v1=[bool]$OperatorOpenSsh;stream_upload_deflate_v1=[bool]$OperatorOpenSsh;chunked_copy_v1=[bool]$OperatorOpenSsh;chunked_copy_slots_v1=[bool]$OperatorOpenSsh}
                        if($extendedOperator){$evidence.operator_exec_max_sec=$OperatorExecMaxSec}
                        $out=$evidence|ConvertTo-Json -Compress
                    }
                    {$_ -cin @('ssh_exec','ssh_push','ssh_pull','ssh_copy')} {
                        $phase='policy';$node=Target $request
                        if($request.op -ceq 'ssh_copy' -and -not $OperatorOpenSsh){throw 'Chunked copy requires the operator backend'}
                        if($request.as_root -and $node.allow_sudo -ne $true){throw 'sudo is not approved for this target'}
                        $prefix=if($request.as_root){'sudo -n sh -c '}else{'sh -c '}
                        $inputFile='';$outputFile='';$inputText='';$downloadLength=-1
                        if($request.op -eq 'ssh_exec'){
                            if($node.allow_exec -ne $true -or $request.command -isnot [string] -or $request.command.Length -gt 1048576){throw 'Command execution is not approved'}
                            $remote=if($request.as_root){'sudo -n sh -s'}else{'sh -s'};$inputText=$request.command+"`n"
                        }else{
                            if($node.allow_transfer -ne $true -or [string]$request.transfer_id -cnotmatch '^[a-f0-9]{32}$' -or
                               $request.remote_path -isnot [string] -or -not $request.remote_path.StartsWith('/') -or $request.remote_path.IndexOfAny([char[]]@("`r","`n",[char]0)) -ge 0){throw 'Invalid or unapproved transfer'}
                            $transfer=[IO.Path]::Combine($SpoolDir,('structured_'+$request.transfer_id+'.bin'))
                            if(-not $OperatorOpenSsh){Assert-PlainPath $transfer}
                            $remotePath=Quote-Posix $request.remote_path
                            if($request.op -ceq 'ssh_copy'){
                                $body=New-OperatorCopyCommand $request
                                $recordData.copy_action=$request.copy_action
                                $recordData.transfer_id=$request.transfer_id
                                $recordData.copy_offset=$request.copy_offset
                                if($request.copy_action -ceq 'push_part'){
                                    if($request.copy_length -gt 0 -and -not $request.upload_slot_bytes){throw 'Upload slot is required'}
                                    if($request.copy_length -eq 0 -and $request.sha256 -cne (Hash-Bytes ([byte[]]::new(0)))){throw 'Invalid empty upload checksum'}
                                }
                                if($request.copy_action -ceq 'pull_part'){$downloadLength=$request.copy_length}
                            }elseif($request.op -eq 'ssh_push'){
                                if([string]$request.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid upload checksum'}
                                if(-not $OperatorOpenSsh){
                                    if((New-Object IO.FileInfo($transfer)).Length -gt 67108864){throw 'Transfer limit exceeded'}
                                    if((Hash-File $transfer) -cne $request.sha256){throw 'Upload checksum mismatch'}
                                }
                                $stage=Quote-Posix ($request.remote_path+'.egw-'+$request.transfer_id)
                                $body='(umask 077; set -C; : > '+$stage+') || exit 1; trap '+(Quote-Posix ('rm -f -- '+$stage))+' 0; cat > '+$stage+' && test "$(sha256sum < '+$stage+' | cut -d " " -f 1)" = '+(Quote-Posix $request.sha256)+' && mv -f -- '+$stage+' '+$remotePath+' && printf '+(Quote-Posix ('VERIFIED:'+$request.sha256))
                                $inputFile=$transfer
                            }else{
                                $body='sha256sum < '+$remotePath+'; cat -- '+$remotePath
                                $outputFile=$transfer
                            }
                            $remote=$prefix+(Quote-Posix $body)
                        }
                        $phase='ssh'
                        $result=if($OperatorOpenSsh){Invoke-OperatorSsh $remote $inputFile $inputText $outputFile $deadline $id ([ref]$dispatched) ([string]$request.sha256) $recordData $item.UploadOffset $request.upload_bytes $request.upload_plain_bytes $request.upload_slot_bytes $downloadLength $request.op}
                        else{Run-Ssh $node $remote $inputFile $inputText $outputFile $deadline $id ([ref]$dispatched)}
                        $code=$result.Code;$out=$result.Output;$err=$result.Error
                        $data=$result.Data
                        if($result.State){$state=$result.State}elseif($code){$state='failed'}
                        if(-not $OperatorOpenSsh -and $request.op -eq 'ssh_pull' -and -not $code){
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
                if($claimed){
                    $recordData.state=$state;$recordData.exit_code=$code
                    Write-Atomic $record ($recordData|ConvertTo-Json -Compress)
                }
                Response $id $code $out $err $state $data
                if($request.op -eq 'stop'){return}
            }catch{
                $state=if($dispatched){'indeterminate'}else{'failed'}
                if($claimed){$recordData.state=$state;$recordData.failure_stage=$phase;$recordData.error_type=$_.Exception.GetType().FullName;Write-Atomic $record ($recordData|ConvertTo-Json -Compress)}
                Response $id 125 '' ('Structured operation failed at '+$phase+' ('+$_.Exception.GetType().Name+'); inspect approved policy and reconcile durable outcomes before retrying') $state
            }finally{$operatorExecInProgress=$false;if($path){[IO.File]::Delete($path)};if($OperatorOpenSsh){[void]$operatorCancelled.Remove($id)}}
            if($operatorBroken){return}
        }
        if($OperatorOpenSsh){
            Assert-OperatorPeerIdle
            $next=[long]($operatorCursor/4096)
            if($operatorQueue.Count){$next=$operatorQueue.Peek().Ticket}
            foreach($stale in @($operatorSlots.Keys)){if($stale -lt $next){$operatorSlots[$stale].Dispose();$operatorSlots.Remove($stale)}}
            if(-not $operatorSlots.ContainsKey($next)){$operatorSlots[$next]=Open-OperatorSlot $next}
        }
        if($started.ElapsedMilliseconds-$script:lastPulse -ge 5000){Pulse}
        Start-Sleep -Milliseconds $(if($OperatorOpenSsh){15}else{100})
    }
}finally{
    try{
        # Stop accepting traffic before closing redirected handles, whose
        # close operations may each require a network round trip.
        if($OperatorOpenSsh -and $publishedRunning){
            try{
                if(-not ([IO.File]::GetAttributes($statePath) -band [IO.FileAttributes]::ReparsePoint)){
                    # Invalidate the readiness timestamp before the slower JSON
                    # replacement. The session lease stays held throughout.
                    [IO.File]::SetLastWriteTimeUtc($statePath,[DateTime]::new(2000,1,1,0,0,0,[DateTimeKind]::Utc))
                }
            }catch [IO.IOException]{}catch [UnauthorizedAccessException]{}
        }
        if($sessionLease -and (Get-Command Heartbeat -CommandType Function -ErrorAction SilentlyContinue)){Heartbeat 'stopped'}
    }finally{
        try{
            if($operatorInput){$operatorInput.Dispose()};if($operatorOutput){$operatorOutput.Dispose()}
            $operatorFrameData.Dispose()
            foreach($reader in $operatorUploadReaders){$reader.Dispose()}
            foreach($reader in $operatorSlotReaders){$reader.Dispose()}
            if($operatorRequests){$operatorRequests.Dispose()};foreach($slot in $operatorSlots.Values){$slot.Dispose()}
        }finally{
            if($sessionLease){$sessionLease.Dispose()}
            if($operatorStateLease){$operatorStateLease.Dispose()}
            if($scriptLease){$scriptLease.Dispose()};if($policyLease){$policyLease.Dispose()}
        }
    }
}
