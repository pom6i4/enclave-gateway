"""Bounded local Appliance cleanup without discarding active request ownership."""
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.control.stream_pruner import LOCAL_STREAM_PRUNER


def cleanup_script(spool, *, execution_profile='legacy', structured_backend='spawn'):
    if structured_backend == 'operator':
        if execution_profile != 'structured_only':
            raise ValueError('Operator cleanup requires structured_only')
        return _operator_cleanup_script(spool)
    if structured_backend != 'spawn':
        raise ValueError('Unknown structured backend')
    if execution_profile not in ('legacy','structured_only'):raise ValueError('Unknown cleanup profile')
    binding='worker_structured_storage.json' if execution_profile=='structured_only' else 'worker_storage.json'
    valid=("$meta.revision -eq 1 -and $meta.owner_sha256 -cmatch '^[a-f0-9]{64}$' -and [IO.Directory]::Exists((Join-Path $spool '.structured-transactions'))"
           if execution_profile=='structured_only' else '$meta.protocol -eq 2')
    return r'''$ErrorActionPreference='Stop'
$spool=SPOOL;$removed=0;$deferred=0;$errors=0;$lease=$null;$stopped=$false
$streamRemoved=0;$streamDeferred=0;$streamPreserved=0;$streamCleanup='worker_not_stopped';$activeInstance=''
$prunerAttempted=$false;$prunerReady=$false
$streamErrorCodes=@{}
if($env:OS -eq 'Windows_NT'){
 $full=[IO.Path]::GetFullPath($spool)
 if($full.StartsWith('\\') -or (New-Object IO.DriveInfo([IO.Path]::GetPathRoot($full))).DriveType -eq [IO.DriveType]::Network){throw 'Cleanup requires a local Appliance spool, not a redirected or mapped network path'}
 $parent=New-Object IO.DirectoryInfo($full)
 while($parent){if($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked Appliance cleanup path rejected'};$parent=$parent.Parent}
}
if([IO.Directory]::Exists($spool)){
 $binding=Join-Path $spool 'STORAGE_BINDING';$session=Join-Path $spool '.worker-session'
 if([IO.File]::Exists($binding) -and [IO.File]::Exists($session)){
  try{
   $meta=[IO.File]::ReadAllText($binding)|ConvertFrom-Json
   if(VALID_STORAGE_BINDING){$lease=[IO.File]::Open($session,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$stopped=$true}
  }catch{}
 }
 try{
  if($stopped -and $env:OS -eq 'Windows_NT'){
   $streamCleanup='descriptor_unavailable';$descriptor=Join-Path $spool 'ipc_descriptor.json'
   if([IO.File]::Exists($descriptor)){
    try{
     if(([IO.File]::GetAttributes($descriptor) -band [IO.FileAttributes]::ReparsePoint) -or (Get-Item -LiteralPath $descriptor).Length -gt 4096){throw 'Invalid stream descriptor'}
     $info=[IO.File]::ReadAllText($descriptor)|ConvertFrom-Json
     if(($info.revision -isnot [int] -and $info.revision -isnot [long]) -or $info.revision -ne 3 -or
        ($info.block_bytes -isnot [int] -and $info.block_bytes -isnot [long]) -or $info.block_bytes -ne 4096 -or
        $info.instance -isnot [string] -or $info.instance -cnotmatch '^[a-f0-9]{32}$' -or
        $info.worker_sha256 -isnot [string] -or $info.worker_sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid stream descriptor'}
     $activeInstance=$info.instance;$streamCleanup='complete'
    }catch{$streamCleanup='invalid_descriptor';$errors++}
   }
  }elseif($stopped){$streamCleanup='unsupported_platform'}
  foreach($file in @([IO.Directory]::EnumerateFiles($spool))){
   try{
    if([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint){continue}
    $name=[IO.Path]::GetFileName($file);$age=([DateTime]::UtcNow-[IO.File]::GetLastWriteTimeUtc($file)).TotalSeconds
    $streamCandidate=$false;$emptyOnly=$true;$retired=''
    if($name -cmatch '^worker_pulse_([a-f0-9]{32})_[ab]\.json$'){$streamCandidate=$true;$emptyOnly=$false;$retired=$Matches[1]}
    elseif($name -cmatch '^ipc_res_([a-f0-9]{32})_([0-9]{1,5})\.bin$' -and [int]$Matches[2] -lt 16384){$streamCandidate=$true;$retired=$Matches[1]}
    if($streamCandidate){
     if(-not $activeInstance -or $retired -ceq $activeInstance){$streamPreserved++;continue}
     if(-not $prunerAttempted){
      $prunerAttempted=$true
      try{STREAM_HELPER
       $prunerReady=$true
      }catch{$streamCleanup='helper_unavailable';$errors++}
     }
     if(-not $prunerReady){$streamDeferred++;continue}
     try{
      if([EnclaveGateway.LocalStreamPruner]::Delete($file,$emptyOnly)){$removed++;$streamRemoved++}else{$streamPreserved++}
     }catch{
      $cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException}
      if($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -in @(2,3,32,33)){$streamDeferred++}else{
       $code=if($cause -is [ComponentModel.Win32Exception]){[string]$cause.NativeErrorCode}else{[string]$cause.HResult}
       $streamErrorCodes[$code]=1+[int]$streamErrorCodes[$code];$streamCleanup='failed';throw
      }
     }
     continue
    }
    if($name -match '^req_([A-Za-z0-9_-]{1,128})\.json$'){
     $id=$Matches[1];$request=[IO.File]::ReadAllText($file)|ConvertFrom-Json
     if($request.tx_id -cne $id -or -not $request.expires_unix_ms -or [double]$request.expires_unix_ms -ge [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()){continue}
     # Atomic claim competes with worker dispatch. The losing side leaves it alone.
     $claim=$file+'.cleaning'
     try{[IO.File]::Move($file,$claim)}catch{continue}
     [IO.File]::Delete($claim);$removed++
     $cancel=Join-Path $spool ('cancel_'+$id+'.json')
     if(-not [IO.File]::Exists($file+'.processing')){[IO.File]::Delete($cancel)}
    }elseif($name -match '^req_[A-Za-z0-9_-]{1,128}\.json\.processing$'){
     if($stopped){[IO.File]::Delete($file);$removed++}else{$deferred++}
    }elseif($name -match '^cancel_([A-Za-z0-9_-]{1,128})\.json$'){
     $id=$Matches[1]
     if($age -gt 300 -and -not [IO.File]::Exists((Join-Path $spool ('req_'+$id+'.json'))) -and -not [IO.File]::Exists((Join-Path $spool ('req_'+$id+'.json.processing')))){[IO.File]::Delete($file);$removed++}
    }elseif(($name -match '^res_[A-Za-z0-9_-]{1,128}\.json$' -and $age -gt 300) -or
             ($name -match '^(chunk_[A-Za-z0-9_]+\.bin|pull_[A-Za-z0-9_]+\.bin|egw_(stage|pull)_[a-f0-9]{24}|(req|res|worker_state)_[A-Za-z0-9_.-]+\.tmp)$' -and $age -gt 86400)){
     [IO.File]::Delete($file);$removed++
    }
   }catch [IO.FileNotFoundException] {continue}catch{$errors++}
  }
 }finally{if($lease){$lease.Dispose()}}
}
Write-Output ('APPLIANCE_CLEAN_OK:'+(@{removed=$removed;deferred_processing=$deferred;errors=$errors;stopped_worker_verified=$stopped;stream_cleanup=$streamCleanup;stream_removed=$streamRemoved;stream_preserved=$streamPreserved;stream_deferred=$streamDeferred;stream_error_codes=$streamErrorCodes}|ConvertTo-Json -Compress))
if($errors){exit 1}
'''.replace('STREAM_HELPER',LOCAL_STREAM_PRUNER).replace('VALID_STORAGE_BINDING',valid).replace('STORAGE_BINDING',binding).replace('SPOOL',ps_quote(spool))

def _operator_cleanup_script(spool):
    """Reclaim retired, scrubbed buffers on the Appliance under the worker lease."""
    return r'''$ErrorActionPreference='Stop'
$spool=SPOOL
$stopped=$false
$lease=$null
$removed=0;$preserved=0;$deferred=0;$errors=0
$cleanup='worker_not_stopped'
if($env:OS -eq 'Windows_NT'){
 $spool=[IO.Path]::GetFullPath($spool)
 if($spool.StartsWith('\\') -or [IO.DriveInfo]::new([IO.Path]::GetPathRoot($spool)).DriveType -eq 'Network'){
  throw 'Operator cleanup requires the local Appliance spool'
 }
}
$dir=[IO.DirectoryInfo]::new($spool)
while($dir){
 if($dir.Exists -and ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked Appliance cleanup path rejected'}
 $dir=$dir.Parent
}
$path=[IO.Path]::Combine($spool,'.worker-session')
if([IO.File]::Exists($path)){
 if([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint){throw 'Linked operator lease rejected'}
 try{
  $lease=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  $statePath=[IO.Path]::Combine($spool,'worker_state.json')
  $binding=[IO.Path]::Combine($spool,'worker_structured_storage.json')
  if([IO.File]::Exists($statePath) -and [IO.File]::Exists($binding)){
   foreach($item in $statePath,$binding){
    $info=[IO.FileInfo]::new($item)
    if(($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $info.Length -gt 65536){throw 'Invalid operator cleanup metadata'}
   }
   $state=[IO.File]::ReadAllText($statePath)|ConvertFrom-Json
   $meta=[IO.File]::ReadAllText($binding)|ConvertFrom-Json
   $stopped=$state.status -ceq 'stopped' -and $state.execution_profile -ceq 'structured_only' -and
    $state.structured_backend -ceq 'operator' -and $state.spool_protocol -ceq 'stream' -and
    $state.instance_id -cmatch '^[a-f0-9]{32}$' -and $meta.revision -eq 1 -and $meta.owner_sha256 -cmatch '^[a-f0-9]{64}$'
  }
  if($stopped){
   $cleanup='unsupported_platform'
   if($env:OS -eq 'Windows_NT'){
    $cleanup='complete'
    $attempts=0;$remaining=134217728;$prunerReady=$false
    foreach($file in [IO.DirectoryInfo]::new($spool).EnumerateFiles()){
     if($file.Name -cnotmatch '^ipc_(?:req_|upload_|res_)([a-f0-9]{32})(?:_[0-9]{1,5})?\.bin$'){continue}
     if($file.Name.StartsWith('ipc_res_') -ne ($file.Name -cmatch '_[0-9]{1,5}\.bin$')){continue}
     if($attempts -ge 128 -or $remaining -le 0){$cleanup='bounded';break}
     $attempts++
     try{
      if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 67108864){$preserved++;continue}
      if($file.Length -gt $remaining){$deferred++;continue}
      $length=[uint32]$file.Length;$remaining-=$length
      if(-not $prunerReady){STREAM_HELPER
       $prunerReady=$true
      }
      if([EnclaveGateway.LocalStreamPruner]::DeleteZero($file.FullName,$length)){$removed++}else{$preserved++}
     }catch{
      $cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException}
      if($cause -is [IO.FileNotFoundException] -or ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -in @(2,3,32,33))){
       $deferred++
      }else{$errors++;$cleanup='failed';break}
     }
    }
   }
  }
 }catch [IO.IOException]{}finally{if($lease){$lease.Dispose()}}
}
Write-Output ('APPLIANCE_CLEAN_OK:'+(@{removed=$removed;errors=$errors;stopped_worker_verified=$stopped;stream_cleanup=$cleanup;stream_removed=$removed;stream_preserved=$preserved;stream_deferred=$deferred}|ConvertTo-Json -Compress))
if($errors){exit 1}
'''.replace('STREAM_HELPER', LOCAL_STREAM_PRUNER).replace('SPOOL', ps_quote(spool))
