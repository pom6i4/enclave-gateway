"""Bounded local Appliance cleanup without discarding active request ownership."""
from enclave_gateway.security.quoting import ps_quote


def cleanup_script(spool):
    return r'''$ErrorActionPreference='Stop'
$spool=SPOOL;$removed=0;$deferred=0;$errors=0;$lease=$null;$stopped=$false
if([IO.Directory]::Exists($spool)){
 $binding=Join-Path $spool 'worker_storage.json';$session=Join-Path $spool '.worker-session'
 if([IO.File]::Exists($binding) -and [IO.File]::Exists($session)){
  try{
   $meta=[IO.File]::ReadAllText($binding)|ConvertFrom-Json
   if($meta.protocol -eq 2){$lease=[IO.File]::Open($session,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$stopped=$true}
  }catch{}
 }
 try{
  foreach($file in @([IO.Directory]::EnumerateFiles($spool))){
   try{
    if([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint){continue}
    $name=[IO.Path]::GetFileName($file);$age=([DateTime]::UtcNow-[IO.File]::GetLastWriteTimeUtc($file)).TotalSeconds
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
Write-Output ('APPLIANCE_CLEAN_OK:'+(@{removed=$removed;deferred_processing=$deferred;errors=$errors;stopped_worker_verified=$stopped}|ConvertTo-Json -Compress))
if($errors){exit 1}
'''.replace('SPOOL',ps_quote(spool))
