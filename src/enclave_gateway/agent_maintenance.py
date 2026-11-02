"""Explicit, quiescent cleanup of lease-aware agent generations."""
from __future__ import annotations
import json
import re
from enclave_gateway.onboarding import agent_bundle
from enclave_gateway.operations.context import mark_dispatched
from enclave_gateway.security.quoting import ps_quote


def prune_agent_bundles(control,config,*,remove=(),keep=(),min_age_hours=168,apply=False):
    if not config.bastion.enabled:raise ValueError('Agent maintenance requires an enabled Bastion')
    if type(min_age_hours) is not int or not 1<=min_age_hours<=87600:raise ValueError('Minimum bundle age must be 1..87600 hours')
    for values in (remove,keep):
        if len(values)>100 or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in values):
            raise ValueError('Use at most 100 exact lowercase bundle SHA-256 identifiers')
    if apply and not remove:raise ValueError('Apply requires explicit --remove identifiers from a reviewed preview')
    if not apply and remove:raise ValueError('--remove requires --apply')
    _,_,current,_=agent_bundle(config)
    root=config.bastion.appliance_spool_dir.rstrip('\\/')+'\\agents'
    script=r'''$ErrorActionPreference='Stop'
$root=ROOT;$keep=@(KEEP);$remove=@(REMOVE);$apply=APPLY;$hours=HOURS
function Assert-Directory([string]$path){
 if(-not [IO.Path]::IsPathRooted($path) -or $path.StartsWith('\\')){throw 'Use a local absolute Appliance spool path'}
 $p=New-Object IO.DirectoryInfo($path)
 while($p){if($p.Exists -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked bundle path rejected'};$p=$p.Parent}
}
Assert-Directory $root
if(-not(Test-Path -LiteralPath $root)){
 if($apply){throw 'No managed bundles exist'}
 @{schema='egw.agents-prune.v1';applied=$false;bundles=@();removed=@()}|ConvertTo-Json -Compress;return
}
$lock=Join-Path $root '.bundle-lease'
if(-not(Test-Path -LiteralPath $lock) -or ((Get-Item -LiteralPath $lock -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'No safe bundle lease; stage current agents before maintenance'}
$lease=$null
try{
 try{
  $share=if($apply){[IO.FileShare]::None}else{[IO.FileShare]::Read}
  $lease=[IO.File]::Open($lock,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
 }catch{throw 'Bundle maintenance is busy: stop managed workers and retry; no bundles were removed'}
 $rows=@();$eligible=@{}
 foreach($directory in @(Get-ChildItem -LiteralPath $root -Directory -Force | Sort-Object Name)){
  $id=$directory.Name
  if($id -cnotmatch '^[a-f0-9]{64}$'){continue}
  $reason='legacy-or-unrecognized';$valid=$false
  try{
   Assert-Directory $directory.FullName
   $entries=@(Get-ChildItem -LiteralPath $directory.FullName -Force)
   if($entries.Count -ne 3){throw 'Unexpected generation contents'}
   foreach($entry in $entries){if($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $entry.Name -cnotin @('bastion_worker.ps1','bastion_bootstrap.ps1','bundle.json')){throw 'Unsafe generation entry'}}
   $receiptPath=Join-Path $directory.FullName 'bundle.json'
   if((Get-Item -LiteralPath $receiptPath).Length -gt 4096){throw 'Oversized receipt'}
   $receipt=Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8|ConvertFrom-Json
   if($receipt.protocol -ne 1 -or $receipt.bundle_sha256 -cne $id){throw 'Unknown cleanup protocol'}
   $hashes=@{}
   foreach($name in @('bastion_bootstrap.ps1','bastion_worker.ps1')){
    $hash=(Get-FileHash -LiteralPath (Join-Path $directory.FullName $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if($receipt.files.$name -cne $hash){throw 'Generation content changed'}
    $hashes[$name]=$hash
   }
   $canonical='{"bastion_bootstrap.ps1": "'+$hashes['bastion_bootstrap.ps1']+'", "bastion_worker.ps1": "'+$hashes['bastion_worker.ps1']+'"}'
   $sha=[Security.Cryptography.SHA256]::Create()
   try{$identity=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
   if($identity -cne $id){throw 'Generation identity mismatch'}
   if(-not (Select-String -LiteralPath (Join-Path $directory.FullName 'bastion_worker.ps1') -SimpleMatch '# EGW_BUNDLE_LEASE_V1' -Quiet)){throw 'Legacy worker has no lifetime lease'}
   $valid=$true
  }catch{$valid=$false}
  if($valid){
   if($id -in $keep){$reason='retained'}
   elseif($directory.LastWriteTimeUtc -gt [DateTime]::UtcNow.AddHours(-$hours)){$reason='too-recent'}
   else{$reason='eligible';$eligible[$id]=$directory.FullName}
  }
  $rows+=@{bundle_sha256=$id;reason=$reason}
 }
 # Validate the complete explicit set before changing any generation.
 foreach($id in $remove){if(-not $eligible.ContainsKey($id)){throw 'Requested bundle is retained, too recent, changed or unrecognized; nothing removed'}}
 $removed=@()
 if($apply){
  foreach($id in @($remove|Select-Object -Unique)){
   $path=$eligible[$id]
   # Only these three previously validated regular files belong to this protocol.
   foreach($name in @('bastion_worker.ps1','bastion_bootstrap.ps1','bundle.json')){[IO.File]::Delete((Join-Path $path $name))}
   [IO.Directory]::Delete($path);$removed+=,$id
  }
 }
 @{schema='egw.agents-prune.v1';applied=[bool]$apply;bundles=@($rows);removed=@($removed)}|ConvertTo-Json -Depth 5 -Compress
}finally{if($lease){$lease.Dispose()}}
'''
    for token,value in [('ROOT',ps_quote(root)),('KEEP',','.join(ps_quote(v) for v in sorted({current,*keep}))),
                        ('REMOVE',','.join(ps_quote(v) for v in sorted(set(remove)))),('APPLY','$true' if apply else '$false'),('HOURS',str(min_age_hours))]:
        script=script.replace(token,value)
    if apply:mark_dispatched()
    result=control.exec_powershell(script,timeout_sec=60)
    if result.exit_code:raise RuntimeError('Bundle maintenance failed; no worker was stopped automatically. '+result.stderr[-1000:])
    data=json.loads(result.stdout)
    if data.get('schema')!='egw.agents-prune.v1':raise ValueError('Invalid bundle maintenance response')
    return data
