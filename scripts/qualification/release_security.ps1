param([Parameter(Mandatory=$true)][string]$PackageV1,[Parameter(Mandatory=$true)][string]$PackageV2,
      [Parameter(Mandatory=$true)][string[]]$TrustedThumbprints,[Parameter(Mandatory=$true)][string]$Workspace)
$ErrorActionPreference='Stop'
if(Test-Path $Workspace){throw 'Use a new private release-policy workspace'}
[void][IO.Directory]::CreateDirectory($Workspace)
$installed=Join-Path $Workspace 'installed';$installer=Join-Path $PackageV2 'install_windows.ps1';$verifier=Join-Path $PackageV2 'verify_windows.ps1';$checks=@()
function Install([string]$Package,[string]$Action='Install'){
 $args=@{InstallDir=$installed;TrustedThumbprints=$TrustedThumbprints;Action=$Action}
 if($Package){$args.PackageDir=$Package};return (& $installer @args|Out-String|ConvertFrom-Json)
}
function Reject([scriptblock]$Code){$denied=$false;try{& $Code|Out-Null}catch{$denied=$true};if(-not $denied){throw 'Unsafe release was accepted'}}
function Sign-Metadata([string]$Directory,$Metadata){
 Add-Type -AssemblyName System.Security
 $bytes=[Text.Encoding]::UTF8.GetBytes(($Metadata|ConvertTo-Json -Depth 8 -Compress))
 [IO.File]::WriteAllBytes((Join-Path $Directory 'signature-manifest.json'),$bytes)
 $cms=New-Object Security.Cryptography.Pkcs.SignedCms((New-Object Security.Cryptography.Pkcs.ContentInfo(,$bytes)),$true)
 $certificate=Get-Item "Cert:\LocalMachine\My\$($TrustedThumbprints[0])"
 $signer=New-Object Security.Cryptography.Pkcs.CmsSigner($certificate)
 $signer.DigestAlgorithm=New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1');$cms.ComputeSignature($signer)
 [IO.File]::WriteAllBytes((Join-Path $Directory 'signature-manifest.p7s'),$cms.Encode())
}
try{
 $one=Install $PackageV1;$two=Install $PackageV2
 if($one.release_id -eq $two.release_id){throw 'Distinct signed releases required'}
 $checks+='signed-upgrade'
 Reject {Install $PackageV1};$checks+='downgrade-install-rejected'
 $selection=Get-Content "$installed\installation.json" -Raw|ConvertFrom-Json
 $high=$selection.max_sequence
 $rollback=Install '' 'Rollback'
 if($rollback.release_id -ne $one.release_id){throw 'Verified explicit rollback failed'}
 $selection=Get-Content "$installed\installation.json" -Raw|ConvertFrom-Json
 if($selection.max_sequence -ne $high -or $selection.highest_release -ne $two.release_id){throw 'Rollback lowered release high-water mark'}
 $checks+='explicit-rollback-retains-high-water'
 [void](Install $PackageV2);$checks+='approved-upgrade-after-rollback'
 $reused=Join-Path $Workspace 'sequence-reuse';Copy-Item $PackageV2 $reused -Recurse
 $metadata=Get-Content "$reused\signature-manifest.json" -Raw|ConvertFrom-Json
 $metadata|Add-Member -NotePropertyName fixture -NotePropertyValue 'different-release-at-same-sequence'
 Sign-Metadata $reused $metadata
 & $verifier -PackageDir $reused -TrustedThumbprints $TrustedThumbprints|Out-Null
 Reject {Install $reused};$checks+='validly-signed-sequence-reuse-rejected'
 $metadata.channel='alternate';$metadata.sequence++
 Sign-Metadata $reused $metadata
 & $verifier -PackageDir $reused -TrustedThumbprints $TrustedThumbprints|Out-Null
 Reject {Install $reused};$checks+='validly-signed-channel-change-rejected'
 $metadata.channel='Stable';Sign-Metadata $reused $metadata
 Reject {& $verifier -PackageDir $reused -TrustedThumbprints $TrustedThumbprints};$checks+='validly-signed-noncanonical-channel-rejected'
 $mutated=Join-Path $Workspace 'metadata-tamper';Copy-Item $PackageV2 $mutated -Recurse
 $manifest=Get-Content "$mutated\signature-manifest.json" -Raw|ConvertFrom-Json;$manifest.sequence++
 [IO.File]::WriteAllText("$mutated\signature-manifest.json",($manifest|ConvertTo-Json -Depth 8))
 Reject {& $verifier -PackageDir $mutated -TrustedThumbprints $TrustedThumbprints};$checks+='metadata-only-tamper-rejected'
 Copy-Item "$PackageV2\signature-manifest.json" "$mutated\signature-manifest.json" -Force
 Copy-Item "$PackageV1\signature-manifest.p7s" "$mutated\signature-manifest.p7s" -Force
 Reject {& $verifier -PackageDir $mutated -TrustedThumbprints $TrustedThumbprints};$checks+='cross-release-signature-rejected'
 Remove-Item "$mutated\signature-manifest.p7s"
 Reject {& $verifier -PackageDir $mutated -TrustedThumbprints $TrustedThumbprints};$checks+='missing-metadata-signature-rejected'
 Reject {& $verifier -PackageDir $PackageV2 -TrustedThumbprints @('0000000000000000000000000000000000000000')};$checks+='untrusted-metadata-signer-rejected'
 $status=Install '' 'Status';if($status.release_id -ne $two.release_id){throw 'Rejected release changed selection'}
 $checks+='rejection-preserves-current'
 $report=@{status='passed';checks=$checks;scope='lab-signed-metadata-and-downgrade-policy';production_signing='not_qualified'}
}catch{$report=@{status='failed';checks=$checks;error_type=$_.Exception.GetType().FullName};throw}
finally{$report|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Workspace 'result.json') -Encoding UTF8}
$report|ConvertTo-Json -Depth 5
