param([ValidateSet('arm64','x86_64')][string]$Architecture,[switch]$CompleteSetup)
$ErrorActionPreference='Stop'
$install='C:\EnclaveGateway'
[void][IO.Directory]::CreateDirectory($install)
$phase='media-policy';$mediaVerification='';$msiExit=$null
function Set-MachinePhase([string]$Name){
    $script:phase=$Name
    @{revision=1;status='running';phase=$Name}|ConvertTo-Json|Set-Content (Join-Path $install 'machine-progress.json') -Encoding UTF8
    Write-Host "Machine preparation: $Name"
}
function Assert-GuestAgentMedia([string]$Path,[string]$ExpectedHash){
    if($ExpectedHash -and $ExpectedHash -notmatch '^[a-f0-9]{64}$'){throw 'Invalid guest agent approval'}
    if($ExpectedHash -and (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash){throw 'Guest agent media hash mismatch'}
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    try{
        if($signature.Status -eq 'Valid'){return $(if($ExpectedHash){'sha256-and-authenticode'}else{'authenticode'})}
        # An explicit approval binds the exact unsigned installer selected by
        # the controller. It is not publisher authentication or a trust root.
        if($signature.Status -eq 'NotSigned' -and $ExpectedHash){return 'sha256-pin'}
        throw 'Guest agent media needs a valid signature or explicit unsigned-artifact approval'
    }finally{foreach($cert in @($signature.SignerCertificate,$signature.TimeStamperCertificate)){if($cert){$cert.Dispose()}}}
}
function Invoke-AgentMsi([string]$CommandLine){
    $process=New-Object Diagnostics.Process
    try{
        $start=New-Object Diagnostics.ProcessStartInfo
        $start.FileName="$env:SystemRoot\System32\msiexec.exe";$start.Arguments=$CommandLine;$start.UseShellExecute=$false
        $process.StartInfo=$start;[void]$process.Start()
        if(-not $process.WaitForExit(1800000)){$process.Kill();throw 'Guest agent installer deadline expired'}
        return $process.ExitCode
    }finally{$process.Dispose()}
}
try{
    Set-MachinePhase 'media-policy'
    $approvedHash='';$policy=Join-Path $PSScriptRoot 'provision-media.json'
    if(Test-Path -LiteralPath $policy){
        $approval=Get-Content -LiteralPath $policy -Raw -Encoding UTF8|ConvertFrom-Json
        if($approval.revision -ne 1){throw 'Unsupported provision media policy'}
        $approvedHash=[string]$approval.guest_agent_sha256
        if($approvedHash -and $approvedHash -notmatch '^[a-f0-9]{64}$'){throw 'Invalid provision media policy'}
    }
    $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
    if(-not $CompleteSetup -and ($setup.SystemSetupInProgress -or $setup.OOBEInProgress)){
        # QGA's VSS COM registration needs the completed OS. Specialize only
        # stages this SYSTEM hook; it never logs a user on or installs MSI.
        Set-MachinePhase 'deferred-until-setup-complete'
        $scripts=Join-Path $env:SystemRoot 'Setup\Scripts'
        [void][IO.Directory]::CreateDirectory($scripts)
        $hook=Join-Path $scripts 'SetupComplete.cmd'
        $command="@echo off`r`n`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File `"$install\machine_prepare.ps1`" -Architecture $Architecture -CompleteSetup`r`nexit /b %errorlevel%`r`n"
        if((Test-Path -LiteralPath $hook) -and [IO.File]::ReadAllText($hook) -ne $command){throw 'Existing SetupComplete hook requires explicit integration'}
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $install 'machine_prepare.ps1') -Force
        if(Test-Path -LiteralPath $policy){Copy-Item -LiteralPath $policy -Destination (Join-Path $install 'provision-media.json') -Force}
        [IO.File]::WriteAllText($hook,$command,[Text.Encoding]::ASCII)
        return
    }
    $roots=@(Get-PSDrive -PSProvider FileSystem|ForEach-Object {$_.Root})
    $driverArch=if($Architecture -eq 'arm64'){'ARM64'}else{'amd64'}
    Set-MachinePhase 'drivers'
    foreach($root in $roots){
        foreach($driver in @('NetKVM','vioserial','viogpudo','qxldod','viostor')){
            foreach($relative in @("$driver\$driverArch\w11","$driver\w11\$driverArch","Drivers\$driver\$driverArch\w11","Drivers\$driver\w11\$driverArch")){
                $directory=Join-Path $root $relative
                if(Test-Path -LiteralPath $directory){& "$env:SystemRoot\System32\pnputil.exe" /add-driver "$directory\*.inf" /subdirs /install|Out-Null}
            }
        }
    }
    function Find-AgentMsi([string]$Name){
        foreach($root in $roots){foreach($relative in @("guest-agent\$Name",$Name)){
            $path=Join-Path $root $relative
            if(Test-Path -LiteralPath $path -PathType Leaf){return $path}
        }}
        return $null
    }
    $native=Find-AgentMsi $(if($Architecture -eq 'arm64'){'qemu-ga-aarch64.msi'}else{'qemu-ga-x86_64.msi'})
    $mode='msi-native'
    if($native){
        Set-MachinePhase 'native-media-verification'
        $mediaVerification=Assert-GuestAgentMedia $native $approvedHash
        Set-MachinePhase 'native-msi'
        $msiExit=Invoke-AgentMsi "/i `"$native`" /qn /norestart"
        if($msiExit -notin @(0,3010)){$native=$null}
    }
    if(-not $native){
        if($Architecture -ne 'arm64'){throw 'Native QGA installer is unavailable or failed'}
        $fallback=Find-AgentMsi 'qemu-ga-x86_64.msi'
        if(-not $fallback){throw 'Approved x64 QGA fallback media is missing'}
        Set-MachinePhase 'fallback-media-verification'
        $mediaVerification=Assert-GuestAgentMedia $fallback $approvedHash
        $stage=Join-Path $install ('qga-stage-'+[Guid]::NewGuid().ToString('N'))
        try{
            Set-MachinePhase 'fallback-extraction'
            $msiExit=Invoke-AgentMsi "/a `"$fallback`" TARGETDIR=`"$stage`" /qn /norestart"
            if($msiExit -notin @(0,3010)){throw 'QGA extraction failed'}
            $agents=@(Get-ChildItem $stage -Recurse -File -Filter qemu-ga.exe)
            if($agents.Count -ne 1){throw 'Ambiguous QGA administrative image'}
            # The extracted files inherit the approved installer's provenance;
            # staging stays under this machine's administrative directory.
            Copy-Item -LiteralPath $agents[0].Directory.FullName -Destination (Join-Path $install 'qga-files') -Recurse -Force
            $exe=Join-Path (Join-Path $install 'qga-files') 'qemu-ga.exe'
            Set-MachinePhase 'fallback-service-registration'
            & $exe -s install
            if($LASTEXITCODE){throw 'QGA standalone service registration failed'}
            $mode='x64-emulated-vss-not-qualified'
        }finally{if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}}
    }
    Set-MachinePhase 'service-start'
    Set-Service qemu-ga -StartupType Automatic
    Start-Service qemu-ga
    $service=Get-Service qemu-ga
    if($service.Status -ne 'Running'){throw 'QGA service did not start'}
    @{revision=1;status='machine_ready';architecture=$Architecture;qga_mode=$mode;media_verification=$mediaVerification;approved_sha256=$approvedHash;automatic_logon='not_configured';provider='not_installed'}|ConvertTo-Json|Set-Content (Join-Path $install 'provision-machine.json') -Encoding UTF8
    Set-MachinePhase 'complete'
}catch{
    try{@{revision=1;status='failed';phase=$phase;msi_exit_code=$msiExit;error_type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult}|ConvertTo-Json|Set-Content (Join-Path $install 'machine-prepare-failed.json') -Encoding UTF8}catch{}
    throw
}
