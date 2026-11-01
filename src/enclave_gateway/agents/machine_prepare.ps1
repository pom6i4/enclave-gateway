param([ValidateSet('arm64','x86_64')][string]$Architecture,[switch]$CompleteSetup,
      [ValidateSet('StartupTask','SetupComplete')][string]$CompletionMode='StartupTask',[switch]$WaitForSetup)
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
function Complete-Preparation([string]$QgaMode,[string]$Verification,[string]$ApprovedHash){
    $removed=$false
    if($CompletionMode -eq 'StartupTask'){
        Set-MachinePhase 'completion-task-cleanup'
        $name='EnclaveGatewayMachinePreparation'
        $existing=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if($existing){
            $exe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            $expected="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$install\machine_prepare.ps1`" -Architecture $Architecture -CompleteSetup -WaitForSetup"
            if(@($existing.Actions).Count -ne 1 -or $existing.Actions[0].Execute -ne $exe -or $existing.Actions[0].Arguments -ne $expected -or $existing.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Existing machine preparation task requires explicit integration'}
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Machine preparation task was not removed'}
        }
        $removed=$true
    }
    Remove-Item -LiteralPath (Join-Path $install 'machine-prepare-failed.json') -ErrorAction SilentlyContinue
    Set-MachinePhase 'complete'
    # Publish readiness last. A controller may power down as soon as it sees
    # this record; neither task deletion nor installer work may follow it.
    @{revision=2;status='machine_ready';architecture=$Architecture;qga_mode=$QgaMode;media_verification=$Verification;approved_sha256=$ApprovedHash;
      completion_mode=$CompletionMode;completion_task_removed=$removed;automatic_logon='not_configured';provider='not_installed'}|ConvertTo-Json|Set-Content (Join-Path $install 'provision-machine.json') -Encoding UTF8
}
try{
    if($WaitForSetup){
        if(-not $CompleteSetup){throw 'Setup wait requires completion mode'}
        $until=[DateTime]::UtcNow.AddHours(2)
        do{
            $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
            if(-not ($setup.SystemSetupInProgress -or $setup.OOBEInProgress -or $setup.SetupType)){break}
            if([DateTime]::UtcNow -ge $until){throw 'Windows Setup completion deadline expired'}
            Start-Sleep -Seconds 5
        }while($true)
    }
    Set-MachinePhase 'media-policy'
    $approvedHash='';$policy=Join-Path $PSScriptRoot 'provision-media.json'
    if(Test-Path -LiteralPath $policy){
        $approval=Get-Content -LiteralPath $policy -Raw -Encoding UTF8|ConvertFrom-Json
        if($approval.revision -ne 1){throw 'Unsupported provision media policy'}
        $approvedHash=[string]$approval.guest_agent_sha256
        if($approval.completion_mode){
            if($approval.completion_mode -notin @('StartupTask','SetupComplete')){throw 'Invalid completion mode policy'}
            $CompletionMode=[string]$approval.completion_mode
        }
        if($approvedHash -and $approvedHash -notmatch '^[a-f0-9]{64}$'){throw 'Invalid provision media policy'}
    }
    $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
    if(-not $CompleteSetup -and ($setup.SystemSetupInProgress -or $setup.OOBEInProgress)){
        # QGA's VSS COM registration needs the completed OS. Specialize only
        # stages this SYSTEM hook; it never logs a user on or installs MSI.
        Set-MachinePhase 'deferred-until-setup-complete'
        if($CompletionMode -eq 'StartupTask'){
            # This SYSTEM task also runs where OEM media disables SetupComplete.
            # Start now to observe completion in the same boot; startup is the
            # persistent recovery trigger if Windows Setup reboots first.
            $name='EnclaveGatewayMachinePreparation'
            $exe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            $args="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$install\machine_prepare.ps1`" -Architecture $Architecture -CompleteSetup -WaitForSetup"
            $existing=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if($existing -and (@($existing.Actions).Count -ne 1 -or $existing.Actions[0].Execute -ne $exe -or $existing.Actions[0].Arguments -ne $args -or $existing.Principal.UserId -notin @('SYSTEM','S-1-5-18'))){throw 'Existing machine preparation task requires explicit integration'}
            Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $install 'machine_prepare.ps1') -Force
            if(Test-Path -LiteralPath $policy){Copy-Item -LiteralPath $policy -Destination (Join-Path $install 'provision-media.json') -Force}
            $action=New-ScheduledTaskAction -Execute $exe -Argument $args
            $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
            $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 3) -StartWhenAvailable
            Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settings -Force|Out-Null
            Start-ScheduledTask -TaskName $name
            return
        }
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
    # Recover a previously completed generation whose one-time cleanup was
    # interrupted. Missing removable media must not trigger another MSI run.
    $readyFile=Join-Path $install 'provision-machine.json'
    if($CompleteSetup -and $CompletionMode -eq 'StartupTask' -and (Test-Path -LiteralPath $readyFile)){
        $prior=Get-Content -LiteralPath $readyFile -Raw -Encoding UTF8|ConvertFrom-Json
        if($prior.revision -in @(1,2) -and $prior.status -eq 'machine_ready' -and $prior.architecture -eq $Architecture -and
           [string]$prior.approved_sha256 -eq $approvedHash -and $prior.qga_mode -in @('msi-native','x64-emulated-vss-not-qualified') -and
           $prior.media_verification -in @('authenticode','sha256-pin','sha256-and-authenticode')){
            $service=Get-Service qemu-ga -ErrorAction Stop
            if($service.Status -eq 'Running'){
                Complete-Preparation $prior.qga_mode $prior.media_verification $approvedHash
                return
            }
        }
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
    Complete-Preparation $mode $mediaVerification $approvedHash
}catch{
    try{@{revision=1;status='failed';phase=$phase;msi_exit_code=$msiExit;error_type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult}|ConvertTo-Json|Set-Content (Join-Path $install 'machine-prepare-failed.json') -Encoding UTF8}catch{}
    throw
}
