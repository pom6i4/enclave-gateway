param(
    [Parameter(Mandatory=$true)][string]$Worker,
    [Parameter(Mandatory=$true)][string]$Workspace,
    [string]$Runtime='',
    [switch]$DisposableLab
)
# This fixture creates temporary trust only in an explicitly disposable Windows VM.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if(-not $DisposableLab -or $env:OS -ne 'Windows_NT'){throw 'An explicitly disposable Windows lab is required'}
if([IO.Directory]::Exists($Workspace)){throw 'Use a new evidence directory; previous attempts must be retained'}
[void][IO.Directory]::CreateDirectory($Workspace)
$checks=New-Object 'Collections.Generic.List[object]'
$certificate=$null;$script:workerProcess=$null;$result=@{revision=1;status='running';scope='windows-local-spool';rdp_tested=$false;kes_tested=$false;checks=$checks}
function Save-Result { [IO.File]::WriteAllText((Join-Path $Workspace 'result.json'),($result|ConvertTo-Json -Depth 8)) }
function Check([string]$Name,[scriptblock]$Action){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try{& $Action;$checks.Add(@{name=$Name;status='passed';wall_ms=$watch.ElapsedMilliseconds})}
    catch{$checks.Add(@{name=$Name;status='failed';wall_ms=$watch.ElapsedMilliseconds;error=$_.Exception.ToString()});Save-Result;throw}
    Save-Result
}
function Start-Worker([string]$Path,[string]$Hash,[string]$Name){
    $out=Join-Path $Workspace ($Name+'.stdout.log');$err=Join-Path $Workspace ($Name+'.stderr.log')
    $arguments=@('-NoProfile','-NonInteractive','-File',('"'+$Path+'"'),'-SpoolDir',('"'+$spool+'"'),'-PolicyPath',('"'+$policyPath+'"'),'-PolicySha256',$Hash,'-TrustedSignerThumbprints',$certificate.Thumbprint,'-LeaseSeconds','60')
    $p=Start-Process -FilePath ($env:SystemRoot+'\System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    [void]$p.Handle
    return $p
}
function Expect-Rejection([string]$Path,[string]$Hash,[string]$Name,[string]$Reason=''){
    $p=Start-Worker $Path $Hash $Name
    try{if(-not $p.WaitForExit(15000)){throw 'Rejected worker did not exit within 15 seconds'};if($p.ExitCode -eq 0){throw 'Untrusted worker unexpectedly started'};if($Reason -and [IO.File]::ReadAllText((Join-Path $Workspace ($Name+'.stderr.log'))) -notmatch $Reason){throw 'Rejection did not establish the expected cause'}}
    finally{if(-not $p.HasExited){$p.Kill();[void]$p.WaitForExit(5000)};$p.Dispose()}
}
function Credential-Request([hashtable]$Value){
    $p=New-Object Diagnostics.Process;$start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Runtime;$start.Arguments='credentials';$start.UseShellExecute=$false
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $p.StartInfo=$start
    try{
        [void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
        $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Compress));$p.StandardInput.BaseStream.Write($bytes,0,$bytes.Length);$p.StandardInput.Close()
        if(-not $p.WaitForExit(15000)){throw 'Native credential request exceeded 15 seconds'}
        return @{code=$p.ExitCode;stdout=$out.GetAwaiter().GetResult()}
    }finally{if(-not $p.HasExited){$p.Kill();[void]$p.WaitForExit(5000)};$p.Dispose()}
}
function Request([string]$Operation,[hashtable]$Fields=@{}){
    $id='tx_'+[Guid]::NewGuid().ToString('N');$value=@{tx_id=$id;op=$Operation;timeout_ms=10000;expires_unix_ms=([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+15000)}
    foreach($key in $Fields.Keys){$value[$key]=$Fields[$key]}
    $path=Join-Path $spool ('req_'+$id+'.json');$temporary=$path+'.tmp'
    [IO.File]::WriteAllText($temporary,($value|ConvertTo-Json -Depth 5 -Compress));[IO.File]::Move($temporary,$path)
    $reply=Join-Path $spool ('res_'+$id+'.json');$watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists($reply)){if($watch.ElapsedMilliseconds -gt 15000 -or $script:workerProcess.HasExited){throw 'Worker response deadline expired'};Start-Sleep -Milliseconds 20}
    $answer=[IO.File]::ReadAllText($reply)|ConvertFrom-Json
    if($answer.tx_id -cne $id){throw 'Response identity mismatch'}
    return $answer
}
try{
    $result.platform=@{os=[Environment]::OSVersion.VersionString;machine_arch=[Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE','Machine');process_arch=$env:PROCESSOR_ARCHITECTURE;ps=$PSVersionTable.PSVersion.ToString();execution_policy=[string](Get-ExecutionPolicy)}
    $result.source_sha256=(Get-FileHash -LiteralPath $Worker -Algorithm SHA256).Hash.ToLowerInvariant()
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $spool=Join-Path $Workspace 'spool';[void][IO.Directory]::CreateDirectory($spool)
    $policyPath=Join-Path $Workspace 'policy.json'
    $policy=@{revision=1;owner_sid=$sid;targets=@{app01=@{host='10.0.20.11';port=22;user='fixture';key_path='C:\EGWEndpointFixture\unused-key';known_hosts_path='C:\EGWEndpointFixture\unused-known-hosts';allow_exec=$false;allow_transfer=$false;allow_sudo=$false}}}
    [IO.File]::WriteAllText($policyPath,($policy|ConvertTo-Json -Depth 5 -Compress))
    $acl=New-Object Security.AccessControl.FileSecurity
    $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($admins);$acl.SetAccessRuleProtection($true,$false)
    foreach($principal in @($admins,$system)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($principal,'FullControl','Allow')))}
    [IO.File]::SetAccessControl($policyPath,$acl)
    $hash=(Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $certificate=New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=EGW Disposable Endpoint Fixture '+[Guid]::NewGuid().ToString('N')) -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddDays(1)
    foreach($name in @('Root','TrustedPublisher')){
        $store=New-Object Security.Cryptography.X509Certificates.X509Store($name,'LocalMachine')
        try{$store.Open('ReadWrite');$store.Add($certificate)}finally{$store.Close()}
    }
    $signed=Join-Path $Workspace 'worker.ps1';[IO.File]::WriteAllBytes($signed,[IO.File]::ReadAllBytes($Worker))
    Check 'authenticode-synthetic-trust' {
        $signature=Set-AuthenticodeSignature -LiteralPath $signed -Certificate $certificate -HashAlgorithm SHA256
        if($signature.Status -ne 'Valid'){throw 'Synthetic signature did not validate'}
    }
    Check 'reject-unsigned-worker' {Expect-Rejection $Worker $hash 'unsigned'}
    Check 'reject-policy-hash' {Expect-Rejection $signed ('0'*64) 'wrong-policy-hash' 'Approved worker policy hash mismatch'}
    Check 'reject-user-writable-policy' {
        $unsafe=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),'Write','Allow')
        $acl.AddAccessRule($unsafe);[IO.File]::SetAccessControl($policyPath,$acl)
        try{Expect-Rejection $signed $hash 'writable-policy' 'Policy must not be writable by an unapproved principal'}finally{$acl.RemoveAccessRuleSpecific($unsafe);[IO.File]::SetAccessControl($policyPath,$acl)}
    }
    Check 'signed-worker-start-with-system-openssh' {
        $script:workerProcess=Start-Worker $signed $hash 'valid'
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while(-not [IO.File]::Exists((Join-Path $spool 'worker_state.json'))){if($script:workerProcess.HasExited -or $watch.ElapsedMilliseconds -gt 15000){throw 'Signed worker did not become ready within 15 seconds'};Start-Sleep -Milliseconds 20}
    }
    Check 'fixed-ping' {if((Request 'ping').exit_code -ne 0){throw 'Ping rejected'}}
    Check 'fresh-attestation-binds-policy' {
        $nonce=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N');$reply=Request 'attest' @{attestation_nonce=$nonce}
        $e=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($reply.stdout_b64))|ConvertFrom-Json
        if($reply.exit_code -ne 0 -or $e.nonce -cne $nonce -or $e.policy_sha256 -cne $hash -or $e.signature_status -ne 'Valid'){throw 'Attestation was not bound to the approved policy'}
    }
    Check 'reject-arbitrary-powershell' {if((Request 'exec' @{command='Write-Output MUST_NOT_EXECUTE'}).exit_code -eq 0){throw 'Dynamic PowerShell accepted'}}
    Check 'reject-tcp-mux' {if((Request 'mux_open').exit_code -eq 0){throw 'Raw socket operation accepted'}}
    Check 'reject-unapproved-target' {if((Request 'ssh_exec' @{target='unapproved';expected_host='10.0.20.11';expected_port=22;expected_user='fixture';command='true'}).exit_code -eq 0){throw 'Unapproved target accepted'}}
    Check 'fixed-clean-preserves-journal' {
        if((Request 'clean').exit_code -ne 0){throw 'Clean rejected'}
        if(-not [IO.Directory]::Exists((Join-Path $spool '.structured-transactions'))){throw 'Durable journal lost'}
    }
    Check 'acknowledged-stop' {
        $reply=Request 'stop';$stopped=$script:workerProcess.WaitForExit(15000);$script:workerProcess.Refresh()
        $result.stop=@{response_code=$reply.exit_code;exited=$stopped;process_code=$script:workerProcess.ExitCode}
        if($reply.exit_code -ne 0 -or -not $stopped -or $script:workerProcess.ExitCode -ne 0){throw 'Worker stop failed'}
    }
    if($Runtime){
        Check 'native-credentials-exact-current-sid' {
            # The randomly named credential is the only entry read or deleted.
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EGWFixtureCredential {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct C {public uint Flags,Type;public string Target,Comment;public System.Runtime.InteropServices.ComTypes.FILETIME Written;public uint Size;public IntPtr Blob;public uint Persist,Count;public IntPtr Attributes;public string Alias,User;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool CredReadW(string target,uint type,uint flags,out IntPtr credential);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool CredDeleteW(string target,uint type,uint flags);
 [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr credential);
 public static bool Matches(string target,string user,string password) {IntPtr p;if(!CredReadW(target,1,0,out p))return false;try{C c=(C)Marshal.PtrToStructure(p,typeof(C));return c.User==user && c.Size==password.Length*2 && Marshal.PtrToStringUni(c.Blob,(int)c.Size/2)==password;}finally{CredFree(p);}}
}
'@
            $target='TERMSRV/egw-fixture-'+[Guid]::NewGuid().ToString('N')+'.enclave.internal';$password='fixture-данные-'+[Guid]::NewGuid().ToString('N')
            try{
                $reply=Credential-Request @{expected_sid=$sid;target=$target;username='fixture';password=$password}
                if($reply.code -ne 0 -or ($reply.stdout|ConvertFrom-Json).credential_updated -ne $true -or -not [EGWFixtureCredential]::Matches($target,'fixture',$password)){throw 'Credential did not match the exact SID payload'}
                $denied=Credential-Request @{expected_sid='S-1-5-21-999-999-999-999';target=$target;username='fixture';password='must-not-replace'}
                if($denied.code -eq 0 -or -not [EGWFixtureCredential]::Matches($target,'fixture',$password)){throw 'Wrong SID was accepted or modified the credential'}
            }finally{[void][EGWFixtureCredential]::CredDeleteW($target,1,0)}
        }
    }
    $result.status='passed'
}catch{$result.status='failed';$result.error=$_.Exception.ToString();throw}
finally{
    if($script:workerProcess){try{if(-not $script:workerProcess.HasExited){$script:workerProcess.Kill();[void]$script:workerProcess.WaitForExit(5000)}}finally{$script:workerProcess.Dispose()}}
    if($certificate){
        foreach($store in @('My','Root','TrustedPublisher')){
            $path='Cert:\LocalMachine\'+$store+'\'+$certificate.Thumbprint
            if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}
        }
        foreach($store in @('My','Root','TrustedPublisher')){if(Test-Path -LiteralPath ('Cert:\LocalMachine\'+$store+'\'+$certificate.Thumbprint)){throw 'Synthetic certificate cleanup failed'}}
        $certificate.Dispose();$result.synthetic_trust_removed=$true
    }
    Save-Result
}
$result|ConvertTo-Json -Depth 8 -Compress
