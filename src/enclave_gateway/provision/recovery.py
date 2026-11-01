"""Finish an interrupted prepared generation without reinstalling guest tools."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path


def recover_machine(agent, architecture: str):
    if architecture not in ('arm64', 'x86_64'):
        raise ValueError('Recovery requires an explicit guest architecture')
    source = Path(__file__).parents[1] / 'agents' / 'machine_prepare.ps1'
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    # The installed script is privileged code: never execute a path merely
    # because a guest journal claims that it is an approved generation.
    script = r"""$ErrorActionPreference='Stop'
$mutex=New-Object Threading.Mutex($false,'Global\EnclaveGatewayMachineRecovery')
$acquired=$false
try{
 try{$acquired=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$acquired=$true}
 if(-not $acquired){throw 'Another machine recovery is running'}
$root='C:\EnclaveGateway';$entry=Join-Path $root 'machine_prepare.ps1'
foreach($p in @($root,$entry,(Join-Path $root 'machine-prepared.json'),(Join-Path $root 'provision-media.json'))){
 if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Recovery path is a reparse point'}
}
if((Get-FileHash -LiteralPath $entry -Algorithm SHA256).Hash.ToLowerInvariant() -ne '__HASH__'){throw 'Installed recovery source does not match controller'}
$active=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -match '(?i)-File\s+"?C:\\EnclaveGateway\\machine_prepare\.ps1(?:"|\s|$)'})
if($active.Count){throw 'Machine preparation is still running'}
$setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
if($setup.SystemSetupInProgress -or $setup.OOBEInProgress -or $setup.SetupType){throw 'Windows Setup is incomplete'}
& $entry -Architecture __ARCH__ -CompleteSetup -RecoverOnly 6>$null | Out-Null
Get-Content (Join-Path $root 'provision-machine.json') -Raw -Encoding UTF8
}finally{if($acquired){$mutex.ReleaseMutex()};$mutex.Dispose()}
""".replace('__HASH__', digest).replace('__ARCH__', architecture)
    result = agent.exec_powershell(script, timeout_sec=120)
    if result.exit_code:
        raise RuntimeError('Prepared generation recovery failed')
    value = json.loads(result.stdout)
    if (value.get('revision') != 2 or value.get('status') != 'machine_ready'
            or value.get('architecture') != architecture):
        raise RuntimeError('Invalid recovered readiness record')
    return value
