param([Parameter(Mandatory=$true)][string[]]$PythonExecutables, [string]$OutputDir='./build/qualification-windows', [int]$Transactions=10000, [string]$RuntimeHelper='', [switch]$AllowUnsignedLab, [string]$TrustedSigner='', [ValidateRange(1,100)][int]$ExecEvery=1)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This entry point records Windows qualification only on Windows' }
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$powerShell=(Get-Process -Id $PID).Path
$arguments=@((Join-Path $root 'scripts/qualify.py'),'--output-dir',$OutputDir,'--powershell',$powerShell,'--transactions',[string]$Transactions,'--exec-every',[string]$ExecEvery,'--timeout','1200')
if ($RuntimeHelper) {$arguments+=@('--runtime',$RuntimeHelper)}
if ($AllowUnsignedLab) {$arguments+='--allow-unsigned-lab'}
if ($TrustedSigner) {$arguments+=@('--trusted-signer',$TrustedSigner)}
foreach ($python in $PythonExecutables) { $arguments+=@('--python',$python) }
& $PythonExecutables[0] @arguments
if ($LASTEXITCODE -ne 0) { throw 'Local Windows qualification failed; inspect the retained logs' }
