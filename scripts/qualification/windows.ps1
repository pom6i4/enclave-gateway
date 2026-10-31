param([Parameter(Mandatory=$true)][string[]]$PythonExecutables, [string]$OutputDir='./build/qualification-windows', [int]$Transactions=10000)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This entry point records Windows qualification only on Windows' }
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$powerShell=(Get-Process -Id $PID).Path
$arguments=@((Join-Path $root 'scripts/qualify.py'),'--output-dir',$OutputDir,'--powershell',$powerShell,'--transactions',[string]$Transactions,'--timeout','1200')
foreach ($python in $PythonExecutables) { $arguments+=@('--python',$python) }
& $PythonExecutables[0] @arguments
if ($LASTEXITCODE -ne 0) { throw 'Local Windows qualification failed; inspect the retained logs' }
