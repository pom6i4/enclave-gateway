param(
    [ValidateSet('win-x64','win-arm64')][string]$Runtime = 'win-x64',
    [string]$OutputDir = './build/askpass',
    [string]$Dotnet = 'dotnet',
    [ValidateSet('askpass','runtime')][string]$Component='askpass'
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$project=if ($Component -eq 'runtime') { Join-Path $root 'native/runtime/EnclaveRuntime.csproj' } else { Join-Path $root 'native/askpass/EnclaveAskpass.csproj' }
& $Dotnet publish $project -c Release -r $Runtime --self-contained true -p:PublishSingleFile=true -p:DebugType=none -o $OutputDir
if ($LASTEXITCODE -ne 0) { throw 'Credential helper build failed' }
$helper=Join-Path $OutputDir ('egw-'+$Component+'.exe')
if (-not (Test-Path -LiteralPath $helper)) { throw 'Helper executable is missing' }
@{ runtime=$Runtime; sha256=(Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLower(); signature='unsigned'; qualified_windows=$false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDir 'build-manifest.json') -Encoding UTF8
