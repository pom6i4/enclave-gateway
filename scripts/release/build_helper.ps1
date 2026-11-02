param(
    [ValidateSet('win-x64','win-arm64')][string]$Runtime = 'win-x64',
    [string]$OutputDir = './build/askpass',
    [string]$Dotnet = 'dotnet',
    [ValidateSet('askpass','runtime')][string]$Component='askpass',
    [string]$SdkVersion='',
    [string]$RuntimeVersion=''
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$output=[IO.Path]::GetFullPath($(if([IO.Path]::IsPathRooted($OutputDir)){$OutputDir}else{Join-Path (Get-Location).Path $OutputDir}))
$dotnetCommand=(Get-Command $Dotnet -CommandType Application -ErrorAction Stop).Source
if(Test-Path -LiteralPath $output){throw 'Use a new helper build output directory'}
[void][IO.Directory]::CreateDirectory($output)
$work=Join-Path ([IO.Path]::GetTempPath()) ('egw-build-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
if($env:OS -ne 'Windows_NT'){& chmod 700 $work;if($LASTEXITCODE){throw 'Private build workspace failed'}}
$report=@{status='running';runtime=$Runtime;component=$Component;signature='unsigned';qualified_windows=$false;source_sha256=@{}}
try{
 $sdk=(& $dotnetCommand --version|Out-String).Trim()
 if($LASTEXITCODE -or ($SdkVersion -and $sdk -ne $SdkVersion)){throw 'SDK version mismatch'}
 $report.sdk=$sdk
 @{sdk=@{version=$sdk;rollForward='disable'}}|ConvertTo-Json|Set-Content (Join-Path $work 'global.json') -Encoding UTF8
 foreach($name in @('Directory.Build.props','Directory.Build.targets')){[IO.File]::WriteAllText((Join-Path $work $name),'<Project />')}
 $nuget=Join-Path $work 'NuGet.Config'
 [IO.File]::WriteAllText($nuget,'<configuration><packageSources><clear/><add key="public" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>')
 foreach($file in @(Get-ChildItem (Join-Path $root "native/$Component") -File|Where-Object {$_.Extension -in @('.cs','.csproj')})){
  if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Build source links rejected'}
  Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $work $file.Name)
  $report.source_sha256[$file.Name]=(Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
 }
 $project=Join-Path $work $(if($Component -eq 'runtime'){'EnclaveRuntime.csproj'}else{'EnclaveAskpass.csproj'})
 $arguments=@('publish',$project,'-c','Release','-r',$Runtime,'--self-contained','true','-p:PublishSingleFile=true','-p:DebugType=none','-p:ContinuousIntegrationBuild=true',"-p:PathMap=$work=/_/src","-p:RestoreConfigFile=$nuget",'-o',$output)
 if($RuntimeVersion){if($RuntimeVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$'){throw 'Exact runtime patch required'};$arguments+="-p:RuntimeFrameworkVersion=$RuntimeVersion";$report.runtime_version=$RuntimeVersion}
 Push-Location -LiteralPath $work
 try{& $dotnetCommand @arguments 2>&1|Tee-Object -FilePath (Join-Path $output 'build.log')}finally{Pop-Location}
 if($LASTEXITCODE){throw 'Isolated helper build failed'}
 $helper=Join-Path $output ('egw-'+$Component+'.exe')
 if(-not (Test-Path -LiteralPath $helper)){throw 'Helper executable missing'}
 $report.sha256=(Get-FileHash $helper -Algorithm SHA256).Hash.ToLowerInvariant();$report.status='passed'
}catch{$report.status='failed';$report.error_type=$_.Exception.GetType().FullName;throw}
finally{
 $report|ConvertTo-Json -Depth 6|Set-Content (Join-Path $output 'build-manifest.json') -Encoding UTF8
 Remove-Item -LiteralPath $work -Recurse -Force
}
