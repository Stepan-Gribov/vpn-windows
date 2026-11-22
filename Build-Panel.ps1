param([string]$SmokeOutput)
$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path $compiler)) { throw 'Install .NET Framework 4.8. See BUILD-RU.md.' }
$source = Join-Path $PSScriptRoot 'tools\BuildPanel.cs'
$cache = Join-Path $PSScriptRoot '.build\build-tools'
New-Item -ItemType Directory -Force $cache | Out-Null
$hash = (Get-FileHash $source -Algorithm SHA256).Hash.Substring(0,16)
$exe = Join-Path $cache ("TnDtun.Build.$hash.exe")
if (!(Test-Path $exe)) {
    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 "/out:$exe" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll $source
    if ($LASTEXITCODE) { throw 'Cannot compile the build panel.' }
}
$arguments = '"'+$PSScriptRoot+'"'
if ($SmokeOutput) { $arguments += ' --smoke "'+$SmokeOutput+'"' }
$process = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -Wait
if ($process.ExitCode) { throw "Build panel exited with code $($process.ExitCode)." }
