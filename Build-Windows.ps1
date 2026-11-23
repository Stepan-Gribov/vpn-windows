param([switch]$RestoreDependencies, [switch]$PrivateBuild, [string]$PanelBootstrap, [string]$VKAppConfig)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$root = $PSScriptRoot
if (!$PrivateBuild -and ($PanelBootstrap -or $VKAppConfig)) {
    throw 'Local configuration requires -PrivateBuild.'
}
$vkSource = 'native\KindlyTurn\Source\pkg\clientcore\vk-apps.json'
if (!$PrivateBuild -and (Get-Content -LiteralPath (Join-Path $root $vkSource) -Raw).Trim() -cne '[]') {
    throw 'Public builds require an empty bundled VK application list.'
}
if (!$PrivateBuild) {
    $env:GOENV = 'off'
    $env:GOFLAGS = ''
}
$dist = Join-Path $root 'dist'
if ($PrivateBuild) { $dist = Join-Path $dist 'private' }
. (Join-Path $root 'tools\Build-Metadata.ps1')
$project = Read-ProjectMetadata $root
$engine = Join-Path $root 'native\CombinedXray'
$env:GIT_CEILING_DIRECTORIES = Join-Path $root '.build'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path $compiler)) { throw 'Install .NET Framework 4.8, then retry.' }
foreach ($tool in @('go','git')) {
    if (!(Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Required build tool: $tool. See BUILD-RU.md." }
}
$env:GOTOOLCHAIN = 'local'
$env:CGO_ENABLED = '0'; $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
if ($RestoreDependencies) { $env:GOPROXY = 'https://proxy.golang.org,direct'; $env:GOSUMDB = 'sum.golang.org' }
else { $env:GOPROXY = 'off'; $env:GOSUMDB = 'off' }
$cache = (& go env GOMODCACHE).Trim()
if ($LASTEXITCODE) { throw 'Cannot locate Go cache' }
$modules = @(
    @('github.com/xtls/xray-core','github.com/autorepobot/xray-core@v0.0.0-20260704054728-50c452881eb9','xray','XrayCoreIOS.patch'),
    @('github.com/amnezia-vpn/amneziawg-go/v3','github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828','awg','AmneziaWGTimers.patch')
)
foreach ($m in $modules) {
    $target = Join-Path $root ('.build\'+$m[2])
    if (!(Test-Path $target)) {
        $source = Join-Path $cache $m[1]
        if (!(Test-Path $source) -and $RestoreDependencies) {
            & go -C $engine mod download $m[1]
            if ($LASTEXITCODE) { throw "Cannot restore $($m[1])" }
        }
        if (!(Test-Path $source)) { throw "Module absent: $($m[1]). Use -RestoreDependencies once, or the full source archive." }
        New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -Recurse
    }
    Get-ChildItem -LiteralPath $target -Recurse -Force | ForEach-Object { $_.Attributes = $_.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly) }
    $patch = Join-Path $engine $m[3]
    $ErrorActionPreference = 'Continue'
    & git -C $target apply --check $patch 2>$null
    $patchCheck = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($patchCheck -eq 0) {
        & git -C $target apply $patch
        if ($LASTEXITCODE) { throw 'Cannot apply native patch' }
    } else {
        & git -C $target apply --reverse --check $patch
        if ($LASTEXITCODE) { throw 'Unexpected or partially patched upstream source' }
    }
    & go -C $engine mod edit ("-replace="+$m[0]+"=../../.build/"+$m[2])
    if ($LASTEXITCODE) { throw 'Cannot configure local native source' }
}
Copy-Item (Join-Path $root 'patches\desktop_physical_windows.go') (Join-Path $root '.build\xray\proxy\tun\desktop_physical_windows.go') -Force
Copy-Item (Join-Path $root 'patches\desktop_packet.go') (Join-Path $root '.build\xray\proxy\tun\desktop_packet.go') -Force
Copy-Item (Join-Path $root 'patches\desktop_release_windows.go') (Join-Path $root '.build\xray\proxy\tun\desktop_release_windows.go') -Force
$xraySource = Join-Path $root '.build\xray'
foreach ($patchName in @('WindowsDesktop.patch','WindowsReleaseRoutes.patch')) {
    $patch = Join-Path $engine $patchName
    $ErrorActionPreference = 'Continue'
    & git -C $xraySource apply --check $patch 2>$null
    $check = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($check -eq 0) { & git -C $xraySource apply $patch }
    else { & git -C $xraySource apply --reverse --check $patch }
    if ($LASTEXITCODE) { throw "Unexpected desktop patch state: $patchName" }
}
if ($RestoreDependencies) {
    & go -C $engine mod download
    if ($LASTEXITCODE) { throw 'Pinned dependency restore failed' }
}
$metadata = New-BuildMetadata $project $root $compiler
$metadata.distribution = if ($PrivateBuild) { 'private' } else { 'public' }
$metadataDir = Join-Path $root '.build\build-tools'
New-Item -ItemType Directory -Force $metadataDir | Out-Null
$overrides = @{}
if ($PrivateBuild) {
    $localPanel = Join-Path $root '.private\panel-bootstrap.json'
    $localVK = Join-Path $root '.private\vk-apps.json'
    if (!$PanelBootstrap -and (Test-Path -LiteralPath $localPanel)) { $PanelBootstrap = $localPanel }
    if (!$VKAppConfig -and (Test-Path -LiteralPath $localVK)) { $VKAppConfig = $localVK }
}
foreach ($entry in @(
    @{Input=$PanelBootstrap; Source='native\CombinedXray\internal\desktop\bootstrap.json'},
    @{Input=$VKAppConfig; Source=$vkSource}
)) {
    if (!$entry.Input) { continue }
    $file = Get-Item -LiteralPath $entry.Input
    if ($file.PSIsContainer -or $file.Length -lt 2 -or $file.Length -gt 32768) { throw 'Invalid local configuration size.' }
    $overrides[(Join-Path $root $entry.Source)] = $file.FullName
}
$buildOptions = @()
if ($overrides.Count) {
    $overlay = Join-Path $metadataDir 'source-overlay.json'
    Write-BuildJson $overlay @{Replace=$overrides}
    $buildOptions += "-overlay=$overlay"
}
$assemblyInfo = Join-Path $metadataDir 'AssemblyInfo.cs'
Write-BuildAssemblyInfo $assemblyInfo $metadata
$dest = Join-Path $dist ('TnDtun-'+$project.version+'-'+$project.target)
New-Item -ItemType Directory -Force $dest | Out-Null
$linker = '-s -w -X kindlyvpn/native/internal/desktop.Version='+$metadata.version+' -X kindlyvpn/native/internal/desktop.Build='+$metadata.buildId
Write-Host ('Building TnDtun '+$metadata.version+' / '+$metadata.buildId)
& go -C $engine build -mod=readonly @buildOptions -trimpath ("-ldflags="+$linker) -o (Join-Path $dest 'TnDtun.Engine.exe') ./cmd/tndtun-engine
if ($LASTEXITCODE) { throw 'Engine build failed' }
$argsCSC = @('/nologo','/target:winexe','/platform:x64','/optimize+',('/out:'+(Join-Path $dest 'TnDtun.exe')),('/win32manifest:'+(Join-Path $root 'app\app.manifest')),('/win32icon:'+(Join-Path $root 'resources\TnDtun.ico')),'/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll','/reference:System.Web.dll',(Join-Path $root 'app\TnDtun.cs'),$assemblyInfo)
& $compiler @argsCSC
if ($LASTEXITCODE) { throw 'UI build failed' }
foreach ($file in @('wintun.dll','WINTUN-LICENSE.txt','TnDtun.ico')) { Copy-Item (Join-Path $root ('resources\'+$file)) $dest -Force }
if ((Get-FileHash (Join-Path $dest 'wintun.dll') -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce') { throw 'Unexpected Wintun DLL' }
foreach ($file in @('LICENSE','START-RU.md','Install-Shortcuts.ps1','Remove-Shortcuts.ps1')) { Copy-Item (Join-Path $root $file) $dest -Force }
Copy-Item (Join-Path $root 'validation\SUMMARY.md') (Join-Path $dest 'VALIDATION.md') -Force
Copy-Item (Join-Path $root 'licenses') $dest -Recurse -Force
Write-BuildJson (Join-Path $dest 'BUILD-INFO.json') $metadata
$zip = $dest+'.zip'
Compress-Archive -Path $dest -DestinationPath $zip -Force
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$metadata.artifact = $zip
$metadata.sha256 = $zipHash
$metadata.bytes = (Get-Item -LiteralPath $zip).Length
Write-BuildJson (Join-Path $dist 'last-build.json') $metadata
[IO.File]::WriteAllText(($zip+'.sha256'), $zipHash+'  '+[IO.Path]::GetFileName($zip)+[Environment]::NewLine)
Write-Host ('SHA256: '+$zipHash)
Write-Host "Ready: $zip"
