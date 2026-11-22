function Read-ProjectMetadata([string]$Root) {
    $p = Get-Content -LiteralPath (Join-Path $Root 'project.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($p.name -ne 'TnDtun' -or $p.target -ne 'windows-x64') { throw 'Unsupported project name or target.' }
    if ($p.version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { throw 'Invalid version in project.json.' }
    if ($p.fileVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'fileVersion must have four numeric parts.' }
    foreach ($part in $p.fileVersion.Split('.')) {
        if ([long]$part -gt 65534) { throw 'fileVersion parts must be between 0 and 65534.' }
    }
    return $p
}

function New-BuildMetadata([object]$Project, [string]$Root, [string]$Compiler) {
    $commit = 'unknown'; $dirty = $null
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & git -C $Root rev-parse --is-inside-work-tree 2>$null | Out-Null
    $isGit = $LASTEXITCODE -eq 0
    $ErrorActionPreference = $savedPreference
    if ($isGit) {
        $commit = (& git -C $Root rev-parse HEAD).Trim()
        # Compare normalized content; Windows line-ending conversions alone are not edits.
        & git -C $Root diff --quiet HEAD --
        if ($LASTEXITCODE -gt 1) { throw 'Cannot compare source revision.' }
        $dirty = $LASTEXITCODE -ne 0
        $dirty = $dirty -or [bool](& git -C $Root ls-files --others --exclude-standard)
    }
    $now = [DateTime]::UtcNow
    $revision = if ($commit -eq 'unknown') { 'source' } else { $commit.Substring(0,8) }
    $buildId = $now.ToString('yyyyMMddTHHmmssfffZ')+'-'+$revision
    if ($dirty) { $buildId += '-dirty' }
    return [ordered]@{
        schema = 1; product = $Project.name; version = $Project.version; fileVersion = $Project.fileVersion
        buildId = $buildId; builtAtUtc = $now.ToString('o'); sourceCommit = $commit; sourceDirty = $dirty
        target = $Project.target; framework = $Project.framework; transports = @($Project.transports)
        goVersion = (& go version | Out-String).Trim(); csharpCompiler = [Diagnostics.FileVersionInfo]::GetVersionInfo($Compiler).FileVersion
    }
}

function Write-BuildJson([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 8)+[Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}

function Write-BuildAssemblyInfo([string]$Path, [object]$Metadata) {
    $text = @"
using System.Reflection;
[assembly: AssemblyTitle("TnDtun")]
[assembly: AssemblyProduct("TnDtun")]
[assembly: AssemblyVersion("$($Metadata.fileVersion)")]
[assembly: AssemblyFileVersion("$($Metadata.fileVersion)")]
[assembly: AssemblyInformationalVersion("$($Metadata.version)+$($Metadata.buildId)")]
"@
    [IO.File]::WriteAllText($Path, $text, (New-Object Text.UTF8Encoding($false)))
}
