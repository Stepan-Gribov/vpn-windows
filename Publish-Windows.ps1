[CmdletBinding(SupportsShouldProcess)]
param([string]$Archive)

$ErrorActionPreference = 'Stop'
$sourceRepo = 'Stepan-Gribov/vpn-windows'
$buildsRepo = 'Stepan-Gribov/vpn-builds'
$checksumName = 'SHA256SUMS.txt'

function Invoke-GitHub([string[]]$Arguments) {
    $output = & gh @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'GitHub CLI command failed. See the error above.' }
    return $output
}

function Get-GitHubJson([string]$Path) {
    Invoke-GitHub @('api', '--hostname', 'github.com', $Path) | Out-String | ConvertFrom-Json
}

function Get-Release([string]$Repo, [string]$Tag) {
    # Include drafts so a failed upload can be resumed.
    $tags = Invoke-GitHub @('api', '--hostname', 'github.com', '--paginate',
        "repos/$Repo/releases?per_page=100", '--jq', '.[].tag_name')
    if ($Tag -in $tags) {
        Invoke-GitHub @('release', 'view', $Tag, '--repo', "github.com/$Repo",
            '--json', 'assets,isDraft,url') | ConvertFrom-Json
    }
}

function Assert-Checksum([string]$Path, [string]$Name, [string]$Hash) {
    $expected = '^' + $Hash + '\s+\*?' + [regex]::Escape($Name) + '$'
    if ((Get-Content -LiteralPath $Path -Raw).Trim() -notmatch $expected) {
        throw "SHA-256 or file name does not match the archive: $Path"
    }
}

if (!$Archive) {
    $project = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'project.json') -Raw | ConvertFrom-Json
    $Archive = Join-Path $PSScriptRoot "dist/TnDtun-$($project.version)-$($project.target).zip"
}
$file = Get-Item -LiteralPath $Archive
$versionPattern = '\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?'
if ($file.PSIsContainer -or $file.Name -cnotmatch "^TnDtun-($versionPattern)-windows-x64\.zip$") {
    throw 'Select a TnDtun Windows x64 release ZIP.'
}
$version = $Matches[1]
$tag = "windows-v$version"
$revisionPattern = '^[0-9a-f]{40}$'
$hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
Assert-Checksum ($file.FullName + '.sha256') $file.Name $hash

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($file.FullName)
try {
    $root = $file.BaseName
    $entries = @{}
    foreach ($entry in $zip.Entries) {
        $entries[$entry.FullName.Replace('\', '/')] = $entry
    }
    foreach ($name in @('TnDtun.exe', 'TnDtun.Engine.exe', 'wintun.dll', 'BUILD-INFO.json')) {
        if (!$entries["$root/$name"].Length) { throw "Missing or empty file in ZIP: $name" }
    }
    $reader = New-Object IO.StreamReader($entries["$root/BUILD-INFO.json"].Open())
    try { $build = $reader.ReadToEnd() | ConvertFrom-Json }
    finally { $reader.Dispose() }
} finally { $zip.Dispose() }

$revision = $build.sourceCommit
if ($build.product -cne 'TnDtun' -or $build.version -cne $version -or $build.target -cne 'windows-x64' -or
    $build.sourceDirty -isnot [bool] -or $build.sourceDirty -or $revision -cnotmatch $revisionPattern) {
    throw 'BUILD-INFO.json must match the archive and identify a clean source commit.'
}
if ($build.buildId -cnotmatch ('^\d{8}T\d{9}Z-' + $revision.Substring(0, 8) + '$')) {
    throw 'The build ID must identify the same source commit.'
}

if (!(Get-Command gh -ErrorAction SilentlyContinue)) { throw 'Install GitHub CLI and run gh auth login.' }
$account = Get-GitHubJson 'user'
$source = Get-GitHubJson "repos/$sourceRepo"
$builds = Get-GitHubJson "repos/$buildsRepo"
if ($account.login -cne 'Stepan-Gribov' -or $source.full_name -cne $sourceRepo -or $source.private -ne $false -or
    $builds.full_name -cne $buildsRepo -or $builds.private -ne $true) {
    throw 'Sign in as Stepan-Gribov and verify the source and private build repositories.'
}
$comparison = Get-GitHubJson "repos/$sourceRepo/compare/$revision...$($source.default_branch)"
if ($comparison.status -notin @('identical', 'ahead')) { throw 'Push the source commit to the default branch first.' }
$sourceProject = Invoke-GitHub @('api', '--hostname', 'github.com', '--header', 'Accept: application/vnd.github.raw+json',
    "repos/$sourceRepo/contents/project.json?ref=$revision") | Out-String | ConvertFrom-Json
if ($sourceProject.version -cne $version -or $sourceProject.target -cne $build.target -or
    $sourceProject.fileVersion -cne $build.fileVersion) { throw 'Package version does not match the source commit.' }

$tagRef = Get-GitHubJson "repos/$sourceRepo/git/matching-refs/tags/$tag" | Where-Object { $_.ref -ceq "refs/tags/$tag" }
if ($tagRef -and (Get-GitHubJson "repos/$sourceRepo/commits/$tag").sha -cne $revision) {
    throw 'The public source tag already points to a different commit.'
}
$public = Get-Release $sourceRepo $tag
if ($public -and ($public.isDraft -or !$tagRef)) { throw 'Review the existing public release before continuing.' }
$private = Get-Release $buildsRepo $tag
if (!$PSCmdlet.ShouldProcess("$buildsRepo, $sourceRepo", "Publish or verify $tag")) { return }

$title = "TnDtun $version (Windows x64)"
$releaseType = @()
if ($version.Contains('-')) { $releaseType += '--prerelease' }
$sourceUrl = "https://github.com/$sourceRepo"
$privateUrl = "https://github.com/$buildsRepo/releases/tag/$tag"
$assetRepo = "github.com/$buildsRepo"
$temp = Join-Path ([IO.Path]::GetTempPath()) ('tndtun-release-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    if (!$private) {
        $notes = "Extract the ZIP and run TnDtun.exe.`n`nSource: $sourceUrl/tree/$tag`n`nBuild: $($build.buildId)`n`nSHA-256: $hash"
        Invoke-GitHub (@('release', 'create', $tag, '--repo', $assetRepo, '--draft', '--title', $title,
            '--notes', $notes) + $releaseType) | Out-Null
        $private = Get-Release $buildsRepo $tag
        if (!$private) { throw 'The private draft could not be read after creation.' }
    }

    $download = Join-Path $temp 'download'
    New-Item -ItemType Directory -Path $download | Out-Null
    $hasChecksum = $checksumName -in $private.assets.name
    if ($hasChecksum) {
        Invoke-GitHub @('release', 'download', $tag, '--repo', $assetRepo, '--pattern', $checksumName, '--dir', $download)
        Assert-Checksum (Join-Path $download $checksumName) $file.Name $hash
    }
    if ($file.Name -notin $private.assets.name) {
        Invoke-GitHub @('release', 'upload', $tag, '--repo', $assetRepo, $file.FullName)
    }
    Invoke-GitHub @('release', 'download', $tag, '--repo', $assetRepo, '--pattern', $file.Name, '--dir', $download)
    $downloaded = Get-FileHash -LiteralPath (Join-Path $download $file.Name) -Algorithm SHA256
    if ($downloaded.Hash -ne $hash) { throw 'The GitHub ZIP differs from the local build. Review the existing release.' }
    if (!$hasChecksum) {
        $checksum = Join-Path $temp $checksumName
        [IO.File]::WriteAllText($checksum, "$hash  $($file.Name)`n")
        Invoke-GitHub @('release', 'upload', $tag, '--repo', $assetRepo, $checksum)
        Invoke-GitHub @('release', 'download', $tag, '--repo', $assetRepo, '--pattern', $checksumName, '--dir', $download)
        Assert-Checksum (Join-Path $download $checksumName) $file.Name $hash
    }

    if ($private.isDraft) { Invoke-GitHub @('release', 'edit', $tag, '--repo', $assetRepo, '--draft=false') | Out-Null }
    if (!$public) {
        $notes = "[Windows x64 ZIP (private release)]($privateUrl)`n`n[Build instructions]($sourceUrl/blob/$tag/BUILD-RU.md)"
        $tagOption = @('--target', $revision)
        if ($tagRef) { $tagOption = @('--verify-tag') }
        Invoke-GitHub (@('release', 'create', $tag, '--repo', "github.com/$sourceRepo", '--title', $title,
            '--notes', $notes, '--generate-notes') + $tagOption + $releaseType) | Out-Null
    }
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }

Write-Host "SHA-256 verified: $hash"
Write-Host "Download: $privateUrl"
Write-Host "Release: $sourceUrl/releases/tag/$tag"
