$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'TnDtun.exe'
if (!(Test-Path $exe)) { throw 'Keep this script next to TnDtun.exe.' }
$shell = New-Object -ComObject WScript.Shell
foreach ($folder in @([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('Programs'))) {
    $link = $shell.CreateShortcut((Join-Path $folder 'TnDtun.lnk'))
    $link.TargetPath = $exe; $link.WorkingDirectory = $PSScriptRoot
    $link.IconLocation = (Join-Path $PSScriptRoot 'TnDtun.ico'); $link.Save()
}
$key = 'HKCU:\Software\Classes\tndtun'
New-Item -Path ($key+'\shell\open\command') -Force | Out-Null
Set-Item -Path $key -Value 'URL:TnDtun activation'
New-ItemProperty -Path $key -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null
Set-Item -Path ($key+'\shell\open\command') -Value ('"'+$exe+'" --activate "%1"')
Write-Host 'TnDtun shortcuts and activation links registered for this Windows user.'
