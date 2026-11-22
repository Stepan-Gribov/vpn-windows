$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'TnDtun.exe'
$shell = New-Object -ComObject WScript.Shell
foreach ($folder in @([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('Programs'))) {
    $path = Join-Path $folder 'TnDtun.lnk'
    if ((Test-Path $path) -and $shell.CreateShortcut($path).TargetPath -eq $exe) { Remove-Item $path }
}
$key = 'HKCU:\Software\Classes\tndtun'
$command = Get-Item ($key+'\shell\open\command') -ErrorAction SilentlyContinue
if ($command -and $command.GetValue('').StartsWith('"'+$exe+'"')) { Remove-Item $key -Recurse }
Write-Host 'Shortcuts removed. Saved profiles remain in LocalAppData\TnDtun.'
