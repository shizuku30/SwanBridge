[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'Apply-CorePatches.ps1')
$shortRoot = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($root).ShortPath
if ($shortRoot.Contains(' ')) { throw 'Autotools requires a path without spaces or an NTFS short path.' }
$bash = Join-Path $shortRoot 'tools\msys64\usr\bin\bash.exe'
if (!(Test-Path -LiteralPath $bash)) { throw 'Run Initialize-Toolchain.ps1 -InstallPackages first.' }
$env:MSYSTEM = 'MINGW64'
$env:CHERE_INVOKING = '1'
$unix = '/' + $shortRoot.Substring(0,1).ToLowerInvariant() + $shortRoot.Substring(2).Replace('\','/')
& $bash --login "$unix/scripts/build-core.sh"
if ($LASTEXITCODE -ne 0) { throw "strongSwan core build failed ($LASTEXITCODE)." }
