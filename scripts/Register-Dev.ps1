[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'build\layout\AppxManifest.xml'
if (!(Test-Path -LiteralPath $manifest)) { throw 'Run scripts\Build.ps1 first.' }
# This uses the existing development policy. It does not enable Developer Mode.
Add-AppxPackage -Register $manifest -ErrorAction Stop
Get-AppxPackage -Name SwanBridge.Vpn | Select-Object Name,Version,PackageFamilyName,InstallLocation,Status
