[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
[xml]$manifest = Get-Content -LiteralPath (Join-Path $root 'package\AppxManifest.xml') -Raw
$package = Join-Path $root ('dist\{0}_{1}_{2}.msix' -f $manifest.Package.Identity.Name,$manifest.Package.Identity.Version,$manifest.Package.Identity.ProcessorArchitecture)
$signature = Get-AuthenticodeSignature -LiteralPath $package
if ($signature.Status -ne 'Valid') {
    throw 'The signed package is not trusted. Have an administrator run Trust-DevCertificate.ps1 first.'
}
Add-AppxPackage -Path $package -ForceApplicationShutdown -ErrorAction Stop
Get-AppxPackage -Name SwanBridge.Vpn | Select-Object Name,Version,PackageFamilyName,InstallLocation,Status
