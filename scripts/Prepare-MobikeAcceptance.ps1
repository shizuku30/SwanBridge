#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Mobike', 'Split', 'Rekey')][string]$Mode = 'Mobike')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1.' }
$package = Get-AppxPackage -Name SwanBridge.Vpn
if (!$package) { throw 'Install the acceptance build first.' }
$launcher = Join-Path $root 'build\ActivateApp.exe'
if (!(Test-Path -LiteralPath $launcher)) { throw 'Run scripts\Build.ps1 first.' }
# Persisted diagnostics can outlive a crashed or updated host. The app checks
# the current Windows profile states before provisioning this separate profile.
$started = [DateTimeOffset]::Now
$activation = if ($Mode -eq 'Rekey') { 'acceptance-rekey-profile' } elseif ($Mode -eq 'Split') { 'acceptance-split-profile' } else { 'acceptance-mobike-profile' }
& $launcher ($package.PackageFamilyName+'!App') $activation
if ($LASTEXITCODE -ne 0) { throw 'Application activation failed.' }
$deadline = $started.AddSeconds(15)
do {
    Start-Sleep -Milliseconds 200
    $d = Get-PackageDiagnostics $package.PackageFamilyName
    if ($d.MobikeProfilePreparedAt -and [DateTimeOffset]::Parse($d.MobikeProfilePreparedAt) -ge $started -and
        $d.MobikeProfilePreparation -ne 'Running') {
        if ($d.MobikeProfilePreparation -ne 'Ready') { throw $d.MobikeProfilePreparation }
        [pscustomobject]@{ ProfileName=$d.MobikeProfileName; Result='Ready'; SourceProfileModified=$false; PskDecrypted=$false }
        exit 0
    }
} while ([DateTimeOffset]::Now -lt $deadline)
throw 'No fresh provisioning result. The installed app must be built with -AcceptanceHooks.'
