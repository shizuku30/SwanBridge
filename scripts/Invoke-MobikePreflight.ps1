#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [ValidateSet('SwanBridge-Acceptance-MOBIKE','SwanBridge-Acceptance-Split')][string]$ProfileName = 'SwanBridge-Acceptance-MOBIKE'
)
$ErrorActionPreference = 'Stop'
$requestedOutput = $OutputDirectory
$requestedProfile = $ProfileName
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$OutputDirectory = $requestedOutput
$ProfileName = $requestedProfile
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1.' }
if (!$OutputDirectory) { $OutputDirectory=Join-Path $root ('build\acceptance\mobike-safe-preflight-'+(Get-Date -Format 'yyyyMMdd-HHmmss')) }
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$result=[ordered]@{ Outcome='ERROR'; Accepted=$false; StartedAt=[DateTimeOffset]::Now.ToString('o') }
$attempted=$false; $code=1
try {
    $package=Get-AppxPackage -Name SwanBridge.Vpn
    if (!$package) { throw 'Install the acceptance build first.' }
    $name=$ProfileName
    $phonebook=Join-Path $env:LOCALAPPDATA ('Packages\'+$package.PackageFamilyName+'\LocalState\rasphone.pbk')
    if (@(Get-PhonebookProfiles $phonebook) -cnotcontains $name) { throw 'Prepare the separate MOBIKE profile first.' }
    $ras=Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' 10
    $d=Get-PackageDiagnostics $package.PackageFamilyName
    if ($ras.ExitCode -ne 0 -or $d.ChannelUp -or $ras.Output.IndexOf($name,[StringComparison]::Ordinal) -ge 0) {
        throw 'A SwanBridge connection is active or RAS state is unknown; it was not touched.'
    }
    $before=Get-NetworkSnapshot
    Write-JsonFile $before (Join-Path $OutputDirectory 'before.json')
    $started=[DateTimeOffset]::Now; $attempted=$true
    $result.Connect=Invoke-RasControl $name $phonebook
    if ($result.Connect.ExitCode -ne 0) { throw 'The separate test connection failed.' }
    $deadline=[DateTimeOffset]::Now.AddSeconds(12)
    do {
        $d=Get-PackageDiagnostics $package.PackageFamilyName
        if ($d.ChannelUp -and $d.Authenticated -and $d.ChildSaUp -and $d.ConnectedAt -and [DateTimeOffset]::Parse($d.ConnectedAt) -ge $started) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::Now -lt $deadline)
    if (!$d.ChannelUp -or !$d.EngineRunning -or !$d.Authenticated -or !$d.ChildSaUp -or
        !$d.ConnectedAt -or [DateTimeOffset]::Parse($d.ConnectedAt) -lt $started -or
        !$d.HeartbeatAt -or [DateTimeOffset]::Parse($d.HeartbeatAt) -lt $started) { throw 'The Windows VPN channel did not become ready with fresh diagnostics.' }
    $shell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $result.ProbeProcess=Invoke-BoundedProcess $shell ('-NoProfile -ExecutionPolicy Bypass -File "'+
        (Join-Path $PSScriptRoot 'Test-VpnMobike.ps1')+'" -Mode Probe -ProfileName "'+$name+'" -OutputDirectory "'+(Join-Path $OutputDirectory 'probe')+'"') 100
    $path=Join-Path $OutputDirectory 'probe\result.json'
    if (Test-Path -LiteralPath $path) { $result.Probe=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json }
    if ($result.ProbeProcess.ExitCode -eq 2 -and $result.Probe.ClientEvidencePassed -and !$result.Probe.Accepted) {
        $result.Outcome=$result.Probe.Outcome; $result.Accepted=$false; $result.ClientEvidencePassed=$true; $code=2
    } elseif ($result.ProbeProcess.ExitCode -eq 0 -and $result.Probe.Accepted) {
        $result.Outcome=$result.Probe.Outcome; $result.Accepted=$true; $code=0
    } else { throw 'The bounded preflight failed; restoring the original network.' }
} catch { $result.Error=$_.Exception.Message }
finally {
    if ($attempted) {
        $result.Disconnect=Invoke-RasControl $name $phonebook -Disconnect
        $deadline=[DateTimeOffset]::Now.AddSeconds(10)
        do {
            $after=Get-NetworkSnapshot
            $result.NetworkDifference=Get-SnapshotDifference $before $after
            $result.NetworkRestored=Test-SnapshotUnchanged $result.NetworkDifference
            if ($result.NetworkRestored) { break }
            Start-Sleep -Milliseconds 300
        } while ([DateTimeOffset]::Now -lt $deadline)
        if ($result.Disconnect.ExitCode -ne 0 -or !$result.NetworkRestored) { $code=1; $result.Accepted=$false; $result.Outcome='CLEANUP_FAILED' }
        $result.FinalDiagnostics=Get-PackageDiagnostics $package.PackageFamilyName
        $cleanupDeadline=[DateTimeOffset]::Now.AddSeconds(12)
        do {
            $d=Get-PackageDiagnostics $package.PackageFamilyName
            $result.EngineStopped=(!$d.ChannelUp -and !$d.EngineRunning -and !$d.Authenticated -and !$d.ChildSaUp -and
                $d.HeartbeatAt -and [DateTimeOffset]::Parse($d.HeartbeatAt) -ge $started)
            if ($result.EngineStopped) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTimeOffset]::Now -lt $cleanupDeadline)
        $result.FinalDiagnostics=$d
        if (!$result.EngineStopped) { $code=1; $result.Accepted=$false; $result.Outcome='ENGINE_CLEANUP_FAILED' }
    }
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o'); $result.ExitCode=$code
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
$result | ConvertTo-Json -Depth 12
exit $code
