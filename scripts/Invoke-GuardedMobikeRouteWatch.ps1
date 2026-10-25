#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$requestedOutput=$OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$OutputDirectory=$requestedOutput
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1.' }
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$profile='SwanBridge-Acceptance-MOBIKE'
$result=[ordered]@{ Outcome='ERROR'; Accepted=$false; PhysicalSwitchAccepted=$false;
    StartedAt=[DateTimeOffset]::Now.ToString('o'); GuardSeconds=90; RedialAllowed=$false }
$guard=$null; $attempted=$false; $code=1
try {
    $package=Get-AppxPackage -Name SwanBridge.Vpn
    if (!$package -or [version]$package.Version -lt [version]'0.1.0.43') { throw 'Install package 0.1.0.43 or newer with host-order underlay diagnostics first.' }
    $result.PackageVersion=$package.Version.ToString()
    $family=$package.PackageFamilyName
    $initial=Get-PackageDiagnostics $family
    $ras=Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' 5
    if ($initial.ChannelUp -or $initial.EngineRunning -or $ras.ExitCode -ne 0 -or $ras.Output -match 'SwanBridge') {
        throw 'A SwanBridge session is active; it was not touched.'
    }
    $before=Get-NetworkSnapshot
    Write-JsonFile $before (Join-Path $OutputDirectory 'network-before.json')
    $shell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $guardScript=Join-Path $PSScriptRoot 'Watch-FullTunnelSafety.ps1'
    $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$guardScript+'"'),
        '-GuardDirectory',('"'+$OutputDirectory+'"'),'-GuardSeconds','90')
    $guard=Start-Process -FilePath $shell -ArgumentList $arguments -WindowStyle Hidden -PassThru
    $readyPath=Join-Path $OutputDirectory 'guard-ready.json'
    $deadline=[DateTimeOffset]::Now.AddSeconds(10)
    while (!(Test-Path $readyPath) -and !$guard.HasExited -and [DateTimeOffset]::Now -lt $deadline) { Start-Sleep -Milliseconds 100 }
    if ($guard.HasExited -or !(Test-Path $readyPath)) { throw 'The safety guard did not arm.' }
    $ready=Get-Content $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($ready.GuardPid -ne $guard.Id -or $ready.Stage -ne 'GuardArmed') { throw 'Safety guard identity mismatch.' }
    $result.GuardPid=$guard.Id
    $phonebook=Join-Path $env:LOCALAPPDATA ('Packages\'+$family+'\LocalState\rasphone.pbk')
    $attempted=$true
    $result.Connect=Invoke-RasControl $profile $phonebook
    if ($result.Connect.ExitCode) { throw 'The full-tunnel connection failed.' }
    $watchPath=Join-Path $OutputDirectory 'watch'
    $watchScript=Join-Path $PSScriptRoot 'Test-MobikeRouteMigration.ps1'
    $result.WatchProcess=Invoke-BoundedProcess $shell ('-NoProfile -ExecutionPolicy Bypass -File "'+$watchScript+
        '" -WaitSeconds 75 -OutputDirectory "'+$watchPath+'"') 83
    $watchReport=Join-Path $watchPath 'result.json'
    if (Test-Path $watchReport) { $result.Watch=Get-Content $watchReport -Raw -Encoding UTF8 | ConvertFrom-Json }
    if ($result.WatchProcess.ExitCode -ne 2 -or !$result.Watch.ClientEvidencePassed) {
        throw 'No verified full-tunnel migration on the new physical path.'
    }
    $result.ClientEvidencePassed=$true; $result.Outcome=$result.Watch.Outcome; $code=2
} catch { $result.Error=$_.Exception.Message }
finally {
    if ($attempted -and $family -and $result.Watch.Before) {
        $returnDeadline=[DateTimeOffset]::Now.AddSeconds(35)
        if ($ready.Deadline) {
            $guardDeadline=[DateTimeOffset]::Parse($ready.Deadline).AddSeconds(-5)
            if ($guardDeadline -lt $returnDeadline) { $returnDeadline=$guardDeadline }
        }
        do {
            $current=Get-PackageDiagnostics $family
            if (!$current.ChannelUp -or ($current.LocalIPv4 -eq $result.Watch.Before.LocalIPv4 -and !$current.MobikePending)) { break }
            Start-Sleep -Seconds 1
        } while ([DateTimeOffset]::Now -lt $returnDeadline)
    }
    if ($attempted) { try { $result.Disconnect=Invoke-RasControl $profile '' -Disconnect } catch { $result.DisconnectError=$_.Exception.Message } }
    if ($guard) {
        if (!$guard.WaitForExit(110000)) { $result.GuardWaitTimedOut=$true; $code=1 }
        $guardReport=Join-Path $OutputDirectory 'guard-result.json'
        if (Test-Path $guardReport) { $result.Guard=Get-Content $guardReport -Raw -Encoding UTF8 | ConvertFrom-Json }
        $guard.Dispose()
    }
    if ($family) {
        $result.Final=Get-PackageDiagnostics $family
        $result.EngineStopped=(!$result.Final.ChannelUp -and !$result.Final.EngineRunning -and !$result.Final.Authenticated -and !$result.Final.ChildSaUp)
        if (!$result.EngineStopped) { $result.Outcome='CLEANUP_FAILED'; $code=1 }
    }
    if ($before) {
        $after=Get-NetworkSnapshot
        Write-JsonFile $after (Join-Path $OutputDirectory 'network-after.json')
        $result.NetworkDifference=Get-SnapshotDifference $before $after
        $result.NetworkRestored=Test-SnapshotUnchanged $result.NetworkDifference
        if (!$result.NetworkRestored) { $result.Outcome='NETWORK_CLEANUP_REQUIRES_REVIEW'; $code=1 }
    }
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o'); $result.ExitCode=$code
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
$result | ConvertTo-Json -Depth 12
exit $code
