#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$requestedOutput=$OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
. (Join-Path $PSScriptRoot 'MobikeRouteEvidence.ps1')
$OutputDirectory=$requestedOutput
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$family='SwanBridge.Vpn_sbb2y36yht658'
$original='SwanBridge-Acceptance-MOBIKE'
$shell=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$result=[ordered]@{Outcome='ERROR';Accepted=$false;StartedAt=[DateTimeOffset]::Now.ToString('o')}
$restoreOriginal=$false; $restoreGuard=$null
try {
    $initial=Get-PackageDiagnostics $family
    $ras=Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32/rasdial.exe') '' 5
    if ($ras.ExitCode) { throw 'Cannot inspect existing RAS connections.' }
    if ($initial.ChannelUp -or $initial.EngineRunning) {
        if (!$initial.ChannelUp -or $ras.Output -notmatch [regex]::Escape($original)) { throw 'Unowned active session was not touched.' }
        Write-JsonFile $initial (Join-Path $OutputDirectory 'original-session.json')
        $result.OriginalDisconnect=Invoke-RasControl $original '' -Disconnect
        if ($result.OriginalDisconnect.ExitCode) { throw 'Original test VPN did not disconnect.' }
        $restoreOriginal=$true
        Start-Sleep -Seconds 2
        if ((Get-PackageDiagnostics $family).EngineRunning) { throw 'Engine cleanup is incomplete; package was not updated.' }
    } elseif ($ras.Output -match 'SwanBridge') { throw 'Pending SwanBridge session was not touched.' }
    & (Join-Path $PSScriptRoot 'Install-Signed.ps1') *> (Join-Path $OutputDirectory 'install.log')
    $provision=Join-Path $PSScriptRoot 'Prepare-MobikeAcceptance.ps1'
    $result.Provision=Invoke-BoundedProcess $shell ('-NoProfile -ExecutionPolicy Bypass -File "'+$provision+'" -Mode Rekey') 25
    if ($result.Provision.ExitCode) { throw 'Rekey test profile provisioning failed.' }
    $test=Join-Path $PSScriptRoot 'Test-WindowsRekey.ps1'
    $testDir=Join-Path $OutputDirectory 'test'
    $result.TestProcess=Invoke-BoundedProcess $shell ('-NoProfile -ExecutionPolicy Bypass -File "'+$test+'" -OutputDirectory "'+$testDir+'"') 330
    if (Test-Path (Join-Path $testDir 'result.json')) { $result.Test=Get-Content (Join-Path $testDir 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json }
    if (!$result.Test.ClientEvidencePassed -or !$result.Test.EngineStopped -or !$result.Test.NetworkRestored) { throw 'Windows rekey continuity or cleanup did not pass.' }
    $result.ClientEvidencePassed=$true; $result.Outcome=$result.Test.Outcome
} catch { $result.Error=$_.Exception.Message }
finally {
    $current=Get-PackageDiagnostics $family
    if ($restoreOriginal -and !$current.ChannelUp -and !$current.EngineRunning) {
        try {
            $guardDir=Join-Path $OutputDirectory 'restore-safety'
            $null=New-Item -ItemType Directory -Path $guardDir -Force
            $restoreGuard=Start-Process -FilePath $shell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $PSScriptRoot 'Watch-FullTunnelSafety.ps1')+'"'),'-GuardDirectory',('"'+$guardDir+'"'),'-GuardSeconds','90')
            $deadline=[DateTimeOffset]::Now.AddSeconds(10)
            while (!(Test-Path (Join-Path $guardDir 'guard-ready.json')) -and !$restoreGuard.HasExited -and [DateTimeOffset]::Now -lt $deadline) { Start-Sleep -Milliseconds 100 }
            if ($restoreGuard.HasExited -or !(Test-Path (Join-Path $guardDir 'guard-ready.json'))) { throw 'Original-connection safety guard did not arm.' }
            $phonebook=Join-Path $env:LOCALAPPDATA ('Packages/'+$family+'/LocalState/rasphone.pbk')
            $connectStarted=[DateTimeOffset]::Now
            $result.RestoreOriginal=Invoke-RasControl $original $phonebook
            if ($result.RestoreOriginal.ExitCode) { throw 'Could not restore the original VPN.' }
            $restored=Wait-ConnectedDiagnostics $family $connectStarted $current.SessionId
            $result.RestoredTraffic=Invoke-VpnPublicWebProbe -IPv4Only
            if (!$result.RestoredTraffic.Passed -or $result.RestoredTraffic.LocalAddress -ne $restored.VirtualIPv4) { throw 'Original VPN traffic verification failed; independent disconnect remains armed.' }
            $result.OriginalConnectionRestored=$true
            if (!$restoreGuard.HasExited) { $restoreGuard.Kill(); $restoreGuard.WaitForExit() }
            $result.RestoreGuardCancelledAfterVerifiedTraffic=$true
        } catch { $result.RestoreError=$_.Exception.Message }
    }
    if ($restoreGuard) { $restoreGuard.Dispose() }
    $cleanupAt=[DateTimeOffset]::Now
    try {
        & (Join-Path $root 'build/ActivateApp.exe') ($family+'!App') 'acceptance-remove-rekey-profile' | Out-Null
        $deadline=[DateTimeOffset]::Now.AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 200
            $d=Get-PackageDiagnostics $family
            if ($d.RekeyProfileCleanupAt -and [DateTimeOffset]::Parse($d.RekeyProfileCleanupAt) -ge $cleanupAt) { break }
        } while ([DateTimeOffset]::Now -lt $deadline)
        $result.TestProfileRemoved=($d.RekeyProfileCleanup -eq 'Removed' -and [DateTimeOffset]::Parse($d.RekeyProfileCleanupAt) -ge $cleanupAt)
    } catch { $result.ProfileCleanupError=$_.Exception.Message }
    if (($restoreOriginal -and !$result.OriginalConnectionRestored) -or !$result.TestProfileRemoved) { $result.Outcome='RESTORATION_REQUIRES_REVIEW'; $result.ClientEvidencePassed=$false }
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o')
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
[pscustomobject]$result|Select-Object Outcome,ClientEvidencePassed,OriginalConnectionRestored,TestProfileRemoved,Error,RestoreError|ConvertTo-Json
if (!$result.ClientEvidencePassed) { exit 1 }
exit 2
