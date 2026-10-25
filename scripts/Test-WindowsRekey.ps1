#Requires -Version 5.1
[CmdletBinding()]
param([ValidateRange(180,240)][int]$Seconds=210,[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$requestedOutput=$OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
. (Join-Path $PSScriptRoot 'RekeyEvidence.ps1')
. (Join-Path $PSScriptRoot 'MobikeRouteEvidence.ps1')
$OutputDirectory=$requestedOutput
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$profile='SwanBridge-Acceptance-Rekey'
$result=[ordered]@{Outcome='ERROR';Accepted=$false;StartedAt=[DateTimeOffset]::Now.ToString('o');RedialAllowed=$false}
$attempted=$false; $guard=$null; $session=$null
try {
    if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1.' }
    $package=Get-AppxPackage SwanBridge.Vpn
    if (!$package -or [version]$package.Version -lt [version]'0.1.0.45') { throw 'Install package 0.1.0.45 or newer with the IKE/Child deadline race fix first.' }
    $family=$package.PackageFamilyName
    $initial=Get-PackageDiagnostics $family
    $ras=Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32/rasdial.exe') '' 5
    if ($initial.ChannelUp -or $initial.EngineRunning -or $ras.ExitCode -or $ras.Output -match 'SwanBridge') { throw 'A pre-existing session was not touched.' }
    $networkBefore=Get-NetworkSnapshot
    Write-JsonFile $networkBefore (Join-Path $OutputDirectory 'network-before.json')
    $shell=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $guard=Start-Process -FilePath $shell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $PSScriptRoot 'Watch-FullTunnelSafety.ps1')+'"'),'-GuardDirectory',('"'+$OutputDirectory+'"'),'-GuardSeconds','270','-ProfileName',$profile)
    $guardReady=Join-Path $OutputDirectory 'guard-ready.json'
    $deadline=[DateTimeOffset]::Now.AddSeconds(10)
    while (!(Test-Path $guardReady) -and !$guard.HasExited -and [DateTimeOffset]::Now -lt $deadline) { Start-Sleep -Milliseconds 100 }
    if (!(Test-Path $guardReady) -or $guard.HasExited) { throw 'Independent disconnect guard did not arm.' }
    $ready=Get-Content $guardReady -Raw -Encoding UTF8|ConvertFrom-Json
    if ($ready.GuardPid -ne $guard.Id -or $ready.ProfileName -ne $profile) { throw 'Disconnect guard identity mismatch.' }
    $phonebook=Join-Path $env:LOCALAPPDATA ('Packages/'+$family+'/LocalState/rasphone.pbk')
    $attempted=$true
    $connectStarted=[DateTimeOffset]::Now
    $result.Connect=Invoke-RasControl $profile $phonebook
    if ($result.Connect.ExitCode) { throw 'The isolated Windows rekey profile failed to connect.' }
    $null=Wait-ConnectedDiagnostics $family $connectStarted $initial.SessionId
    $samples=[Collections.Generic.List[object]]::new()
    $deadline=[DateTimeOffset]::Now.AddSeconds($Seconds)
    do {
        $d=Get-PackageDiagnostics $family
        if (!$session) { $session=$d.SessionId }
        if (!$d.ChannelUp -or !$d.ChildSaUp -or $d.RouteMode -ne 1 -or $d.SessionId -ne $session) { throw 'The original split Windows channel was lost or replaced.' }
        $traffic=$null; $trafficError=$null
        try { $traffic=Test-WindowsVpnTraffic $d.VirtualIPv4 -PinnedBaidu $d.RekeyHttpsAddress } catch { $trafficError=$_.Exception.Message }
        $d=Get-PackageDiagnostics $family
        $route=Get-SelectedRoute '8.8.8.8'
        $vpn=@(Get-NetIPAddress -IPAddress $d.VirtualIPv4 -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $routePassed=$vpn.Count -eq 1 -and !$route.Error -and $route.InterfaceIndex -eq $vpn[0].InterfaceIndex
        $httpsRoute=Get-SelectedRoute $d.RekeyHttpsAddress
        $routePassed=$routePassed -and !$httpsRoute.Error -and $httpsRoute.InterfaceIndex -eq $vpn[0].InterfaceIndex
        $d|Add-Member TrafficPassed ([bool]($traffic.Passed -and $routePassed))
        $d|Add-Member Traffic $traffic
        $d|Add-Member TrafficError $trafficError
        $d|Add-Member Route $route
        $d|Add-Member HttpsRoute $httpsRoute
        $samples.Add($d)
        [IO.File]::AppendAllText((Join-Path $OutputDirectory 'samples.jsonl'),(($d|ConvertTo-Json -Depth 8 -Compress)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        if ($samples.Count -eq 1) { Write-JsonFile ([ordered]@{Stage='Armed';At=[DateTimeOffset]::Now.ToString('o');SessionId=$session;VirtualIPv4=$d.VirtualIPv4}) (Join-Path $OutputDirectory 'ready.json') }
        Start-Sleep -Seconds 1
    } while ([DateTimeOffset]::Now -lt $deadline)
    $result.Before=$samples[0]; $result.After=$samples[-1]; $result.SampleCount=$samples.Count
    $result.ClientEvidence=Test-RekeyEvidence $samples.ToArray() -WindowsChannel
    if ($result.After.IkeRekeysCompleted -lt [Math]::Floor($Seconds/90) -or
        $result.After.ChildRekeysCompleted -lt [Math]::Floor($Seconds/60)) { throw 'A scheduled rekey cycle was skipped, including the simultaneous IKE/Child deadline.' }
    if (!$result.ClientEvidence.Passed) { throw ($result.ClientEvidence.Failures -join '; ') }
    $result.ClientEvidencePassed=$true; $result.Outcome='WINDOWS_REKEY_PASSED_SERVER_VERIFICATION_REQUIRED'
} catch { $result.Error=$_.Exception.Message }
finally {
    if ($attempted) {
        $current=Get-PackageDiagnostics $family
        if (!$session -or $current.SessionId -eq $session) { $result.Disconnect=Invoke-RasControl $profile '' -Disconnect }
        else { $result.DisconnectSkipped='A different session replaced this test; it was not disconnected.' }
    }
    if ($guard) { if (!$guard.WaitForExit(300000)) { $result.GuardWaitTimedOut=$true }; $guard.Dispose() }
    if ($family) {
        $final=Get-PackageDiagnostics $family
        $result.EngineStopped=(!$final.EngineRunning -and !$final.ChannelUp)
    }
    if ($networkBefore) {
        $networkAfter=Get-NetworkSnapshot
        Write-JsonFile $networkAfter (Join-Path $OutputDirectory 'network-after.json')
        $result.NetworkDifference=Get-SnapshotDifference $networkBefore $networkAfter
        $result.NetworkRestored=Test-SnapshotUnchanged $result.NetworkDifference
    }
    if (!$result.EngineStopped -or !$result.NetworkRestored) { $result.ClientEvidencePassed=$false; $result.Outcome='CLEANUP_REQUIRES_REVIEW' }
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o')
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
[pscustomobject]$result|Select-Object Outcome,ClientEvidencePassed,SampleCount,EngineStopped,NetworkRestored,Error|ConvertTo-Json
if (!$result.ClientEvidencePassed) { exit 1 }
exit 2
