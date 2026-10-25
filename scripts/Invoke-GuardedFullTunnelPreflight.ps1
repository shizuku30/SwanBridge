#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$requestedOutput=$OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
. (Join-Path $PSScriptRoot 'MobikeRouteEvidence.ps1')
$OutputDirectory=$requestedOutput
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1.' }
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$profile='SwanBridge-Acceptance-MOBIKE'
$result=[ordered]@{ Outcome='ERROR'; Accepted=$false; PhysicalSwitchAccepted=$false; RedialAllowed=$false;
    StartedAt=[DateTimeOffset]::Now.ToString('o'); GuardSeconds=90 }
$guard=$null; $attempted=$false; $code=1
try {
    $package=Get-AppxPackage -Name SwanBridge.Vpn
    if (!$package -or [version]$package.Version -lt [version]'0.1.0.38') { throw 'Install the route-fix acceptance package first.' }
    $family=$package.PackageFamilyName
    $initial=Get-PackageDiagnostics $family
    $ras=Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' 5
    if ($initial.ChannelUp -or $initial.EngineRunning -or $ras.ExitCode -ne 0 -or $ras.Output -match 'SwanBridge') {
        throw 'A SwanBridge VPN is already active; it was not touched.'
    }
    $before=Get-NetworkSnapshot
    Write-JsonFile $before (Join-Path $OutputDirectory 'network-before.json')
    $result.BeforeIPv6=Invoke-VpnPublicWebProbe -IPv6Only
    $shell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $guardScript=Join-Path $PSScriptRoot 'Watch-FullTunnelSafety.ps1'
    $guardArguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$guardScript+'"'),
        '-GuardDirectory',('"'+$OutputDirectory+'"'),'-GuardSeconds','90')
    $guard=Start-Process -FilePath $shell -ArgumentList $guardArguments -WindowStyle Hidden -PassThru
    $readyPath=Join-Path $OutputDirectory 'guard-ready.json'
    $deadline=[DateTimeOffset]::Now.AddSeconds(10)
    while (!(Test-Path -LiteralPath $readyPath) -and !$guard.HasExited -and [DateTimeOffset]::Now -lt $deadline) { Start-Sleep -Milliseconds 100 }
    if ($guard.HasExited -or !(Test-Path -LiteralPath $readyPath)) { throw 'The independent safety guard did not arm.' }
    $ready=Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($ready.GuardPid -ne $guard.Id -or $ready.Stage -ne 'GuardArmed') { throw 'Safety guard identity does not match.' }
    $result.GuardPid=$guard.Id
    $phonebook=Join-Path $env:LOCALAPPDATA ('Packages\'+$family+'\LocalState\rasphone.pbk')
    $attempted=$true
    $result.Connect=Invoke-RasControl $profile $phonebook
    if ($result.Connect.ExitCode) { throw 'Windows rejected the protected full-tunnel test connection.' }
    $deadline=[DateTimeOffset]::Now.AddSeconds(10)
    do {
        $d=Get-PackageDiagnostics $family
        if ($d.ChannelUp -and $d.Authenticated -and $d.ChildSaUp) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::Now -lt $deadline)
    $result.Diagnostics=$d
    if (!$d.ChannelUp -or !$d.Authenticated -or !$d.ChildSaUp) { throw 'The full-tunnel channel did not become authenticated.' }
    $web4=Invoke-VpnPublicWebProbe -IPv4Only
    $webAuto=Invoke-VpnPublicWebProbe
    $web6=Invoke-VpnPublicWebProbe -IPv6Only
    $routes=Get-VpnRouteObservation $d $web4.RemoteAddress
    $policy=Test-VpnFullTunnelRouteEvidence $d $routes $web4 $webAuto
    $result.WebIPv4=$web4; $result.WebAutomatic=$webAuto; $result.WebIPv6=$web6
    $result.Routes=$routes; $result.RouteEvidence=$policy
    Write-JsonFile (Get-NetworkSnapshot) (Join-Path $OutputDirectory 'network-connected.json')
    if (!$policy.Passed) { throw ($policy.Failures -join '; ') }
    if ($web6.Passed) { throw 'IPv6 still bypasses this IPv4-only VPN.' }
    $result.Outcome='PASS_STATIC_FULL_TUNNEL_AND_NO_OBSERVED_IPV6_BYPASS'
    $result.Accepted=$true; $code=0
} catch { $result.Error=$_.Exception.Message }
finally {
    if ($attempted) {
        try { $result.Disconnect=Invoke-RasControl $profile '' -Disconnect } catch { $result.DisconnectError=$_.Exception.Message }
    }
    if ($guard) {
        if (!$guard.WaitForExit(110000)) { $result.GuardWaitTimedOut=$true; $code=1; $result.Accepted=$false }
        $guardReport=Join-Path $OutputDirectory 'guard-result.json'
        if (Test-Path -LiteralPath $guardReport) { $result.Guard=Get-Content -LiteralPath $guardReport -Raw -Encoding UTF8 | ConvertFrom-Json }
        $guard.Dispose()
    }
    if ($family) {
        $result.Final=Get-PackageDiagnostics $family
        if ($result.Final.ChannelUp -or $result.Final.EngineRunning) { $result.Accepted=$false; $result.Outcome='CLEANUP_FAILED'; $code=1 }
    }
    if ($before) {
        $after=Get-NetworkSnapshot
        Write-JsonFile $after (Join-Path $OutputDirectory 'network-after.json')
        $result.NetworkDifference=Get-SnapshotDifference $before $after
        $result.NetworkRestored=Test-SnapshotUnchanged $result.NetworkDifference
        if (!$result.NetworkRestored) {
            $result.AcceptedBeforeCleanup=$result.Accepted
            $result.Accepted=$false; $result.Outcome='NETWORK_CLEANUP_REQUIRES_REVIEW'; $code=1
        }
    }
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o'); $result.ExitCode=$code
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
$result | ConvertTo-Json -Depth 10
exit $code
