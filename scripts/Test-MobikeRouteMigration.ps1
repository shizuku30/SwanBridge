#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(60,900)][int]$WaitSeconds=300,
    [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$requestedOutput=$OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
. (Join-Path $PSScriptRoot 'MobikeEvidence.ps1')
. (Join-Path $PSScriptRoot 'MobikeRouteEvidence.ps1')
$OutputDirectory=$requestedOutput
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1.' }
if (!$OutputDirectory) { $OutputDirectory=Join-Path $root ('build/acceptance/mobike-routes-'+(Get-Date -Format 'yyyyMMdd-HHmmss')) }
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$result=[ordered]@{ Outcome='ERROR'; Accepted=$false; RedialAllowed=$false; StartedAt=[DateTimeOffset]::Now.ToString('o') }
$code=1
try {
    $package=Get-AppxPackage -Name SwanBridge.Vpn
    if (!$package) { throw 'SwanBridge.Vpn is not installed.' }
    $family=$package.PackageFamilyName
    $ras=Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' 10
    if ($ras.ExitCode -ne 0 -or $ras.Output -notmatch 'SwanBridge-Acceptance-MOBIKE') {
        throw 'Connect the full-tunnel SwanBridge-Acceptance-MOBIKE profile first.'
    }
    $before=Get-PackageDiagnostics $family
    if (!$before.ChannelUp -or !$before.Authenticated -or !$before.ChildSaUp -or
        !$before.MobikeNegotiated -or $before.MobikePending -or $before.MobikeError) {
        throw 'An established MOBIKE session is required; no connection was changed.'
    }
    if (!$before.TransportInterfacePinned -or !$before.UnderlayInterfaceIndex) {
        throw 'The native wire socket is not explicitly pinned to an underlay interface.'
    }
    $initial4=Invoke-VpnPublicWebProbe -IPv4Only
    $initialAuto=Invoke-VpnPublicWebProbe
    if (!$initial4.RemoteAddress) { throw 'Initial public HTTPS did not yield an address.' }
    $publicAddress=$initial4.RemoteAddress
    $routes=Get-VpnRouteObservation $before $publicAddress
    $initialServerRoute=$routes.ServerRoute
    $baseline=Test-VpnFullTunnelRouteEvidence $before $routes $initial4 $initialAuto
    $result.Initial=[pscustomobject]@{ Diagnostics=$before; Routes=$routes; WebIPv4=$initial4; WebAutomatic=$initialAuto; Evidence=$baseline }
    Write-JsonFile $result.Initial (Join-Path $OutputDirectory 'before.json')
    if (!$baseline.Passed) { throw ('Initial full-tunnel policy failed: '+($baseline.Failures -join '; ')) }
    $before=Get-PackageDiagnostics $family
    $result.Before=$before
    Write-JsonFile ([ordered]@{ Stage='Armed'; At=[DateTimeOffset]::Now.ToString('o');
        SessionId=$before.SessionId; LocalIPv4=$before.LocalIPv4; VirtualIPv4=$before.VirtualIPv4;
        ServerIPv4=$before.ServerIPv4; PublicSource=$initial4.LocalAddress }) (Join-Path $OutputDirectory 'ready.json')
    $deadline=[DateTimeOffset]::Now.AddSeconds($WaitSeconds)
    do {
        Start-Sleep -Seconds 2
        $after=Get-PackageDiagnostics $family
        $routes=Get-VpnRouteObservation $after $publicAddress
        Write-JsonFile ([pscustomobject]@{ Diagnostics=$after; Routes=$routes }) (Join-Path $OutputDirectory 'current.json')
        [IO.File]::AppendAllText((Join-Path $OutputDirectory 'routes.jsonl'),
            (([pscustomobject]@{ Diagnostics=$after; Routes=$routes } | ConvertTo-Json -Depth 8 -Compress)+[Environment]::NewLine),
            [Text.UTF8Encoding]::new($false))
        if ($after.SessionId -ne $before.SessionId -or !$after.ChannelUp -or !$after.Authenticated -or !$after.ChildSaUp) {
            throw 'The original VPN session was lost or replaced; no redial was attempted.'
        }
        if ($after.MobikeError) { throw ('MOBIKE error '+$after.MobikeError) }
        if ($after.MobikeCompleted -le $before.MobikeCompleted -or $after.MobikePending) { continue }
        if ($after.LocalIPv4 -eq $before.LocalIPv4 -and
            $routes.ServerRoute.InterfaceIndex -eq $initialServerRoute.InterfaceIndex -and
            $routes.ServerRoute.NextHop -eq $initialServerRoute.NextHop) { continue }
        $observedLocal=$after.LocalIPv4
        $observedCompletions=$after.MobikeCompleted
        Start-Sleep -Seconds 3
        $web4=Invoke-VpnPublicWebProbe -IPv4Only
        $webAuto=Invoke-VpnPublicWebProbe
        $after=Get-PackageDiagnostics $family
        if ($after.LocalIPv4 -ne $observedLocal -or $after.MobikeCompleted -ne $observedCompletions -or $after.MobikePending) {
            $result.LastUnstableProbe='The physical path changed during the web probes; this sample cannot verify the new network.'
            continue
        }
        $routes=Get-VpnRouteObservation $after $web4.RemoteAddress
        $policy=Test-VpnFullTunnelRouteEvidence $after $routes $web4 $webAuto
        $mobike=Test-MobikeEvidence $before $after
        $result.After=$after; $result.RoutesAfter=$routes
        $result.WebIPv4=$web4; $result.WebAutomatic=$webAuto
        $result.RouteEvidence=$policy; $result.MobikeEvidence=$mobike
        if (!$policy.Passed) { throw ('New-network route policy failed: '+($policy.Failures -join '; ')) }
        if (!$mobike.Passed) { throw ($mobike.Failures -join '; ') }
        $result.Outcome='CLIENT_FULL_TUNNEL_MIGRATION_PASSED_SERVER_VERIFICATION_REQUIRED'
        $result.ClientEvidencePassed=$true; $code=2
        break
    } while ([DateTimeOffset]::Now -lt $deadline)
    if (!$result.ClientEvidencePassed) { throw 'No verified full-tunnel migration before the deadline.' }
} catch { $result.Error=$_.Exception.Message }
finally {
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o'); $result.ExitCode=$code
    if ($family) { try { $result.Final=Get-PackageDiagnostics $family } catch {} }
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
$result | ConvertTo-Json -Depth 12
exit $code
