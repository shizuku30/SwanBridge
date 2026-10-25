#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'scripts/MobikeRouteEvidence.ps1')
function Check([bool]$Condition,[string]$Description) {
    if (!$Condition) { throw ('FAIL '+$Description) }
    Write-Output ('PASS '+$Description)
}
function Copy-RouteFixture($Value) { $Value | ConvertTo-Json -Depth 7 | ConvertFrom-Json }
$d=[pscustomobject]@{ VirtualIPv4='10.77.0.3'; LocalIPv4='198.51.100.170' }
$r=[pscustomobject]@{
    VpnInterfaceIndex=52
    PublicRoute=[pscustomobject]@{ InterfaceIndex=52 }
    LanRoute=[pscustomobject]@{ InterfaceIndex=52 }
    DnsRoute=[pscustomobject]@{ InterfaceIndex=52 }
    ServerRoute=[pscustomobject]@{ InterfaceIndex=4; SourceAddress='198.51.100.170' }
}
$w4=[pscustomobject]@{ Passed=$true; IPv4Only=$true; LocalAddress='10.77.0.3' }
$wa=[pscustomobject]@{ Passed=$true; IPv4Only=$false; LocalAddress='10.77.0.3' }
Check (Test-VpnFullTunnelRouteEvidence $d $r $w4 $wa).Passed 'public routing, application source and transport exclusion agree'
$pinned=Copy-RouteFixture $d
$pinned | Add-Member TransportInterfacePinned $true
$pinned | Add-Member UnderlayInterfaceIndex 4
Check (Test-VpnFullTunnelRouteEvidence $pinned $r $w4 $wa).Passed 'actual physical socket override agrees with the bound route lookup'
$pinned.UnderlayInterfaceIndex=52
Check (!(Test-VpnFullTunnelRouteEvidence $pinned $r $w4 $wa).Passed) 'a fabricated or VPN-directed socket override cannot pass'
foreach ($name in @('PublicRoute','DnsRoute')) {
    $copy=Copy-RouteFixture $r; $copy.$name.InterfaceIndex=4
    Check (!(Test-VpnFullTunnelRouteEvidence $d $copy $w4 $wa).Passed) ($name+' physical bypass rejected')
}
$copy=Copy-RouteFixture $r; $copy.ServerRoute.InterfaceIndex=52
Check (!(Test-VpnFullTunnelRouteEvidence $d $copy $w4 $wa).Passed) 'encrypted transport cannot recurse through VPN'
$copy=Copy-RouteFixture $r; $copy.ServerRoute.SourceAddress='192.0.2.234'
Check (!(Test-VpnFullTunnelRouteEvidence $d $copy $w4 $wa).Passed) 'old physical source after handover is rejected'
$copy=Copy-RouteFixture $wa; $copy.LocalAddress='2001:db8::1'
Check (!(Test-VpnFullTunnelRouteEvidence $d $r $w4 $copy).Passed) 'successful HTTP over physical IPv6 is still a VPN bypass'
$copy=Copy-RouteFixture $w4; $copy.LocalAddress='198.51.100.170'
Check (!(Test-VpnFullTunnelRouteEvidence $d $r $copy $wa).Passed) 'successful HTTP over physical IPv4 is rejected'
$copy=Copy-RouteFixture $wa; $copy.Passed=$false
Check (!(Test-VpnFullTunnelRouteEvidence $d $r $w4 $copy).Passed) 'unreachable ordinary web requests cannot pass'
$copy=Copy-RouteFixture $r; $copy.LanRoute=[pscustomobject]@{
    InterfaceIndex=4; NextHop='0.0.0.0'; SourceAddress='192.0.2.234'; DestinationPrefix='192.0.2.0/24'
}
Check (Test-VpnFullTunnelRouteEvidence $d $copy $w4 $wa).Passed 'explicitly excluded local physical LAN is preserved'
$copy.LanRoute.SourceAddress='198.51.100.170'; $copy.LanRoute.NextHop='198.51.100.138'
Check (!(Test-VpnFullTunnelRouteEvidence $d $copy $w4 $wa).Passed) 'remote LAN cannot silently fall through the new physical gateway'
$plugin=Get-Content (Join-Path $root 'src/Plugin.cpp') -Raw
$engine=Get-Content (Join-Path $root 'src/engine/Engine.c') -Raw
$underlayGetter=[regex]::Match($engine,'(?s)uint32_t sb_engine_underlay_interface\(sb_engine \*engine\).*?(?=\n(?:int|void|uint32_t) sb_engine_)').Value
Check ($engine -match 'DWORD value = htonl\(index\)' -and
    $underlayGetter -match 'getsockopt' -and $underlayGetter -match 'return result \? 0 : index;' -and
    $underlayGetter -notmatch 'ntohl') 'UDP interface option writes network order and reports host-order interface indices'
Check ($plugin -notmatch 'ReplaceAndAssociateTransport' -and $plugin -match 'native.rebindUdp') 'native UDP mobility does not trigger Windows framework redial'
Check ($plugin -match 'HostName\(L"::"\), 1' -and $plugin -match 'HostName\(L"8000::"\), 1') 'IPv6 full-tunnel capture outranks physical default routes'
Check ($plugin -match 'ipv6Sink.Append\(HostName\(Ipv6GuardAddress\)\)' -and
    $plugin -match '\+\+blockedIpv6') 'IPv4-only full tunnel provides a local IPv6 sink and explicitly drops IPv6 packets'
