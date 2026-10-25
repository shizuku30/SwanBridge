#Requires -Version 5.1

function Get-SelectedRoute([string]$Address, [uint32]$InterfaceIndex=0) {
    try {
        $parameters=@{ RemoteIPAddress=$Address; ErrorAction='Stop' }
        if ($InterfaceIndex) { $parameters.InterfaceIndex=$InterfaceIndex }
        $selected = @(Find-NetRoute @parameters)
        $route = $selected | Where-Object { $_.PSObject.Properties['DestinationPrefix'] } | Select-Object -First 1
        $source = $selected | Where-Object { $_.PSObject.Properties['IPAddress'] } | Select-Object -First 1
        if (!$route -or !$source) { throw 'Route or source address is missing.' }
        [pscustomobject]@{ Address=$Address; SourceAddress=$source.IPAddress; InterfaceIndex=$route.InterfaceIndex;
            InterfaceAlias=$route.InterfaceAlias; DestinationPrefix=$route.DestinationPrefix;
            NextHop=$route.NextHop; RouteMetric=$route.RouteMetric }
    } catch {
        [pscustomobject]@{ Address=$Address; Error=$_.Exception.Message }
    }
}

function Get-VpnRouteObservation($Diagnostics, [string]$PublicAddress) {
    $interface = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Diagnostics.VirtualIPv4 -ErrorAction SilentlyContinue)
    $unbound=Get-SelectedRoute $Diagnostics.ServerIPv4
    $server=$unbound
    if ($Diagnostics.TransportInterfacePinned -and $Diagnostics.UnderlayInterfaceIndex) {
        $server=Get-SelectedRoute $Diagnostics.ServerIPv4 $Diagnostics.UnderlayInterfaceIndex
    }
    [pscustomobject]@{
        CapturedAt=[DateTimeOffset]::Now.ToString('o')
        VpnInterfaceIndex=$(if ($interface.Count -eq 1) { $interface[0].InterfaceIndex } else { $null })
        VpnInterfaceAlias=$(if ($interface.Count -eq 1) { $interface[0].InterfaceAlias } else { $null })
        ServerRoute=$server
        UnboundServerRoute=$unbound
        TransportInterfacePinned=$Diagnostics.TransportInterfacePinned
        UnderlayInterfaceIndex=$Diagnostics.UnderlayInterfaceIndex
        PublicRoute=Get-SelectedRoute $PublicAddress
        LanRoute=Get-SelectedRoute '192.0.2.222'
        DnsRoute=Get-SelectedRoute '8.8.8.8'
        DefaultRoutes=@(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
            Select-Object AddressFamily,DestinationPrefix,InterfaceIndex,InterfaceAlias,NextHop,RouteMetric)
        Interfaces=@(Get-NetIPInterface | Select-Object AddressFamily,InterfaceIndex,InterfaceAlias,ConnectionState,InterfaceMetric)
        DnsServers=@(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    }
}

function Invoke-VpnPublicWebProbe([switch]$IPv4Only, [switch]$IPv6Only) {
    if ($IPv4Only -and $IPv6Only) { throw 'Choose only one IP address family.' }
    $curl = Join-Path $env:WINDIR 'System32\curl.exe'
    $arguments = '--noproxy "*" --connect-timeout 5 --max-time 12 --fail --silent --show-error --output NUL --write-out "%{json}" https://www.baidu.com/'
    if ($IPv4Only) { $arguments = '--ipv4 ' + $arguments }
    if ($IPv6Only) { $arguments = '--ipv6 ' + $arguments }
    $process = Invoke-BoundedProcess $curl $arguments 15
    $parsed = $null
    try { $parsed = $process.Output | ConvertFrom-Json } catch {}
    [pscustomobject]@{
        IPv4Only=[bool]$IPv4Only; IPv6Only=[bool]$IPv6Only;
        Passed=($process.ExitCode -eq 0 -and $parsed.http_code -ge 200 -and $parsed.http_code -lt 400)
        ExitCode=$process.ExitCode; Status=$parsed.http_code; LocalAddress=$parsed.local_ip;
        RemoteAddress=$parsed.remote_ip; DownloadBytes=$parsed.size_download;
        Seconds=$parsed.time_total; Error=$process.ErrorOutput
    }
}

function Test-VpnFullTunnelRouteEvidence($Diagnostics, $Routes, $WebIPv4, $WebAutomatic) {
    $failures = [System.Collections.Generic.List[string]]::new()
    if (!$Routes.VpnInterfaceIndex) { $failures.Add('The VPN IPv4 interface is missing.') }
    foreach ($name in @('PublicRoute','DnsRoute')) {
        $route = $Routes.$name
        if (!$route -or $route.Error -or $route.InterfaceIndex -ne $Routes.VpnInterfaceIndex) {
            $failures.Add($name + ' does not select the VPN interface.')
        }
    }
    $lan = $Routes.LanRoute
    # The full-tunnel acceptance profile explicitly allows the physical local subnet.
    $localLanBypass = $lan -and !$lan.Error -and $lan.NextHop -eq '0.0.0.0' -and
        $lan.DestinationPrefix -eq '192.0.2.0/24' -and $lan.SourceAddress -like '192.0.2.*'
    if (!$lan -or $lan.Error -or ($lan.InterfaceIndex -ne $Routes.VpnInterfaceIndex -and !$localLanBypass)) {
        $failures.Add('LanRoute is neither VPN-routed nor on the explicitly excluded physical LAN.')
    }
    if (!$Routes.ServerRoute -or $Routes.ServerRoute.Error -or
        $Routes.ServerRoute.InterfaceIndex -eq $Routes.VpnInterfaceIndex -or
        $Routes.ServerRoute.SourceAddress -ne $Diagnostics.LocalIPv4) {
        $failures.Add('The encrypted server transport is not on the current physical path.')
    }
    if ($Diagnostics.TransportInterfacePinned -and
        (!$Diagnostics.UnderlayInterfaceIndex -or $Routes.ServerRoute.InterfaceIndex -ne $Diagnostics.UnderlayInterfaceIndex)) {
        $failures.Add('The route lookup does not match the actual native socket interface override.')
    }
    foreach ($web in @($WebIPv4,$WebAutomatic)) {
        if (!$web.Passed -or $web.LocalAddress -ne $Diagnostics.VirtualIPv4) {
            $failures.Add('An ordinary public web request failed or bypassed the VPN; IPv4Only=' + $web.IPv4Only)
        }
    }
    [pscustomobject]@{ Passed=($failures.Count -eq 0); Failures=$failures.ToArray() }
}
