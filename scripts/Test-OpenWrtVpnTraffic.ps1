#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$requestedOutput = $OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$OutputDirectory = $requestedOutput
if (!$OutputDirectory) { $OutputDirectory = Join-Path $root ('build\acceptance\openwrt-traffic-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$result = [ordered]@{ Outcome = 'ERROR'; Accepted = $false; MobikeAccepted = $false; StartedAt = [DateTimeOffset]::Now.ToString('o') }
$code = 1
try {
    $family = (Get-AppxPackage -Name SwanBridge.Vpn).PackageFamilyName
    $before = Get-PackageDiagnostics $family
    if (!$before.ChannelUp -or !$before.EngineRunning -or !$before.Authenticated -or !$before.ChildSaUp -or
        [DateTimeOffset]::Parse($before.HeartbeatAt) -lt [DateTimeOffset]::Now.AddSeconds(-5)) { throw 'No fresh authenticated Windows VPN channel.' }
    $virtual = [Net.IPAddress]::Parse($before.VirtualIPv4)
    $interfaces = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $virtual.ToString())
    if ($interfaces.Count -ne 1 -or $interfaces[0].InterfaceAlias -ne 'SwanBridge-Acceptance-OpenWrt') { throw 'Only the separate OpenWrt acceptance profile is allowed.' }
    $result.Before = $before | Select-Object SessionId,ConnectedAt,VirtualIPv4,EspTx,EspRx,PlainTx,PlainRx,ChildSpiIn,ChildSpiOut,MobikeNegotiated
    $result.DnsAndOptionalPublicHttps = Test-WindowsVpnTraffic $virtual.ToString() -OpenWrtSplit
    $result.RouterIcmp = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\ping.exe') ('-S ' + $virtual + ' -n 3 -w 1500 10.77.0.1') 8
    $result.PublicIcmp = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\ping.exe') ('-S ' + $virtual + ' -n 3 -w 1500 8.8.8.8') 8
    $tcpResults = @()
    foreach ($target in @(@{ Address = '10.77.0.1'; Port = 80 }, @{ Address = '192.0.2.222'; Port = 3389 })) {
        $socket = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
        $async = $null
        try {
            $socket.Bind([Net.IPEndPoint]::new($virtual, 0))
            $socket.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]31,
                [Net.IPAddress]::HostToNetworkOrder([int]$interfaces[0].InterfaceIndex))
            $async = $socket.BeginConnect($target.Address, $target.Port, $null, $null)
            if (!$async.AsyncWaitHandle.WaitOne(5000)) { throw 'VPN-bound TCP connect timed out.' }
            $socket.EndConnect($async)
            $tcpResults += [pscustomobject]@{ Address = $target.Address; Port = $target.Port; Passed = $socket.Connected; Source = $socket.LocalEndPoint.ToString() }
        } finally {
            if ($async) { $async.AsyncWaitHandle.Close() }
            $socket.Dispose()
        }
    }
    $result.Tcp = $tcpResults
    Start-Sleep -Seconds 1
    $after = Get-PackageDiagnostics $family
    $result.After = $after | Select-Object SessionId,ConnectedAt,VirtualIPv4,EspTx,EspRx,PlainTx,PlainRx,ChildSpiIn,ChildSpiOut,MobikeNegotiated
    if ($after.SessionId -ne $before.SessionId -or !$after.ChannelUp -or !$after.ChildSaUp -or
        $after.EspTx -le $before.EspTx -or $after.EspRx -le $before.EspRx -or !$result.DnsAndOptionalPublicHttps.Dns.Passed -or
        $result.RouterIcmp.ExitCode -ne 0 -or $result.PublicIcmp.ExitCode -ne 0 -or
        [regex]::Matches($result.RouterIcmp.Output, 'TTL=\d+', 'IgnoreCase').Count -ne 3 -or
        [regex]::Matches($result.PublicIcmp.Output, 'TTL=\d+', 'IgnoreCase').Count -ne 3 -or
        @($tcpResults | Where-Object { !$_.Passed }).Count) {
        throw 'Bound Windows data-plane checks failed.'
    }
    $result.Accepted = $true
    $result.Outcome = 'PASS_WINDOWS_PSK_CHILD_DNS_ICMP_TCP_LAN_RDP'
    $code = 0
} catch { $result.Error = $_.Exception.Message }
finally {
    $result.CompletedAt = [DateTimeOffset]::Now.ToString('o')
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
$result | ConvertTo-Json -Depth 8
exit $code
