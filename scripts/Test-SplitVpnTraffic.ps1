#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory, [string[]]$IcmpTargets = @(), [string[]]$TcpTargets = @())
$ErrorActionPreference = 'Stop'
$requestedOutput = $OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$OutputDirectory = $requestedOutput

function ConvertTo-VpnTcpTarget([string]$Target) {
    if ($Target -notmatch '^([0-9.]+):([0-9]{1,5})$') { throw 'Use an IPv4 address and TCP port separated by a colon.' }
    $address = [Net.IPAddress]::Parse($Matches[1])
    $port = [int]$Matches[2]
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $port -lt 1 -or $port -gt 65535) {
        throw 'An IPv4 address and TCP port from 1 to 65535 are required.'
    }
    [pscustomobject]@{ Address = $address.ToString(); Port = $port }
}

function Invoke-SplitVpnTraffic {
    if (!$OutputDirectory) { $OutputDirectory = Join-Path $root ('build/acceptance/split-traffic-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    $null = New-Item -ItemType Directory -Force -Path $OutputDirectory
    $result = [ordered]@{ Outcome = 'ERROR'; Accepted = $false; MobikeAccepted = $false; StartedAt = [DateTimeOffset]::Now.ToString('o') }
    $code = 1
    try {
        $icmpAddresses = @($IcmpTargets | ForEach-Object {
            $address = [Net.IPAddress]::Parse($_)
            if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'ICMP targets must be IPv4 addresses.' }
            $address.ToString()
        })
        $tcpEndpoints = @($TcpTargets | ForEach-Object { ConvertTo-VpnTcpTarget $_ })
        $family = (Get-AppxPackage -Name SwanBridge.Vpn).PackageFamilyName
        $before = Get-PackageDiagnostics $family
        if (!$before.ChannelUp -or !$before.EngineRunning -or !$before.Authenticated -or !$before.ChildSaUp -or
            [DateTimeOffset]::Parse($before.HeartbeatAt) -lt [DateTimeOffset]::Now.AddSeconds(-5)) { throw 'No fresh authenticated Windows VPN channel.' }
        $virtual = [Net.IPAddress]::Parse($before.VirtualIPv4)
        $interfaces = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $virtual.ToString())
        if ($interfaces.Count -ne 1 -or $interfaces[0].InterfaceAlias -ne 'SwanBridge-Acceptance-Split') {
            throw 'Only the separate split-tunnel acceptance profile is allowed.'
        }
        $result.Before = $before | Select-Object SessionId,ConnectedAt,VirtualIPv4,EspTx,EspRx,PlainTx,PlainRx,ChildSpiIn,ChildSpiOut,MobikeNegotiated
        $result.DnsAndPublicHttps = Test-WindowsVpnTraffic $virtual.ToString() -SplitTunnel
        $result.Icmp = @($icmpAddresses | ForEach-Object {
            $reply = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32/ping.exe') ('-S ' + $virtual + ' -n 3 -w 1500 ' + $_) 8
            [pscustomobject]@{ Address = $_; Passed = ($reply.ExitCode -eq 0 -and [regex]::Matches($reply.Output, 'TTL=\d+', 'IgnoreCase').Count -eq 3); Result = $reply }
        })
        $result.Tcp = @($tcpEndpoints | ForEach-Object {
            $target = $_
            $socket = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
            $async = $null
            try {
                $socket.Bind([Net.IPEndPoint]::new($virtual, 0))
                $socket.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]31,
                    [Net.IPAddress]::HostToNetworkOrder([int]$interfaces[0].InterfaceIndex))
                $async = $socket.BeginConnect($target.Address, $target.Port, $null, $null)
                if (!$async.AsyncWaitHandle.WaitOne(5000)) { throw 'VPN-bound TCP connect timed out.' }
                $socket.EndConnect($async)
                [pscustomobject]@{ Address = $target.Address; Port = $target.Port; Passed = $socket.Connected; Source = $socket.LocalEndPoint.ToString() }
            } finally {
                if ($async) { $async.AsyncWaitHandle.Close() }
                $socket.Dispose()
            }
        })
        Start-Sleep -Seconds 1
        $after = Get-PackageDiagnostics $family
        $result.After = $after | Select-Object SessionId,ConnectedAt,VirtualIPv4,EspTx,EspRx,PlainTx,PlainRx,ChildSpiIn,ChildSpiOut,MobikeNegotiated
        if ($after.SessionId -ne $before.SessionId -or !$after.ChannelUp -or !$after.ChildSaUp -or
            $after.EspTx -le $before.EspTx -or $after.EspRx -le $before.EspRx -or !$result.DnsAndPublicHttps.Passed -or
            @($result.Icmp | Where-Object { !$_.Passed }).Count -or @($result.Tcp | Where-Object { !$_.Passed }).Count) {
            throw 'Bound Windows data-plane checks failed.'
        }
        $result.Accepted = $true
        $result.Outcome = 'PASS_WINDOWS_SPLIT_TRAFFIC'
        $code = 0
    } catch { $result.Error = $_.Exception.Message }
    finally {
        $result.CompletedAt = [DateTimeOffset]::Now.ToString('o')
        Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
    }
    $result | ConvertTo-Json -Depth 8
    return $code
}

if ($MyInvocation.InvocationName -ne '.') {
    $output = @(Invoke-SplitVpnTraffic)
    $code = [int]$output[-1]
    $output | Select-Object -SkipLast 1
    exit $code
}
