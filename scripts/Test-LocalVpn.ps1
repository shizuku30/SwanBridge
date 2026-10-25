#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Connect', 'Disconnect', 'Run', 'SaInit')]
    [string]$Action = 'Status',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')]
    [string]$Gateway,
    [ValidatePattern('^[\p{L}\p{N}_. -]{1,128}$')]
    [string]$ProfileName,
    [switch]$ExpectEngineUnavailable,
    [ValidateRange(3, 180)]
    [int]$TimeoutSeconds = 30,
    [switch]$SkipChecks,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Write-JsonFile($Value, [string]$Path) {
    [System.IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12),
        [System.Text.UTF8Encoding]::new($false))
}

function Get-NetworkSnapshot {
    [pscustomobject][ordered]@{
        CapturedAt = [DateTimeOffset]::Now.ToString('o')
        Adapters = @(Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceIndex,Status)
        Routes = @(Get-NetRoute | Select-Object AddressFamily,DestinationPrefix,InterfaceIndex,NextHop,RouteMetric,Protocol,PolicyStore)
        Dns = @(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
        IKEEXT = @(Get-CimInstance Win32_Service -Filter "Name='IKEEXT'" | Select-Object Name,State,StartMode)
    }
}

function Get-SnapshotDifference($Before, $After) {
    $difference = [ordered]@{}
    foreach ($section in @('Adapters', 'Routes', 'Dns', 'IKEEXT')) {
        $previous = @($Before.$section | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 6 })
        $current = @($After.$section | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 6 })
        $difference[$section] = [ordered]@{
            Added = @($current | Where-Object { $previous -cnotcontains $_ })
            Removed = @($previous | Where-Object { $current -cnotcontains $_ })
        }
    }
    [pscustomobject]$difference
}

function Test-SnapshotUnchanged($Difference) {
    foreach ($section in @('Adapters', 'Routes', 'Dns', 'IKEEXT')) {
        if ($Difference.$section.Added.Count -or $Difference.$section.Removed.Count) { return $false }
    }
    return $true
}

function Get-PackageDiagnostics([string]$FamilyName) {
    $null = [Windows.Management.Core.ApplicationDataManager,Windows.Management.Core,ContentType=WindowsRuntime]
    $data = [Windows.Management.Core.ApplicationDataManager]::CreateForPackageFamily($FamilyName)
    $diagnostics = [ordered]@{}
    foreach ($item in $data.LocalSettings.Values) {
        if ($item.Value -is [DateTimeOffset] -or $item.Value -is [DateTime]) {
            $diagnostics[$item.Key] = $item.Value.ToString('o')
        } else {
            $diagnostics[$item.Key] = $item.Value
        }
    }
    [pscustomobject]$diagnostics
}

function Wait-ConnectedDiagnostics([string]$FamilyName, [DateTimeOffset]$Started, [string]$PreviousSession) {
    $deadline=[DateTimeOffset]::Now.AddSeconds(12)
    do {
        $d=Get-PackageDiagnostics $FamilyName
        if ($d.ChannelUp -and $d.EngineRunning -and $d.Authenticated -and $d.ChildSaUp -and
            $d.SessionId -and $d.SessionId -ne $PreviousSession -and $d.ConnectedAt -and
            [DateTimeOffset]::Parse($d.ConnectedAt) -ge $Started -and $d.VirtualIPv4 -and
            @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $d.VirtualIPv4 -ErrorAction SilentlyContinue).Count -eq 1) { return $d }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::Now -lt $deadline)
    throw 'No fresh connected diagnostics and assigned Windows VPN address before the deadline.'
}

function Wait-FailureDiagnostics([string]$FamilyName, [DateTimeOffset]$Started) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds([Math]::Min(5, $TimeoutSeconds))
    do {
        $diagnostics = Get-PackageDiagnostics $FamilyName
        if ($diagnostics.LastEventTime -and $diagnostics.LastEvent -eq 'Disconnect' -and
            [DateTimeOffset]::Parse($diagnostics.LastEventTime) -ge $Started) { return $diagnostics }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $diagnostics
}

function Get-PhonebookProfiles([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        Get-Content -LiteralPath $Path | ForEach-Object {
            if ($_ -match '^\[([^\]]+)\]$') { $Matches[1] }
        }
    }
}

function Invoke-BoundedProcess([string]$FilePath, [string]$Arguments, [int]$Seconds) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $FilePath
    $info.Arguments = $Arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [System.Text.Encoding]::Default
    $info.StandardErrorEncoding = [System.Text.Encoding]::Default
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = !$process.WaitForExit($Seconds * 1000)
        if ($timedOut) {
            $process.Kill()
            $process.WaitForExit()
        }
        [pscustomobject][ordered]@{
            ExitCode = $(if ($timedOut) { 124 } else { $process.ExitCode })
            TimedOut = $timedOut
            Output = $stdout.GetAwaiter().GetResult()
            ErrorOutput = $stderr.GetAwaiter().GetResult()
        }
    } finally {
        $process.Dispose()
    }
}

function Invoke-RasControl([string]$Name, [string]$Phonebook, [switch]$Disconnect) {
    $arguments = '"' + $Name + '"'
    if ($Disconnect) {
        $arguments += ' /disconnect'
    } else {
        $arguments += ' "/phonebook:' + $Phonebook + '"'
    }
    Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') $arguments $TimeoutSeconds
}

function Test-DnsProbeReply([byte[]]$Query, [byte[]]$Reply, [int]$Count) {
    return $Query.Length -ge 2 -and $Count -ge 12 -and $Count -le $Reply.Length -and
        $Reply[0] -eq $Query[0] -and $Reply[1] -eq $Query[1] -and
        ($Reply[2] -band 128) -ne 0 -and ($Reply[3] -band 15) -eq 0 -and
        ($Reply[6] -ne 0 -or $Reply[7] -ne 0)
}

function Test-WindowsVpnTraffic([string]$VirtualIPv4, [switch]$StaticContent, [switch]$SplitTunnel, [string]$PinnedBaidu) {
    $address = [System.Net.IPAddress]::Parse($VirtualIPv4)
    if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'An IPv4 virtual address is required.' }
    $interfaces = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $VirtualIPv4 -ErrorAction Stop)
    if ($interfaces.Count -ne 1) { throw 'The negotiated address is not assigned to exactly one Windows interface.' }
    $interface = $interfaces[0]
    $socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
    try {
        $socket.ReceiveTimeout = 5000
        $socket.SendTimeout = 5000
        $socket.Bind([System.Net.IPEndPoint]::new($address, 0))
        $socket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP,
            [System.Net.Sockets.SocketOptionName]31,
            [int][System.Net.IPAddress]::HostToNetworkOrder([int]$interface.InterfaceIndex))
        $socket.Connect([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse('8.8.8.8'), 53))
        $id = Get-Random -Minimum 1 -Maximum 65536
        [byte[]]$query = @(($id -shr 8), ($id -band 255), 1,0,0,1,0,0,0,0,0,0,
            7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1)
        $null = $socket.Send($query)
        $reply = [byte[]]::new(4096)
        $count = $socket.Receive($reply)
        if (!(Test-DnsProbeReply $query $reply $count)) {
            throw 'The DNS response did not match the Windows application query.'
        }
        $dns = [pscustomobject]@{ Passed = $true; Source = $socket.LocalEndPoint.ToString();
            Destination = '8.8.8.8:53'; Query = 'example.com A'; ResponseBytes = $count }
    } finally { $socket.Dispose() }
    $curl = Join-Path $env:WINDIR 'System32\curl.exe'
    $httpsUrl = $(if ($StaticContent) { 'https://www.microsoft.com/favicon.ico' } else { 'https://www.microsoft.com' })
    $resolve = ''
    if ($SplitTunnel) {
        $httpsUrl = 'https://dns.google/resolve?name=example.com'
        $resolve = ' --resolve "dns.google:443:8.8.8.8"'
    }
    if ($PinnedBaidu) {
        $target=[System.Net.IPAddress]::Parse($PinnedBaidu)
        if ($target.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'The pinned HTTPS target must be IPv4.' }
        $httpsUrl='https://www.baidu.com/'
        $resolve=' --resolve "www.baidu.com:443:'+$target.ToString()+'"'
    }
    $https = Invoke-BoundedProcess $curl ('--ipv4 --noproxy "*" --interface ' + $VirtualIPv4 +
        ' --connect-timeout 5 --max-time 12 --fail --silent --show-error --location --output NUL' +
        $resolve + ' --write-out "status=%{http_code};local=%{local_ip};remote=%{remote_ip};bytes=%{size_download};connect=%{time_connect};tls=%{time_appconnect};firstByte=%{time_starttransfer};total=%{time_total}" ' + $httpsUrl) 14
    $httpsPassed = $https.ExitCode -eq 0 -and $https.Output -match '^status=2[0-9][0-9];local=([^;]+);' -and $Matches[1] -eq $VirtualIPv4
    [pscustomobject]@{ Passed = $httpsPassed; VirtualIPv4 = $VirtualIPv4; InterfaceIndex = $interface.InterfaceIndex;
        InterfaceAlias = $interface.InterfaceAlias; Dns = $dns;
        Https = [pscustomobject]@{ Passed = $httpsPassed; Destination = $httpsUrl; Result = $https } }
}

function Invoke-LocalVpn {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        throw 'Use Windows PowerShell: powershell.exe -NoProfile -File scripts\Test-LocalVpn.ps1'
    }
    if (!$OutputDirectory) {
        $OutputDirectory = Join-Path $root ('build\acceptance\runs\' +
            (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $result = [ordered]@{
        Action = $Action
        StartedAt = [DateTimeOffset]::Now.ToString('o')
        Outcome = 'ERROR'
        VpnFunctionAccepted = $false
        ManualWindowsConnectionRequired = $false
        UiAutomationUsed = $false
        OutputDirectory = $OutputDirectory
    }
    $exitCode = 1
    $before = $null
    $phonebook = $null
    $selectedProfile = $null
    $connectionAttempted = $false
    try {
        if ($Action -eq 'SaInit') {
            if (!$Gateway) { throw 'Specify -Gateway for the unauthenticated IKE_SA_INIT probe.' }
            $binary = Join-Path $root 'build\engine\SwanBridge.IkeProbe.exe'
            if (!(Test-Path -LiteralPath $binary)) { throw 'Run scripts\Build-Core.ps1 first.' }
            $before = Get-NetworkSnapshot
            Write-JsonFile $before (Join-Path $OutputDirectory 'before.json')
            try {
                $result.NativeProbe = Invoke-BoundedProcess $binary ('"' + $Gateway + '" 3000') $TimeoutSeconds
                if (!$result.NativeProbe.Output) { throw 'The native probe returned no JSON. Inspect NativeProbe error output.' }
                $result.Probe = $result.NativeProbe.Output | ConvertFrom-Json
                $result.Outcome = $result.Probe.Outcome
                $exitCode = $result.NativeProbe.ExitCode
            } finally {
                $after = Get-NetworkSnapshot
                Write-JsonFile $after (Join-Path $OutputDirectory 'after.json')
                $result.NetworkDifference = Get-SnapshotDifference $before $after
                $result.NetworkUnchanged = Test-SnapshotUnchanged $result.NetworkDifference
                if (!$result.NetworkUnchanged) {
                    $result.Outcome = 'NETWORK_STATE_CHANGED'
                    $exitCode = 1
                }
            }
        } else {
            $package = Get-AppxPackage -Name SwanBridge.Vpn
            if (!$package) { throw 'SwanBridge.Vpn is not installed for the current user.' }
            $result.PackageVersion = $package.Version.ToString()
            $result.PackageFamilyName = $package.PackageFamilyName
            $stateFolder = Join-Path $env:LOCALAPPDATA ('Packages\' + $package.PackageFamilyName + '\LocalState')
            $phonebook = Join-Path $stateFolder 'rasphone.pbk'
            $profiles = @(Get-PhonebookProfiles $phonebook)
            $result.Profiles = $profiles
            $result.Diagnostics = Get-PackageDiagnostics $package.PackageFamilyName
            if ($Action -eq 'Status') {
                $result.RasConnections = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' $TimeoutSeconds
                $result.Outcome = 'STATUS'
                $exitCode = 0
            } else {
                $selectedProfile = $ProfileName
                if (!$selectedProfile) {
                    if ($profiles.Count -ne 1) { throw 'Specify -ProfileName; the package must have exactly one profile for automatic selection.' }
                    $selectedProfile = $profiles[0]
                }
                if ($selectedProfile -notmatch '^[\p{L}\p{N}_. -]{1,128}$') { throw 'The profile name contains unsupported command-line characters.' }
                if ($profiles -cnotcontains $selectedProfile) { throw 'The selected profile does not exist in the SwanBridge phonebook. No connection was attempted.' }
                $result.ProfileName = $selectedProfile
                if ($Action -eq 'Disconnect') {
                    $result.Disconnect = Invoke-RasControl $selectedProfile $phonebook -Disconnect
                    if ($result.Disconnect.ExitCode -ne 0) { throw 'The disconnect command failed; inspect Disconnect output.' }
                    $result.Outcome = 'DISCONNECTED'
                    $exitCode = 0
                } else {
                    if ($Action -eq 'Run' -and !$SkipChecks) {
                        $runtime = Get-AppxPackage -Name Microsoft.VCLibs.140.00 |
                            Where-Object { [int]$_.Architecture -eq 9 } | Select-Object -First 1
                        if (!$runtime) { throw 'The x64 Microsoft.VCLibs.140.00 runtime is missing.' }
                        $oldPath = $env:PATH
                        try {
                            $env:PATH = $runtime.InstallLocation + ';' + $oldPath
                            $result.Checks = @()
                            foreach ($name in @('ContractTests', 'ProfileConfigurationTests', 'CredentialProbe', 'ActivationProbe', 'EngineAbiProbe')) {
                                $binary = Join-Path $root ('build\' + $name + '.exe')
                                if (!(Test-Path -LiteralPath $binary)) { throw ('Run scripts\Build.ps1 first; missing ' + $name) }
                                $arguments = ''
                                if ($name -eq 'ActivationProbe') {
                                    $plugin = Join-Path $root 'build\layout\SwanBridge.Plugin.dll'
                                    if ((Get-FileHash -LiteralPath $plugin).Hash -ne
                                        (Get-FileHash -LiteralPath (Join-Path $package.InstallLocation 'SwanBridge.Plugin.dll')).Hash) {
                                        throw 'The build-layout plugin differs from the installed plugin.'
                                    }
                                    $arguments = '"' + $plugin + '"'
                                }
                                if ($name -eq 'EngineAbiProbe') {
                                    $engine = Join-Path $root 'build\layout\SwanBridge.Engine.dll'
                                    if ((Get-FileHash -LiteralPath $engine).Hash -ne
                                        (Get-FileHash -LiteralPath (Join-Path $package.InstallLocation 'SwanBridge.Engine.dll')).Hash) {
                                        throw 'The build-layout engine differs from the installed engine.'
                                    }
                                    $arguments = '"' + $engine + '"'
                                }
                                $check = Invoke-BoundedProcess $binary $arguments $TimeoutSeconds
                                $result.Checks += [pscustomobject]@{ Name = $name; Result = $check }
                                if ($check.ExitCode -ne 0) { throw ('A prerequisite check failed: ' + $name) }
                            }
                            $testScript = Join-Path $root 'tests\LocalVpnScriptTests.ps1'
                            $check = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') (
                                '-NoProfile -ExecutionPolicy RemoteSigned -File "' + $testScript + '"') $TimeoutSeconds
                            $result.Checks += [pscustomobject]@{ Name = 'LocalVpnScriptTests'; Result = $check }
                            if ($check.ExitCode -ne 0) { throw 'Command-line acceptance script tests failed.' }
                        } finally { $env:PATH = $oldPath }
                    }
                    if ($Action -eq 'Run') {
                        $result.RasConnectionsBefore = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' $TimeoutSeconds
                        if ($result.RasConnectionsBefore.ExitCode -ne 0) { throw 'Cannot verify existing RAS connections.' }
                        if ($result.RasConnectionsBefore.Output.IndexOf($selectedProfile, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            throw 'The selected profile is already connected. Run refuses to disconnect a pre-existing session.'
                        }
                    }
                    $before = Get-NetworkSnapshot
                    Write-JsonFile $before (Join-Path $OutputDirectory 'before.json')
                    $started = [DateTimeOffset]::Now
                    $connectionAttempted = $true
                    $result.Connect = Invoke-RasControl $selectedProfile $phonebook
                    if ($result.Connect.ExitCode -eq 628) {
                        $result.Diagnostics = Wait-FailureDiagnostics $package.PackageFamilyName $started
                    } else {
                        $result.Diagnostics = Get-PackageDiagnostics $package.PackageFamilyName
                    }
                    $freshDiagnostic = $result.Diagnostics.LastEventTime -and
                        ([DateTimeOffset]::Parse($result.Diagnostics.LastEventTime) -ge $started)
                    $engineUnavailable = $result.Connect.ExitCode -eq 628 -and $freshDiagnostic -and
                        $result.Diagnostics.LastError -eq 'SB1001' -and $result.Diagnostics.LastEvent -eq 'Disconnect'
                    if ($ExpectEngineUnavailable) {
                        if (!$engineUnavailable) { throw 'Expected a fresh SB1001 after a controlled connection failure.' }
                        $result.Outcome = 'PASS_FAIL_CLOSED_ONLY'
                        $exitCode = 0
                    } elseif ($engineUnavailable) {
                        $result.Outcome = 'BLOCKED_ENGINE_UNAVAILABLE'
                        $exitCode = 2
                    } elseif ($result.Connect.ExitCode -eq 0) {
                        $result.Outcome = 'CONNECTED_TRAFFIC_UNVERIFIED'
                        $exitCode = $(if ($Action -eq 'Connect') { 0 } else { 2 })
                        if ($Action -eq 'Run') {
                            if (!$freshDiagnostic -or !$result.Diagnostics.ChannelUp -or
                                !$result.Diagnostics.Authenticated -or !$result.Diagnostics.ChildSaUp -or !$result.Diagnostics.VirtualIPv4) {
                                throw 'Windows connected without fresh authenticated Child SA/channel diagnostics.'
                            }
                            $initial = $result.Diagnostics
                            $result.Traffic = Test-WindowsVpnTraffic $result.Diagnostics.VirtualIPv4
                            if (!$result.Traffic.Passed) { throw 'Windows HTTPS through the virtual address failed; inspect Traffic.Https.' }
                            Start-Sleep -Milliseconds 300
                            $result.Diagnostics = Get-PackageDiagnostics $package.PackageFamilyName
                            if ($result.Diagnostics.EspTx -le $initial.EspTx -or $result.Diagnostics.EspRx -le $initial.EspRx -or
                                $result.Diagnostics.PlainRx -le $initial.PlainRx) {
                                throw 'Application traffic did not produce bidirectional encrypted and decrypted packet counters.'
                            }
                            $result.VpnFunctionAccepted = $true
                            $result.Outcome = 'PASS_WINDOWS_PROTECTED_TRAFFIC'
                            $exitCode = 0
                        }
                    } else {
                        $result.Outcome = 'CONNECTION_FAILED'
                        $result.ManualWindowsConnectionRequired = $null
                        $exitCode = 1
                    }
                }
            }
        }
    } catch {
        $result.Outcome = 'ERROR'
        $result.Error = $_.Exception.Message
        $result.ManualWindowsConnectionRequired = $null
        $exitCode = 1
    } finally {
        if ($connectionAttempted) {
            try { $result.DiagnosticsBeforeDisconnect = Get-PackageDiagnostics $package.PackageFamilyName } catch {}
            # Run always cleans up. Connect only leaves a successful connection active.
            if ($Action -eq 'Run' -or $result.Connect.ExitCode -ne 0) {
                try {
                    $result.Cleanup = Invoke-RasControl $selectedProfile $phonebook -Disconnect
                    if ($result.Cleanup.ExitCode -ne 0) { throw 'The cleanup disconnect command failed.' }
                    $result.RasConnectionsAfter = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' $TimeoutSeconds
                    if ($result.RasConnectionsAfter.ExitCode -ne 0 -or
                        $result.RasConnectionsAfter.Output.IndexOf($selectedProfile, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        throw 'Cannot confirm the selected connection was cleaned up.'
                    }
                    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(8)
                    do {
                        $result.DiagnosticsAfterDisconnect = Get-PackageDiagnostics $package.PackageFamilyName
                        if (!$result.DiagnosticsAfterDisconnect.ChannelUp -and !$result.DiagnosticsAfterDisconnect.EngineRunning) { break }
                        Start-Sleep -Milliseconds 100
                    } while ([DateTimeOffset]::UtcNow -lt $deadline)
                    if ($result.DiagnosticsAfterDisconnect.ChannelUp -or $result.DiagnosticsAfterDisconnect.EngineRunning) {
                        throw 'Windows disconnected but the native engine did not finish stopping.'
                    }
                } catch {
                    $result.CleanupError = $_.Exception.Message
                    $result.Outcome = 'CLEANUP_FAILED'
                    $exitCode = 1
                }
            }
            try {
                $deadline = [DateTimeOffset]::UtcNow.AddSeconds([Math]::Min(5, $TimeoutSeconds))
                do {
                    $after = Get-NetworkSnapshot
                    $result.NetworkDifference = Get-SnapshotDifference $before $after
                    $result.NetworkUnchanged = Test-SnapshotUnchanged $result.NetworkDifference
                    if ($result.NetworkUnchanged -or ($Action -eq 'Connect' -and $result.Connect.ExitCode -eq 0)) { break }
                    Start-Sleep -Milliseconds 200
                } while ([DateTimeOffset]::UtcNow -lt $deadline)
                Write-JsonFile $after (Join-Path $OutputDirectory 'after.json')
                if (($Action -eq 'Run' -or $result.Connect.ExitCode -ne 0) -and !$result.NetworkUnchanged) {
                    $result.Outcome = 'NETWORK_STATE_CHANGED'
                    $exitCode = 1
                }
            } catch {
                $result.NetworkError = $_.Exception.Message
                $result.Outcome = 'NETWORK_VERIFICATION_FAILED'
                $exitCode = 1
            }
        }
        $result.CompletedAt = [DateTimeOffset]::Now.ToString('o')
        $result.ExitCode = $exitCode
        if ($exitCode -ne 0) { $result.VpnFunctionAccepted = $false }
        Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
    }
    $result | ConvertTo-Json -Depth 12
    return $exitCode
}

if ($MyInvocation.InvocationName -ne '.') {
    $output = @(Invoke-LocalVpn)
    $code = [int]$output[-1]
    $output | Select-Object -SkipLast 1
    exit $code
}
