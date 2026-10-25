#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Probe','Watch')][string]$Mode = 'Watch',
    [ValidateSet('SwanBridge-Acceptance-MOBIKE','SwanBridge-Acceptance-Split')][string]$ProfileName = 'SwanBridge-Acceptance-MOBIKE',
    [ValidateRange(60,7200)][int]$WaitSeconds = 1200,
    [ValidateRange(1,10)][int]$Migrations = 2,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$requestedOutput = $OutputDirectory
$requestedProfile = $ProfileName
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
. (Join-Path $PSScriptRoot 'MobikeEvidence.ps1')
$OutputDirectory = $requestedOutput
$ProfileName = $requestedProfile

function Set-MobikeAcceptanceValue([string]$Family, [string]$Key, [object]$Value) {
    $null = [Windows.Management.Core.ApplicationDataManager,Windows.Management.Core,ContentType=WindowsRuntime]
    $data = [Windows.Management.Core.ApplicationDataManager]::CreateForPackageFamily($Family)
    $setter = [System.Collections.Generic.IDictionary[string,object]].GetMethod('set_Item')
    $null = $setter.Invoke($data.LocalSettings.Values, [object[]]@($Key,$Value))
}

function Get-MobikeSnapshot([string]$Family) {
    Get-PackageDiagnostics $Family | Select-Object ChannelUp,EngineRunning,Authenticated,ChildSaUp,
        SessionId,ConnectedAt,HeartbeatAt,VirtualIPv4,ServerIPv4,LocalIPv4,LocalUdpPort,IkeUniqueId,
        IkeSpiInitiator,IkeSpiResponder,ChildSpiIn,ChildSpiOut,MobikeEnabled,MobikeNegotiated,MobikePending,
        MobikeAttempts,MobikeCompleted,MobikeProbesCompleted,MobikeUpdatesSent,MobikeUpdatesAcked,
        MobikeSaUpdates,MobikeNetworkChanges,MobikeError,MobikeVerifiedLocalIPv4,MobikeValidatedAt,
        MobikeProbeConsumed,MobikeFailure,MobikeFailureHresult,MobikeTransportStage,AcceptanceHooksEnabled,EspTx,EspRx,PlainTx,PlainRx,
        WireUdpTx,WireUdpRx,StaleTransportRx,ActiveTransportContext,LastEvent,LastEventTime,LastError,EngineLog
}

function Test-MobikeTraffic([string]$VirtualIPv4) {
    if ($ProfileName -ne 'SwanBridge-Acceptance-Split') { return Test-WindowsVpnTraffic $VirtualIPv4 -StaticContent }
    $path = Join-Path $OutputDirectory ('traffic-' + [guid]::NewGuid().ToString('N'))
    $shell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Invoke-BoundedProcess $shell ('-NoProfile -ExecutionPolicy Bypass -File "' +
        (Join-Path $PSScriptRoot 'Test-SplitVpnTraffic.ps1') + '" -OutputDirectory "' + $path + '"') 40
    $report = $null
    if (Test-Path -LiteralPath (Join-Path $path 'result.json')) { $report = Get-Content -LiteralPath (Join-Path $path 'result.json') -Raw -Encoding UTF8 | ConvertFrom-Json }
    [pscustomobject]@{ Passed = ($process.ExitCode -eq 0 -and $report.Accepted -and $report.After.VirtualIPv4 -eq $VirtualIPv4); Report = $report; Process = $process }
}

function Invoke-MobikeAcceptance {
    if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1.' }
    if (!$OutputDirectory) { $OutputDirectory = Join-Path $root ('build\acceptance\mobike-'+$Mode.ToLower()+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')) }
    $null = New-Item -ItemType Directory -Force -Path $OutputDirectory
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $result = [ordered]@{ Mode=$Mode; StartedAt=[DateTimeOffset]::Now.ToString('o'); Outcome='ERROR';
        Accepted=$false; UiAutomationUsed=$false; RedialAllowed=$false; OutputDirectory=$OutputDirectory }
    $code = 1; $token = $null; $mutex = $null; $owned = $false
    $legs = [System.Collections.Generic.List[object]]::new()
    try {
        $package = Get-AppxPackage -Name SwanBridge.Vpn
        if (!$package) { throw 'SwanBridge.Vpn is not installed.' }
        $family = $package.PackageFamilyName
        $mutex = [System.Threading.Mutex]::new($false, ('Local\SwanBridge.Lifecycle.'+$family))
        try { $owned = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
        if (!$owned) { throw 'Another acceptance run owns this package.' }
        $ras = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' 10
        if ($ras.ExitCode -ne 0 -or $ras.Output.IndexOf($ProfileName,[StringComparison]::Ordinal) -lt 0) {
            throw 'Connect the separate MOBIKE acceptance profile first. No session was changed.'
        }
        $before = Get-MobikeSnapshot $family
        if (!$before.ChannelUp -or !$before.MobikeEnabled -or !$before.MobikeNegotiated -or $before.MobikePending -or
            $before.MobikeError -ne 0 -or [DateTimeOffset]::Parse($before.HeartbeatAt) -lt [DateTimeOffset]::Now.AddSeconds(-5)) {
            throw 'A fresh, authenticated, negotiated MOBIKE session is required.'
        }
        $result.PackageVersion = $package.Version.ToString(); $result.ProfileName = $ProfileName
        $result.InitialTraffic = Test-MobikeTraffic $before.VirtualIPv4
        if (!$result.InitialTraffic.Passed) { throw 'Initial VPN-bound Windows DNS/HTTPS failed.' }
        $before = Get-MobikeSnapshot $family
        $result.Before = $before
        Write-JsonFile (Get-NetworkSnapshot) (Join-Path $OutputDirectory 'network-before.json')
        if ($Mode -eq 'Probe') {
            if (!$before.AcceptanceHooksEnabled) { throw 'Bounded transport preflight requires an acceptance build.' }
            $token = [guid]::NewGuid().ToString('N')
            Set-MobikeAcceptanceValue $family 'AcceptanceMobikeProbeExpiresMs' ([DateTimeOffset]::UtcNow.AddSeconds(60).ToUnixTimeMilliseconds())
            Set-MobikeAcceptanceValue $family 'AcceptanceMobikeProbeToken' $token
            $result.ProbeTrigger = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\ping.exe') ('-S '+$before.VirtualIPv4+' -n 1 -w 1500 10.77.0.1') 4
            $seconds = 50
        } else { $seconds = $WaitSeconds }
        $started = [DateTimeOffset]::Now; $deadline = $started.AddSeconds($seconds)
        Write-JsonFile ([ordered]@{ Stage='Armed'; Mode=$Mode; At=$started.ToString('o'); Deadline=$deadline.ToString('o');
            SessionId=$before.SessionId; VirtualIPv4=$before.VirtualIPv4; ServerIPv4=$before.ServerIPv4; LocalIPv4=$before.LocalIPv4 }) (Join-Path $OutputDirectory 'ready.json')
        do {
            Start-Sleep -Seconds 1
            $after = Get-MobikeSnapshot $family
            Write-JsonFile $after (Join-Path $OutputDirectory 'current.json')
            [System.IO.File]::AppendAllText((Join-Path $OutputDirectory 'samples.jsonl'),
                (($after | ConvertTo-Json -Compress -Depth 4)+[Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))
            if ($after.MobikeNetworkChanges -ne $lastNetworkChanges) {
                $lastNetworkChanges=$after.MobikeNetworkChanges
                Write-JsonFile (Get-NetworkSnapshot) (Join-Path $OutputDirectory ('network-path-'+$lastNetworkChanges+'.json'))
            }
            if ($after.SessionId -ne $before.SessionId -or !$after.ChannelUp -or !$after.ChildSaUp -or !$after.Authenticated) {
                throw 'The original session was lost or replaced. No redial was attempted; this cannot pass MOBIKE.'
            }
            if ($after.MobikeError) { throw ('MOBIKE failed, native code '+$after.MobikeError) }
            $progress = $(if ($Mode -eq 'Probe') {
                $after.MobikeProbeConsumed -eq $token -and ($after.MobikeCompleted+$after.MobikeProbesCompleted) -gt ($before.MobikeCompleted+$before.MobikeProbesCompleted)
            } else { $after.MobikeCompleted -gt $before.MobikeCompleted })
            if ($progress -and !$after.MobikePending) {
                try {
                    $traffic = Test-MobikeTraffic $before.VirtualIPv4
                    if (!$traffic.Passed) { throw 'Post-migration VPN-bound HTTPS failed.' }
                    Start-Sleep -Milliseconds 350
                    $after = Get-MobikeSnapshot $family
                    $evidence = Test-MobikeEvidence $before $after -ProbeOnly:($Mode -eq 'Probe')
                    if (!$evidence.Passed) { throw ($evidence.Failures -join '; ') }
                    $result.Traffic = $traffic; $result.Evidence = $evidence; $result.After = $after
                    $legs.Add([pscustomobject]@{ At=[DateTimeOffset]::Now.ToString('o'); Before=$before; After=$after; Evidence=$evidence; Traffic=$traffic })
                    Write-JsonFile $legs.ToArray() (Join-Path $OutputDirectory 'legs.json')
                    if ($Mode -eq 'Watch' -and $legs.Count -lt $Migrations) {
                        $before=$after
                        Write-JsonFile ([ordered]@{ Stage='WaitingForNextMigration'; ValidatedMigrations=$legs.Count;
                            TargetMigrations=$Migrations; LastLocalIPv4=$after.LocalIPv4; Deadline=$deadline.ToString('o') }) (Join-Path $OutputDirectory 'progress.json')
                        continue
                    }
                    # Local tuple metadata and an ACK cannot prove what reached the peer.
                    $result.ClientEvidencePassed = $true
                    $result.ServerEndpointVerified = $false
                    $result.Accepted = $false
                    $result.Outcome = 'CLIENT_EVIDENCE_PASSED_SERVER_ENDPOINT_VERIFICATION_REQUIRED'
                    $result.Seconds = ([DateTimeOffset]::Now-$started).TotalSeconds
                    $code = 2; break
                } catch {
                    $result.LastTrafficFailure = $_.Exception.Message
                    Write-JsonFile ([ordered]@{ At=[DateTimeOffset]::Now.ToString('o'); Error=$_.Exception.Message; Diagnostics=$after }) (Join-Path $OutputDirectory 'last-probe-failure.json')
                }
            }
        } while ([DateTimeOffset]::Now -lt $deadline)
        if (!$result.ClientEvidencePassed) { throw 'No validated MOBIKE migration within the bounded observation window.' }
    } catch { $result.Error = $_.Exception.Message }
    finally {
        if ($token) { try { Set-MobikeAcceptanceValue $family 'AcceptanceMobikeProbeExpiresMs' ([long]0) } catch { $result.HookCleanupError=$_.Exception.Message; $code=1; $result.Accepted=$false } }
        if ($family) { try { $result.Final = Get-MobikeSnapshot $family } catch {} }
        $result.Legs=$legs.ToArray()
        $result.CompletedAt=[DateTimeOffset]::Now.ToString('o'); $result.ExitCode=$code
        Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
        if ($owned) { $mutex.ReleaseMutex() }
        if ($mutex) { $mutex.Dispose() }
    }
    $result | ConvertTo-Json -Depth 12
    return $code
}

if ($MyInvocation.InvocationName -ne '.') {
    $output = @(Invoke-MobikeAcceptance)
    $code = [int]$output[-1]
    $output | Select-Object -SkipLast 1
    exit $code
}
