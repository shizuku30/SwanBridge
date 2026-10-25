#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Soak','Reconnect','Resume')][string]$Scenario = 'Soak',
    [ValidatePattern('^SwanBridge-Acceptance-[A-Za-z0-9_. -]+$')][string]$ProfileName,
    [ValidateRange(30,14400)][int]$DurationSeconds = 1800,
    [ValidateRange(5,300)][int]$ProbeIntervalSeconds = 15,
    [ValidateRange(0,600)][int]$IdleSeconds = 120,
    [ValidateRange(40,110)][int]$OutageSeconds = 70,
    [ValidateRange(30,300)][int]$RecoveryTimeoutSeconds = 90,
    [ValidateRange(60,7200)][int]$ResumeWaitSeconds = 1800,
    [ValidateRange(30,600)][int]$MinimumSuspendSeconds = 60,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$requestedProfile = $ProfileName
$requestedOutput = $OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$ProfileName = $requestedProfile
$OutputDirectory = $requestedOutput
$TimeoutSeconds = 30
$root = Split-Path -Parent $PSScriptRoot

function Set-AcceptanceValue([string]$Family, [string]$Key, [long]$Value) {
    $null = [Windows.Management.Core.ApplicationDataManager,Windows.Management.Core,ContentType=WindowsRuntime]
    $data = [Windows.Management.Core.ApplicationDataManager]::CreateForPackageFamily($Family)
    # Invoke the explicit projected IDictionary setter (PowerShell hides its indexer).
    $setter = [System.Collections.Generic.IDictionary[string,object]].GetMethod('set_Item')
    $null = $setter.Invoke($data.LocalSettings.Values, [object[]]@($Key, $Value))
}

function Get-SuspendEvidence([datetime]$Since) {
    $sleep = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=42; StartTime=$Since } -ErrorAction SilentlyContinue)
    $wake = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Power-Troubleshooter'; Id=1; StartTime=$Since } -ErrorAction SilentlyContinue)
    if (!$sleep.Count -or !$wake.Count -or $wake[0].TimeCreated -le $sleep[0].TimeCreated) { return $null }
    [xml]$xml = $sleep[0].ToXml()
    $state = @{}
    foreach ($item in $xml.Event.EventData.Data) { $state[[string]$item.Name] = [string]$item.'#text' }
    $sleepAt = [DateTimeOffset]$sleep[0].TimeCreated
    $wakeAt = [DateTimeOffset]$wake[0].TimeCreated
    $timingSource = 'EventCreationTime'
    if ($wake[0].PSObject.Methods['ToXml']) {
        [xml]$wakeXml = $wake[0].ToXml()
        $times = @{}
        foreach ($item in $wakeXml.Event.EventData.Data) { $times[[string]$item.Name] = [string]$item.'#text' }
        if ($times.SleepTime -and $times.WakeTime) {
            $sleepAt = [DateTimeOffset]::Parse($times.SleepTime)
            $wakeAt = [DateTimeOffset]::Parse($times.WakeTime)
            if ($wakeAt -le $sleepAt -or $sleepAt.LocalDateTime -lt $Since.AddSeconds(-1) -or
                [Math]::Abs(($sleep[0].TimeCreated-$sleepAt.LocalDateTime).TotalSeconds) -gt 120) { return $null }
            $timingSource = 'PowerTroubleshooterPayload'
        }
    }
    [pscustomobject]@{ SleepAt=$sleepAt.ToString('o'); WakeAt=$wakeAt.ToString('o');
        Seconds=($wakeAt-$sleepAt).TotalSeconds; TargetState=$state.TargetState; TimingSource=$timingSource;
        SleepEventRecordId=$sleep[0].RecordId; WakeEventRecordId=$wake[0].RecordId }
}

function Wait-EngineStopped([string]$Family, [int]$Seconds = 12) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        $d = Get-PackageDiagnostics $Family
        if (!$d.EngineRunning -and !$d.ChannelUp) { return $d }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'The selected VPN native engine did not finish stopping.'
}

function Connect-LifecycleSession($Context) {
    $started = [DateTimeOffset]::Now
    $connect = Invoke-RasControl $Context.ProfileName $Context.Phonebook
    if ($connect.ExitCode -ne 0) { throw ('RAS connection failed: ' + $connect.ExitCode + ' ' + $connect.Output) }
    $d = Get-PackageDiagnostics $Context.Family
    if (!$d.ChannelUp -or !$d.Authenticated -or !$d.ChildSaUp -or !$d.SessionId -or
        [DateTimeOffset]::Parse($d.ConnectedAt) -lt $started) { throw 'No freshly authenticated Windows VPN session.' }
    return $d
}

function Disconnect-LifecycleSession($Context) {
    $disconnect = Invoke-RasControl $Context.ProfileName $Context.Phonebook -Disconnect
    if ($disconnect.ExitCode -ne 0) { throw 'RAS disconnect failed for the selected acceptance profile.' }
    return Wait-EngineStopped $Context.Family
}

function Test-LifecycleTraffic($Context, [string]$ExpectedSession, [switch]$RetryTransient) {
    $failures = [System.Collections.Generic.List[object]]::new()
    $limit = $(if ($RetryTransient) { 2 } else { 1 })
    for ($attempt=1; $attempt -le $limit; $attempt++) {
    $before = Get-PackageDiagnostics $Context.Family
    if (!$before.ChannelUp -or !$before.ChildSaUp -or !$before.Authenticated) { throw 'The IKE/Child SA or Windows channel is down.' }
    if ($ExpectedSession -and $before.SessionId -ne $ExpectedSession) { throw 'An unexpected reconnection occurred during the soak/short outage.' }
    try {
        $traffic = Test-WindowsVpnTraffic $before.VirtualIPv4 -StaticContent
        if (!$traffic.Passed) { throw ('Bound Windows HTTPS failed: ' + $traffic.Https.Result.ErrorOutput) }
        break
    } catch {
        $failure = [pscustomobject]@{ At=[DateTimeOffset]::Now.ToString('o'); Error=$_.Exception.Message;
            SessionId=$before.SessionId; Traffic=$traffic; Diagnostics=(Get-PackageDiagnostics $Context.Family) }
        $failures.Add($failure)
        if ($OutputDirectory -and (Test-Path -LiteralPath $OutputDirectory)) {
            Write-JsonFile $failure (Join-Path $OutputDirectory 'last-probe-failure.json')
        }
        if ($attempt -eq $limit) { throw }
        Start-Sleep -Seconds 2
    }
    }
    Start-Sleep -Milliseconds 300
    $after = Get-PackageDiagnostics $Context.Family
    if ($after.WireUdpTx -le $before.WireUdpTx -or $after.WireUdpRx -le $before.WireUdpRx -or
        $after.PlainRx -le $before.PlainRx -or !$after.ChannelUp -or !$after.ChildSaUp) {
        throw 'Traffic did not produce bidirectional VPN wire/decryption counters.'
    }
    $hosts = @(Get-Process -Name 'SwanBridge.Host' -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Id=$_.Id; PrivateBytes=$_.PrivateMemorySize64; WorkingSet=$_.WorkingSet64; Handles=$_.HandleCount; Threads=$_.Threads.Count }
    })
    [pscustomobject]@{ At=[DateTimeOffset]::Now.ToString('o'); SessionId=$after.SessionId;
        Traffic=$traffic; Diagnostics=$after; Processes=$hosts; ProbeFailures=$failures.ToArray() }
}

function Repair-LifecycleSession($Context) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($RecoveryTimeoutSeconds)
    $attempts = 0
    $errors = @()
    do {
        $attempts++
        try {
            $null = Disconnect-LifecycleSession $Context
            $d = Connect-LifecycleSession $Context
            $sample = Test-LifecycleTraffic $Context $d.SessionId
            return [pscustomobject]@{ Mode='CommandSupervisorRedial'; Attempts=$attempts; Errors=$errors; Sample=$sample }
        } catch { $errors += $_.Exception.Message; Start-Sleep -Seconds 2 }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw ('Command-supervised VPN recovery failed: ' + ($errors -join '; '))
}

function Invoke-LifecycleAcceptance {
    if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1 for lifecycle acceptance.' }
    if (!$OutputDirectory) { $OutputDirectory = Join-Path $root ('build\acceptance\lifecycle-'+$Scenario.ToLower()+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')) }
    $null = New-Item -ItemType Directory -Force -Path $OutputDirectory
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $samples = [System.Collections.Generic.List[object]]::new()
    $result = [ordered]@{ Scenario=$Scenario; StartedAt=[DateTimeOffset]::Now.ToString('o'); Outcome='ERROR';
        Accepted=$false; OutputDirectory=$OutputDirectory; UiAutomationUsed=$false; ManualWindowsActionRequired=($Scenario -eq 'Resume') }
    $attempted = $false
    $context = $null
    $before = $null
    $mutex = $null
    $ownedMutex = $false
    $code = 1
    try {
        $package = Get-AppxPackage -Name SwanBridge.Vpn
        if (!$package) { throw 'SwanBridge.Vpn is not installed.' }
        $state = Join-Path $env:LOCALAPPDATA ('Packages\'+$package.PackageFamilyName+'\LocalState')
        $phonebook = Join-Path $state 'rasphone.pbk'
        $profiles = @(Get-PhonebookProfiles $phonebook | Where-Object { $_ -match '^SwanBridge-Acceptance-[A-Za-z0-9_. -]+$' })
        if (!$ProfileName) {
            if ($profiles.Count -ne 1) { throw 'Select exactly one SwanBridge acceptance profile.' }
            $ProfileName = $profiles[0]
        }
        if ($profiles -cnotcontains $ProfileName) { throw 'Only an existing SwanBridge-Acceptance-* profile may be tested.' }
        $context = [pscustomobject]@{ Family=$package.PackageFamilyName; ProfileName=$ProfileName; Phonebook=$phonebook }
        $mutex = [System.Threading.Mutex]::new($false, ('Local\SwanBridge.Lifecycle.'+$package.PackageFamilyName))
        try { $ownedMutex = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $ownedMutex = $true }
        if (!$ownedMutex) { throw 'Another lifecycle acceptance run already owns this package.' }
        $ras = Invoke-BoundedProcess (Join-Path $env:WINDIR 'System32\rasdial.exe') '' 10
        if ($ras.ExitCode -ne 0 -or $ras.Output.IndexOf($ProfileName,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'The selected profile is already active or RAS state is unavailable. It was not modified.'
        }
        $before = Get-NetworkSnapshot
        Write-JsonFile $before (Join-Path $OutputDirectory 'before.json')
        $result.PackageVersion = $package.Version.ToString()
        $result.ProfileName = $ProfileName
        $result.BootTimeBefore = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
        $attempted = $true
        $d = Connect-LifecycleSession $context
        $result.InitialSessionId = $d.SessionId
        $samples.Add((Test-LifecycleTraffic $context $d.SessionId))
        $start = [DateTimeOffset]::Now
        if ($Scenario -eq 'Soak') {
            $result.RequestedActiveSeconds = $DurationSeconds
            do {
                Write-JsonFile ([ordered]@{ Stage='Soak'; ElapsedSeconds=([DateTimeOffset]::Now-$start).TotalSeconds;
                    LastSample=$samples[$samples.Count-1] }) (Join-Path $OutputDirectory 'current.json')
                Start-Sleep -Seconds $ProbeIntervalSeconds
                $samples.Add((Test-LifecycleTraffic $context $d.SessionId -RetryTransient))
                Write-JsonFile $samples.ToArray() (Join-Path $OutputDirectory 'samples.json')
            } while (([DateTimeOffset]::Now-$start).TotalSeconds -lt $DurationSeconds)
            $result.ActiveSeconds = ([DateTimeOffset]::Now-$start).TotalSeconds
            Write-JsonFile ([ordered]@{ Stage='Idle'; IdleSeconds=$IdleSeconds }) (Join-Path $OutputDirectory 'current.json')
            if ($IdleSeconds) { Start-Sleep -Seconds $IdleSeconds }
            $samples.Add((Test-LifecycleTraffic $context $d.SessionId))
            $result.IdleSeconds = $IdleSeconds
            $failures = @($samples | ForEach-Object { $_.ProbeFailures })
            $result.ProbeFailureCount = $failures.Count
            $result.ProbeAttemptCount = $samples.Count + $failures.Count
            $result.ProbeSuccessRate = $samples.Count / [double]$result.ProbeAttemptCount
            if ($result.ProbeSuccessRate -lt 0.99) { throw 'Soak probe success rate was below 99 percent.' }
            $resources = @($samples | Where-Object { $_.Processes.Count -eq 1 })
            if ($resources.Count -ge 3) {
                $warm = $resources[[Math]::Min(4, $resources.Count-1)].Processes[0]
                $last = $resources[-1].Processes[0]
                $result.Resources = [ordered]@{ WarmPrivateBytes=$warm.PrivateBytes; FinalPrivateBytes=$last.PrivateBytes;
                    PrivateGrowthBytes=($last.PrivateBytes-$warm.PrivateBytes); FinalHandles=$last.Handles;
                    FinalThreads=$last.Threads; SameHostProcess=($warm.Id -eq $last.Id) }
                if ($DurationSeconds -ge 300 -and (!$result.Resources.SameHostProcess -or $result.Resources.PrivateGrowthBytes -gt 64MB)) {
                    throw 'Soak resource growth exceeded the bounded 64 MiB allowance or the host restarted.'
                }
            }
            $result.Outcome = 'PASS_SOAK_AND_IDLE_TRAFFIC'
        } elseif ($Scenario -eq 'Reconnect') {
            if (!$d.AcceptanceHooksEnabled) { throw 'Rebuild the development package with -AcceptanceHooks for scoped UDP-loss tests.' }
            $lease = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeMilliseconds()
            Set-AcceptanceValue $context.Family 'AcceptanceLeaseExpiresMs' $lease
            Set-AcceptanceValue $context.Family 'AcceptanceDropUntilMs' ([DateTimeOffset]::UtcNow.AddSeconds(12).ToUnixTimeMilliseconds())
            Start-Sleep -Milliseconds 250
            $blocked = $false
            try { $null = Test-WindowsVpnTraffic $d.VirtualIPv4 } catch { $blocked = $true }
            if (!$blocked) { throw 'Scoped packet loss did not block bound Windows traffic.' }
            Start-Sleep -Seconds 8
            Set-AcceptanceValue $context.Family 'AcceptanceDropUntilMs' 0
            Start-Sleep -Seconds 1
            $samples.Add((Test-LifecycleTraffic $context $d.SessionId))
            $result.ShortOutage = [ordered]@{ TrafficBlocked=$blocked; SameSessionRecovered=$true; Sample=$samples[$samples.Count-1] }
            $dropBefore = Get-PackageDiagnostics $context.Family
            $until = [DateTimeOffset]::UtcNow.AddSeconds($OutageSeconds)
            Set-AcceptanceValue $context.Family 'AcceptanceDropUntilMs' $until.ToUnixTimeMilliseconds()
            $downSeen = $false
            $downAt = $null
            $faultObserved = $false
            $previous = $dropBefore
            do {
                Start-Sleep -Seconds 1
                $during = Get-PackageDiagnostics $context.Family
                if (($during.SessionId -eq $previous.SessionId -and $during.FaultDropTx -gt $previous.FaultDropTx) -or
                    ($during.SessionId -ne $previous.SessionId -and $during.FaultDropTx -gt 0)) { $faultObserved=$true }
                $previous=$during
                if (!$during.EngineRunning -and !$during.ChannelUp) { $downSeen=$true; if (!$downAt) { $downAt=[DateTimeOffset]::Now.ToString('o') } }
                Write-JsonFile ([ordered]@{ Stage='ScopedUdpOutage'; Until=$until.ToString('o'); Diagnostics=$during }) (Join-Path $OutputDirectory 'current.json')
            } while ([DateTimeOffset]::UtcNow -lt $until)
            Set-AcceptanceValue $context.Family 'AcceptanceDropUntilMs' 0
            $result.LongOutage = [ordered]@{ Seconds=$OutageSeconds; DownSeen=$downSeen; DownAt=$downAt;
                FaultObserved=$faultObserved; Diagnostics=$during }
            if (!$downSeen) { throw 'DPD expiry did not remove the stale Windows VPN channel/engine.' }
            if (!$faultObserved) { throw 'The long outage did not exercise scoped packet loss.' }
            $recoverStart = [DateTimeOffset]::Now
            $result.Recovery = Repair-LifecycleSession $context
            $result.RecoverySeconds = ([DateTimeOffset]::Now-$recoverStart).TotalSeconds
            if ($result.RecoverySeconds -gt $RecoveryTimeoutSeconds) { throw 'Command recovery exceeded its deadline.' }
            if ($result.Recovery.Sample.SessionId -eq $d.SessionId) { throw 'Recovery did not authenticate a fresh IKE/Child session.' }
            $samples.Add($result.Recovery.Sample)
            $result.Outcome = 'PASS_SCOPED_OUTAGE_AND_COMMAND_REDIAL'
        } else {
            $result.ResumeStageStarted = [DateTimeOffset]::Now.ToString('o')
            $since = Get-Date
            Write-JsonFile ([ordered]@{ Stage='AwaitingRealSuspend'; ReadyAt=$since.ToString('o'); InitialSessionId=$d.SessionId;
                Instructions='Hibernate or sleep Windows, wait at least 60 seconds, then wake the same machine.' }) (Join-Path $OutputDirectory 'current.json')
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds($ResumeWaitSeconds)
            $evidence = $null
            do { Start-Sleep -Seconds 2; $evidence=Get-SuspendEvidence $since } while (!$evidence -and [DateTimeOffset]::UtcNow -lt $deadline)
            if (!$evidence -or $evidence.Seconds -lt $MinimumSuspendSeconds) {
                throw 'No real Windows suspend/resume event pair meeting the minimum duration was recorded.'
            }
            $result.SuspendEvidence = $evidence
            $result.BootTimeAfter = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
            if ($result.BootTimeBefore -ne $result.BootTimeAfter) { throw 'A reboot is not a suspend/resume test.' }
            $recoverStart = [DateTimeOffset]::Now
            try { $sample=Test-LifecycleTraffic $context ''; $result.ResumeRecoveryMode='ExistingOrPlatformSession' }
            catch { $result.InitialResumeFailure=$_.Exception.Message; $result.Recovery=Repair-LifecycleSession $context;
                $sample=$result.Recovery.Sample; $result.ResumeRecoveryMode='CommandSupervisorRedial' }
            $samples.Add($sample)
            $result.RecoverySeconds = ([DateTimeOffset]::Now-$recoverStart).TotalSeconds
            if ($result.RecoverySeconds -gt $RecoveryTimeoutSeconds) { throw 'Resume recovery exceeded its deadline.' }
            $result.WakeToVerifiedTrafficSeconds = ([DateTimeOffset]::Parse($sample.At)-[DateTimeOffset]::Parse($evidence.WakeAt)).TotalSeconds
            $result.ManualWindowsActionRequired = $false
            $result.Outcome = 'PASS_REAL_SUSPEND_RESUME_TRAFFIC'
        }
        $result.Accepted=$true
        $code=0
    } catch { $result.Error=$_.Exception.Message; $result.Outcome='ERROR' }
    finally {
        if ($attempted) {
            try {
                Set-AcceptanceValue $context.Family 'AcceptanceDropUntilMs' 0
                Set-AcceptanceValue $context.Family 'AcceptanceLeaseExpiresMs' 0
            } catch { $result.FaultCleanupError=$_.Exception.Message; $result.Outcome='CLEANUP_FAILED'; $code=1 }
            try {
                $result.FinalDiagnostics=Disconnect-LifecycleSession $context
                $after=Get-NetworkSnapshot
                $difference=Get-SnapshotDifference $before $after
                $result.NetworkUnchanged=Test-SnapshotUnchanged $difference
                $result.NetworkDifference=$difference
                Write-JsonFile $after (Join-Path $OutputDirectory 'after.json')
                if (!$result.NetworkUnchanged) { throw 'Network state was not restored after the lifecycle test.' }
            } catch { $result.CleanupError=$_.Exception.Message; $result.Outcome='CLEANUP_FAILED'; $code=1 }
        }
        if ($ownedMutex) { $mutex.ReleaseMutex() }
        if ($mutex) { $mutex.Dispose() }
        $result.SampleCount=$samples.Count
        $result.CompletedAt=[DateTimeOffset]::Now.ToString('o')
        $result.ExitCode=$code
        if ($code -ne 0) { $result.Accepted=$false }
        Write-JsonFile $samples.ToArray() (Join-Path $OutputDirectory 'samples.json')
        Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
    }
    $result | ConvertTo-Json -Depth 12
    return $code
}

if ($MyInvocation.InvocationName -ne '.') {
    $output=@(Invoke-LifecycleAcceptance)
    $code=[int]$output[-1]
    $output | Select-Object -SkipLast 1
    exit $code
}
