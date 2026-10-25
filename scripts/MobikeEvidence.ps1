#Requires -Version 5.1

function Test-MobikeEvidence($Before, $After, [switch]$ProbeOnly) {
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($sample in @($Before,$After)) {
        foreach ($key in @('ChannelUp','EngineRunning','Authenticated','ChildSaUp','MobikeEnabled','MobikeNegotiated')) {
            if ($sample.$key -ne $true) { $failures.Add($key + ' is not true') }
        }
    }
    foreach ($key in @('SessionId','ConnectedAt','VirtualIPv4','ServerIPv4','IkeUniqueId',
        'IkeSpiInitiator','IkeSpiResponder','ChildSpiIn','ChildSpiOut')) {
        if (!$Before.$key -or !$After.$key -or [string]$Before.$key -cne [string]$After.$key) {
            $failures.Add($key + ' changed or is absent; a redial/rekey is not MOBIKE acceptance')
        }
    }
    foreach ($key in @('MobikeAttempts','MobikeCompleted','MobikeProbesCompleted','MobikeUpdatesSent',
        'MobikeUpdatesAcked','MobikeSaUpdates','MobikeNetworkChanges','EspTx','EspRx','PlainRx')) {
        if ($null -eq $Before.$key -or $null -eq $After.$key -or $After.$key -lt $Before.$key) {
            $failures.Add($key + ' is absent or regressed')
        }
    }
    if ($After.MobikePending -ne $false -or $null -eq $After.MobikeError -or $After.MobikeError -ne 0) {
        $failures.Add('Migration is unconfirmed or failed')
    }
    if ($After.MobikeVerifiedLocalIPv4 -ne $After.LocalIPv4 -or !$After.LocalIPv4) {
        $failures.Add('Verified local endpoint does not match the current transport')
    }
    if ($ProbeOnly) {
        if (($After.MobikeCompleted + $After.MobikeProbesCompleted) -le ($Before.MobikeCompleted + $Before.MobikeProbesCompleted)) {
            $failures.Add('No new validated path probe')
        }
    } else {
        if ($After.MobikeCompleted -le $Before.MobikeCompleted -or
            $After.MobikeUpdatesSent -le $Before.MobikeUpdatesSent -or $After.MobikeUpdatesAcked -le $Before.MobikeUpdatesAcked) {
            $failures.Add('No newly confirmed UPDATE_SA_ADDRESSES exchange; probe-only is insufficient')
        }
        if ($After.LocalIPv4 -eq $Before.LocalIPv4 -and $After.MobikeNetworkChanges -le $Before.MobikeNetworkChanges) {
            $failures.Add('No observed physical network/path change')
        }
    }
    foreach ($key in @('EspTx','EspRx','PlainRx')) {
        if ($After.$key -le $Before.$key) { $failures.Add($key + ' did not increase with protected application traffic') }
    }
    [pscustomobject]@{ Passed=($failures.Count -eq 0); ProbeOnly=[bool]$ProbeOnly; Failures=$failures.ToArray() }
}
