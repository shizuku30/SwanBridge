#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\MobikeEvidence.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\MobikeServerEvidence.ps1')
function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL '+$Description) }
    Write-Output ('PASS '+$Description)
}
$before = [pscustomobject]@{
    ChannelUp=$true; EngineRunning=$true; Authenticated=$true; ChildSaUp=$true; MobikeEnabled=$true; MobikeNegotiated=$true;
    SessionId='session1'; ConnectedAt='2026-10-24T12:00:00Z'; VirtualIPv4='10.0.0.2'; ServerIPv4='198.51.100.1';
    IkeUniqueId=1; IkeSpiInitiator='18446744073709551614'; IkeSpiResponder='18446744073709551613'; ChildSpiIn=123; ChildSpiOut=456;
    MobikePending=$false; MobikeError=0; MobikeAttempts=0; MobikeCompleted=0; MobikeProbesCompleted=0; MobikeUpdatesSent=0;
    MobikeUpdatesAcked=0; MobikeSaUpdates=0; MobikeNetworkChanges=0; LocalIPv4='192.0.2.10'; MobikeVerifiedLocalIPv4='192.0.2.10';
    EspTx=10; EspRx=10; PlainRx=10
}
$after = $before | ConvertTo-Json | ConvertFrom-Json
$after.MobikeAttempts=1; $after.MobikeCompleted=1; $after.MobikeUpdatesSent=1; $after.MobikeUpdatesAcked=1
$after.MobikeSaUpdates=2; $after.MobikeNetworkChanges=1; $after.LocalIPv4='192.0.2.20'; $after.MobikeVerifiedLocalIPv4=$after.LocalIPv4
$after.EspTx=20; $after.EspRx=20; $after.PlainRx=20
Check (Test-MobikeEvidence $before $after).Passed 'same-SA confirmed migration with protected traffic accepted'
foreach ($key in @('SessionId','ConnectedAt','VirtualIPv4','ServerIPv4','IkeUniqueId','IkeSpiInitiator','IkeSpiResponder','ChildSpiIn','ChildSpiOut')) {
    $copy = $after | ConvertTo-Json | ConvertFrom-Json
    $copy.$key='changed'
    Check (!(Test-MobikeEvidence $before $copy).Passed) ($key+' identity change cannot be disguised as mobility')
}
foreach ($key in @('ChannelUp','EngineRunning','Authenticated','ChildSaUp','MobikeEnabled','MobikeNegotiated')) {
    $copy = $after | ConvertTo-Json | ConvertFrom-Json; $copy.$key=$false
    Check (!(Test-MobikeEvidence $before $copy).Passed) ($key+' must remain true')
}
$copy = $after | ConvertTo-Json | ConvertFrom-Json; $copy.MobikePending=$true
Check (!(Test-MobikeEvidence $before $copy).Passed) 'unconfirmed update rejected'
$copy.MobikePending=$false; $copy.MobikeError=5
Check (!(Test-MobikeEvidence $before $copy).Passed) 'failed SA update rejected'
$copy = $after | ConvertTo-Json | ConvertFrom-Json; $copy.MobikeUpdatesAcked=0
Check (!(Test-MobikeEvidence $before $copy).Passed) 'sent update without acknowledgement rejected'
$copy = $after | ConvertTo-Json | ConvertFrom-Json; $copy.MobikeCompleted=0; $copy.MobikeProbesCompleted=1
Check (!(Test-MobikeEvidence $before $copy).Passed) 'probe-only success cannot pass real mobility'
Check (Test-MobikeEvidence $before $copy -ProbeOnly).Passed 'probe-only can satisfy transport preflight, distinctly labelled'
$copy = $after | ConvertTo-Json | ConvertFrom-Json; $copy.LocalIPv4=$before.LocalIPv4; $copy.MobikeVerifiedLocalIPv4=$before.LocalIPv4; $copy.MobikeNetworkChanges=0
Check (!(Test-MobikeEvidence $before $copy).Passed) 'unchanged physical network cannot pass migration'
$copy.MobikeNetworkChanges=1
Check (Test-MobikeEvidence $before $copy).Passed 'same private address on a different physical network is supported'
foreach ($key in @('EspTx','EspRx','PlainRx')) {
    $copy = $after | ConvertTo-Json | ConvertFrom-Json; $copy.$key=$before.$key
    Check (!(Test-MobikeEvidence $before $copy).Passed) ($key+' must show post-migration protected traffic')
}
$copy = $after | ConvertTo-Json | ConvertFrom-Json; $copy.PSObject.Properties.Remove('MobikeError')
Check (!(Test-MobikeEvidence $before $copy).Passed) 'missing diagnostics fail closed'

$serverBefore = [pscustomobject]@{ errors=@(); data=@([pscustomobject]@{ connection=[pscustomobject]@{
    version='2'; state='ESTABLISHED'; uniqueid='22'; 'remote-vips'=@('10.0.0.2');
    'remote-host'='192.0.2.10'; 'remote-port'='40000';
    'initiator-spi'='fffffffffffffffe'; 'responder-spi'='fffffffffffffffd';
    'child-sas'=[pscustomobject]@{ child=[pscustomobject]@{
        state='INSTALLED'; protocol='ESP'; encap='yes'; uniqueid='23'; reqid='1';
        'spi-in'='000001c8'; 'spi-out'='0000007b'; 'if-id-in'='0000002a'; 'if-id-out'='0000002a';
        'remote-ts'=@('10.0.0.2/32'); 'packets-in'='10'; 'packets-out'='11'
    } }
} }) }
$serverAfter = $serverBefore | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$serverAfter.data[0].connection.'remote-host'='198.51.100.10'
$serverAfter.data[0].connection.'remote-port'='50000'
$serverAfter.data[0].connection.'child-sas'.child.'packets-in'='20'
$serverAfter.data[0].connection.'child-sas'.child.'packets-out'='21'
Check (Test-MobikeServerEvidence $before $after $serverBefore $serverAfter).Passed 'server tuple, both SPI directions and protected counters confirm mobility'
$copy = $serverAfter | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$copy.data[0].connection.'remote-host'='192.0.2.10'; $copy.data[0].connection.'remote-port'='40000'
Check (!(Test-MobikeServerEvidence $before $after $serverBefore $copy).Passed) 'unchanged server tuple rejects misleading client ACK evidence'
$copy = $serverAfter | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$copy.data[0].connection.'initiator-spi'='0000000000000001'
Check (!(Test-MobikeServerEvidence $before $after $serverBefore $copy).Passed) 'server reauthentication cannot pass mobility'
$copy = $serverAfter | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$copy.data[0].connection.'child-sas'.child.'spi-in'='00000001'
Check (!(Test-MobikeServerEvidence $before $after $serverBefore $copy).Passed) 'server Child rekey cannot pass mobility'
$copy = $serverAfter | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$copy.data[0].connection.'child-sas'.child.'packets-out'='11'
Check (!(Test-MobikeServerEvidence $before $after $serverBefore $copy).Passed) 'server outbound encrypted traffic is required'
$copy = $serverAfter | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$copy.data[0].connection.'remote-vips'=@('10.0.0.99')
Check (!(Test-MobikeServerEvidence $before $after $serverBefore $copy).Passed) 'evidence from another client VIP is rejected'
