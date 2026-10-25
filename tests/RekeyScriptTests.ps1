#Requires -Version 5.1
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/RekeyEvidence.ps1')
function Check([bool]$Pass,[string]$Description) { if (!$Pass) { throw ('FAIL '+$Description) }; 'PASS '+$Description }
$samples=@(0..2|ForEach-Object {
    [pscustomobject]@{Authenticated=$true;ChildSaUp=$true;TrafficPassed=$true;IkeEstablishments=1;ChildEstablishments=1;
        VirtualIPv4='10.77.0.5';ChannelUp=$true;EngineRunning=$true;SessionId='same';ConnectedAt='same';
        IkeRekeysCompleted=$_;ChildRekeysCompleted=$_;IkeUniqueId=($_+1);IkeSpiInitiator=($_+11);IkeSpiResponder=($_+21);
        ChildUniqueId=($_+1);ChildSpiIn=($_+31);ChildSpiOut=($_+41);EspTx=($_+1);EspRx=($_+1)}
})
Check (Test-RekeyEvidence $samples -WindowsChannel).Passed 'inline IKE and repeated Child rekeys retain the Windows channel'
foreach ($key in @('Authenticated','ChildSaUp','TrafficPassed','ChannelUp','EngineRunning')) {
    $copy=$samples|ConvertTo-Json|ConvertFrom-Json; $copy[1].$key=$false
    Check (!(Test-RekeyEvidence $copy -WindowsChannel).Passed) ($key+' loss cannot pass rekey')
}
foreach ($key in @('SessionId','ConnectedAt','VirtualIPv4')) {
    $copy=$samples|ConvertTo-Json|ConvertFrom-Json; $copy[1].$key='replaced'
    Check (!(Test-RekeyEvidence $copy -WindowsChannel).Passed) ($key+' replacement rejects a disguised redial')
}
foreach ($key in @('IkeEstablishments','ChildEstablishments')) {
    $copy=$samples|ConvertTo-Json|ConvertFrom-Json; $copy[2].$key=2
    Check (!(Test-RekeyEvidence $copy -WindowsChannel).Passed) ($key+' detects fresh authentication or establishment')
}
$copy=$samples|ConvertTo-Json|ConvertFrom-Json; $copy[2].ChildRekeysCompleted=1
Check (!(Test-RekeyEvidence $copy).Passed) 'one Child rekey is insufficient for repeated-cycle acceptance'
$copy=$samples|ConvertTo-Json|ConvertFrom-Json; $copy[2].IkeSpiInitiator=$copy[0].IkeSpiInitiator
Check (!(Test-RekeyEvidence $copy).Passed) 'a fabricated counter without replacement IKE SPI is rejected'
$child=[pscustomobject]@{state='INSTALLED';protocol='ESP';encap='yes';'remote-ts'=@('10.77.0.5/32');
    'spi-in'='0000002b';'spi-out'='00000021';'if-id-in'='0000002a';'if-id-out'='0000002a';
    uniqueid='9';reqid='4';'packets-in'='3';'packets-out'='4'}
$sa=[pscustomobject]@{version='2';state='ESTABLISHED';'initiator-spi'='000000000000000d';'responder-spi'='0000000000000017';
    'remote-vips'=@('10.77.0.5');uniqueid='5';'child-sas'=[pscustomobject]@{test=$child}}
$report=[pscustomobject]@{errors=@();data=@([pscustomobject]@{test=$sa})}
Check (@(Get-RekeyServerMatches $samples[-1] @($report)).Count -eq 1) 'server confirmation matches both IKE and reverse-direction ESP SPIs'
$child.PSObject.Properties.Remove('if-id-in'); $child.PSObject.Properties.Remove('if-id-out')
Check (@(Get-RekeyServerMatches $samples[-1] @($report)).Count -eq 1) 'gateway evidence does not require a particular kernel interface backend'
$child.'spi-in'='deadbeef'
Check (@(Get-RekeyServerMatches $samples[-1] @($report)).Count -eq 0) 'mismatched ESP direction cannot confirm a rekey'
$child.'spi-in'='0000002b';$child.encap='no'
Check (@(Get-RekeyServerMatches $samples[-1] @($report)).Count -eq 0) 'bare ESP cannot pass forced-UDP acceptance'
$child.encap='yes';$child.'remote-ts'=@('10.77.0.6/32')
Check (@(Get-RekeyServerMatches $samples[-1] @($report)).Count -eq 0) 'another client selector cannot confirm protected traffic'
$child.'remote-ts'=@('10.77.0.5/32');$report.errors=@('query failed')
Check (@(Get-RekeyServerMatches $samples[-1] @($report)).Count -eq 0) 'an errored VICI report cannot pass confirmation'
$root=Split-Path -Parent $PSScriptRoot
$guard=Get-Content (Join-Path $root 'scripts/Watch-FullTunnelSafety.ps1') -Raw
Check ($guard.IndexOf('$requestedProfile=$ProfileName') -lt $guard.IndexOf(". (Join-Path") -and
    $guard -match '\$profile=\$requestedProfile') 'disconnect guard preserves its allowlisted profile across helper imports'
