#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ClientDirectory,[Parameter(Mandatory=$true)][string]$ServerCaptureDirectory)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'RekeyEvidence.ps1')
$clientDir=(Resolve-Path -LiteralPath $ClientDirectory).Path
$raw=Get-Content (Join-Path $clientDir 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json
if (!$raw.ClientEvidencePassed -or !($raw.NetworkUnchanged -or $raw.NetworkRestored)) { throw 'A completed client test with verified cleanup is required.' }
$samples=@(Get-Content (Join-Path $clientDir 'samples.jsonl') -Encoding UTF8|Where-Object {$_}|ForEach-Object {$_|ConvertFrom-Json})
$windows=[bool]$samples[0].SessionId
$protocolLog=if ($windows) { ($samples.EngineLog -join "`n") } else { Get-Content (Join-Path $clientDir 'engine.log') -Raw -Encoding UTF8 }
if ($protocolLog -match 'not found for rekey') { throw 'A lost rekey task prevents acceptance even when earlier cycles passed.' }
if ($windows -and !$raw.EngineStopped) { throw 'The test Windows engine did not stop.' }
if (!$windows) { foreach ($sample in $samples) { $sample|Add-Member TrafficPassed ([bool]$sample.DnsTrafficPassed) } }
$local=Test-RekeyEvidence $samples -WindowsChannel:$windows
if (!$local.Passed) { throw ($local.Failures -join '; ') }
$reports=@(Get-ChildItem -LiteralPath $ServerCaptureDirectory -Filter 'sample-*.json' -File|Sort-Object {[int]($_.BaseName -replace '\D','')}|ForEach-Object {
    $r=Get-Content $_.FullName -Raw -Encoding UTF8|ConvertFrom-Json
    if ($null -eq $r.errors -or @($r.errors).Count) { throw 'A server VICI snapshot is invalid.' }
    $r
})
if ($reports.Count -lt 3) { throw 'Continuous server snapshots are required.' }
$epochs=@()
$ikeSpis=@()
foreach ($group in @($samples|Group-Object -Property {([string]$_.IkeSpiInitiator)+'/'+([string]$_.IkeSpiResponder)+'/'+$_.ChildSpiIn+'/'+$_.ChildSpiOut})) {
    $sample=$group.Group[-1]
    $matches=@(Get-RekeyServerMatches $sample $reports)
    if (!$matches.Count -or ($matches|Measure-Object PacketsIn -Maximum).Maximum -le 0 -or
        ($matches|Measure-Object PacketsOut -Maximum).Maximum -le 0) { throw 'A client SA generation lacks exact server SPI and encrypted-traffic evidence.' }
    $ikeSpis += [uint64]::Parse([string]$sample.IkeSpiInitiator).ToString('x16')
    $epochs += [pscustomobject]@{ClientIkeId=$sample.IkeUniqueId;ClientChildId=$sample.ChildUniqueId;
        IkeSpiInitiator=[uint64]::Parse([string]$sample.IkeSpiInitiator).ToString('x16');
        IkeSpiResponder=[uint64]::Parse([string]$sample.IkeSpiResponder).ToString('x16');
        ChildSpiIn=[uint32]::Parse([string]$sample.ChildSpiIn).ToString('x8');
        ChildSpiOut=[uint32]::Parse([string]$sample.ChildSpiOut).ToString('x8');
        ServerIkeIds=@($matches.IkeId|Select-Object -Unique);ServerChildIds=@($matches.ChildId|Select-Object -Unique);
        Reqids=@($matches.Reqid|Select-Object -Unique);MatchingSnapshots=$matches.Count;
        MaxPacketsIn=($matches|Measure-Object PacketsIn -Maximum).Maximum;
        MaxPacketsOut=($matches|Measure-Object PacketsOut -Maximum).Maximum}
}
$childPreserved=$false; $ikePreserved=$false
for ($i=1; $i -lt $samples.Count; ++$i) {
    $b=$samples[$i-1]; $a=$samples[$i]
    if ($a.IkeRekeysCompleted -gt $b.IkeRekeysCompleted -and $a.ChildSpiIn -eq $b.ChildSpiIn -and $a.ChildSpiOut -eq $b.ChildSpiOut) { $childPreserved=$true }
    if ($a.ChildRekeysCompleted -gt $b.ChildRekeysCompleted -and [string]$a.IkeSpiInitiator -ceq [string]$b.IkeSpiInitiator) { $ikePreserved=$true }
}
if (!$childPreserved -or !$ikePreserved) { throw 'Separate IKE/Child replacement semantics were not observed.' }
foreach ($entry in $reports[-1].data) {
    foreach ($p in $entry.PSObject.Properties) {
        if ($ikeSpis -ccontains $p.Value.'initiator-spi') { throw 'A test IKE generation remains on the server after client cleanup.' }
    }
}
$result=[ordered]@{Outcome=$(if($windows){'PASS_WINDOWS_INLINE_IKE_AND_CHILD_REKEY'}else{'PASS_NATIVE_INLINE_IKE_AND_CHILD_REKEY'});
    Accepted=$true;WindowsDataChannelAccepted=$windows;
    Mode=$(if($windows){$samples[0].TransportOwner}else{$raw.Mode});ClientEvidence=$local;
    SampleCount=$samples.Count;ServerSnapshotCount=$reports.Count;SaGenerations=$epochs;
    IkeRekeyPreservesChild=$childPreserved;ChildRekeyPreservesIke=$ikePreserved;
    NoReauthentication=$true;VirtualIPv4=$samples[0].VirtualIPv4;
    TestSasRemovedFromServer=$true;NetworkRestored=[bool]($raw.NetworkUnchanged -or $raw.NetworkRestored);
    CompletedAt=[DateTimeOffset]::Now.ToString('o')}
[IO.File]::WriteAllText((Join-Path $clientDir 'verified-result.json'),($result|ConvertTo-Json -Depth 9),[Text.UTF8Encoding]::new($false))
[pscustomobject]$result|Select-Object Outcome,Accepted,WindowsDataChannelAccepted,Mode,SampleCount,ServerSnapshotCount,IkeRekeyPreservesChild,ChildRekeyPreservesIke,TestSasRemovedFromServer,NetworkRestored|ConvertTo-Json
