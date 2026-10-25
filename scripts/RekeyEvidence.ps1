#Requires -Version 5.1
function Test-RekeyEvidence([object[]]$Samples, [switch]$WindowsChannel) {
    $failures=[Collections.Generic.List[string]]::new()
    if ($Samples.Count -lt 3) { $failures.Add('Continuous samples are missing.') }
    $before=$Samples[0]; $after=$Samples[-1]
    foreach ($sample in $Samples) {
        if (!$sample.Authenticated -or !$sample.ChildSaUp -or !$sample.TrafficPassed) { $failures.Add('A sample lost authentication, Child SA or protected traffic.') }
        if ($sample.IkeEstablishments -ne 1 -or $sample.ChildEstablishments -ne 1) { $failures.Add('Reauthentication or fresh establishment is not inline rekey.') }
        if (!$sample.VirtualIPv4 -or $sample.VirtualIPv4 -cne $before.VirtualIPv4) { $failures.Add('The virtual IP changed or is missing.') }
        if ($WindowsChannel -and (!$sample.ChannelUp -or !$sample.EngineRunning -or
            !$sample.SessionId -or $sample.SessionId -cne $before.SessionId -or
            !$sample.ConnectedAt -or $sample.ConnectedAt -cne $before.ConnectedAt)) { $failures.Add('The Windows VPN channel was restarted or lost.') }
    }
    foreach ($counter in @('IkeRekeysCompleted','ChildRekeysCompleted','EspTx','EspRx')) {
        for ($i=1; $i -lt $Samples.Count; ++$i) {
            if ($null -eq $Samples[$i].$counter -or $Samples[$i].$counter -lt $Samples[$i-1].$counter) { $failures.Add($counter+' is missing or regressed.') }
        }
    }
    if ($after.IkeRekeysCompleted -le $before.IkeRekeysCompleted) { $failures.Add('No completed IKE rekey.') }
    if ($after.ChildRekeysCompleted -lt ($before.ChildRekeysCompleted+2)) { $failures.Add('Fewer than two completed Child rekeys.') }
    foreach ($key in @('IkeUniqueId','IkeSpiInitiator','IkeSpiResponder','ChildUniqueId','ChildSpiIn','ChildSpiOut')) {
        if (!$before.$key -or !$after.$key -or [string]$before.$key -ceq [string]$after.$key) { $failures.Add($key+' did not advance to a replacement SA.') }
    }
    if ($after.EspTx -le $before.EspTx -or $after.EspRx -le $before.EspRx) { $failures.Add('Protected counters did not increase.') }
    [pscustomobject]@{Passed=($failures.Count -eq 0);Failures=@($failures|Select-Object -Unique);
        IkeRekeys=($after.IkeRekeysCompleted-$before.IkeRekeysCompleted);
        ChildRekeys=($after.ChildRekeysCompleted-$before.ChildRekeysCompleted)}
}

function Get-RekeyServerMatches($Client, [object[]]$Reports) {
    $ikeI=[uint64]::Parse([string]$Client.IkeSpiInitiator).ToString('x16')
    $ikeR=[uint64]::Parse([string]$Client.IkeSpiResponder).ToString('x16')
    $childIn=[uint32]::Parse([string]$Client.ChildSpiOut).ToString('x8')
    $childOut=[uint32]::Parse([string]$Client.ChildSpiIn).ToString('x8')
    foreach ($report in $Reports) {
        if ($null -eq $report.errors -or @($report.errors).Count) { continue }
        foreach ($entry in $report.data) {
            foreach ($property in $entry.PSObject.Properties) {
                $sa=$property.Value
                if ($sa.version -ne '2' -or $sa.state -ne 'ESTABLISHED' -or $sa.'initiator-spi' -cne $ikeI -or
                    $sa.'responder-spi' -cne $ikeR -or @($sa.'remote-vips') -notcontains $Client.VirtualIPv4) { continue }
                foreach ($child in $sa.'child-sas'.PSObject.Properties.Value) {
                    if ($child.state -eq 'INSTALLED' -and $child.protocol -eq 'ESP' -and $child.encap -eq 'yes' -and
                        @($child.'remote-ts') -contains ($Client.VirtualIPv4+'/32') -and
                        $child.'spi-in' -ceq $childIn -and $child.'spi-out' -ceq $childOut -and
                        $child.'if-id-in' -eq '0000002a' -and $child.'if-id-out' -eq '0000002a') {
                        [pscustomobject]@{IkeId=$sa.uniqueid;ChildId=$child.uniqueid;Reqid=$child.reqid;
                            PacketsIn=[uint64]$child.'packets-in';PacketsOut=[uint64]$child.'packets-out'}
                    }
                }
            }
        }
    }
}
