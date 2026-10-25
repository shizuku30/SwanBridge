#Requires -Version 5.1

function Test-MobikeServerEvidence($ClientBefore, $ClientAfter, $ServerBefore, $ServerAfter, [switch]$ProbeOnly) {
    $failures = [System.Collections.Generic.List[string]]::new()
    $states = @()
    foreach ($report in @($ServerBefore,$ServerAfter)) {
        $matches = @()
        if ($null -eq $report.errors -or @($report.errors).Count) { $failures.Add('Server VICI query is absent or reported errors') }
        foreach ($entry in $report.data) {
            foreach ($property in $entry.PSObject.Properties) {
                $sa = $property.Value
                if ($sa.version -eq '2' -and $sa.state -eq 'ESTABLISHED' -and @($sa.'remote-vips') -contains $ClientBefore.VirtualIPv4) { $matches += $sa }
            }
        }
        if ($matches.Count -ne 1) { $failures.Add('Exactly one established server IKE SA for the client VIP is required'); continue }
        $sa = $matches[0]
        $children = @($sa.'child-sas'.PSObject.Properties | ForEach-Object Value | Where-Object {
            $_.state -eq 'INSTALLED' -and $_.protocol -eq 'ESP' -and $_.encap -eq 'yes' -and @($_.'remote-ts') -contains ($ClientBefore.VirtualIPv4+'/32')
        })
        if ($children.Count -ne 1) { $failures.Add('Exactly one installed server Child SA for the client VIP is required'); continue }
        $states += [pscustomobject]@{ Ike=$sa; Child=$children[0] }
    }
    if ($states.Count -eq 2) {
        $b=$states[0]; $a=$states[1]
        foreach ($key in @('uniqueid','initiator-spi','responder-spi')) {
            if (!$b.Ike.$key -or [string]$b.Ike.$key -cne [string]$a.Ike.$key) { $failures.Add('Server IKE '+$key+' changed or is absent') }
        }
        foreach ($key in @('uniqueid','reqid','spi-in','spi-out','if-id-in','if-id-out')) {
            if (!$b.Child.$key -or [string]$b.Child.$key -cne [string]$a.Child.$key) { $failures.Add('Server Child '+$key+' changed or is absent') }
        }
        if ($b.Ike.'remote-host' -eq $a.Ike.'remote-host' -and $b.Ike.'remote-port' -eq $a.Ike.'remote-port') {
            $failures.Add('The server still observes the original UDP tuple')
        }
        foreach ($key in @('packets-in','packets-out')) {
            if ($null -eq $b.Child.$key -or $null -eq $a.Child.$key -or [uint64]$a.Child.$key -le [uint64]$b.Child.$key) { $failures.Add('Server encrypted '+$key+' did not increase') }
        }
        try {
            foreach ($pair in @(@('initiator-spi','IkeSpiInitiator'),@('responder-spi','IkeSpiResponder'))) {
                foreach ($client in @($ClientBefore,$ClientAfter)) {
                    if ([uint64]::Parse([string]$client.($pair[1])).ToString('x16') -cne $a.Ike.($pair[0])) { $failures.Add('Server IKE SPI does not match the client') }
                }
            }
            foreach ($pair in @(@('spi-in','ChildSpiOut'),@('spi-out','ChildSpiIn'))) {
                foreach ($client in @($ClientBefore,$ClientAfter)) {
                    if ([uint32]::Parse([string]$client.($pair[1])).ToString('x8') -cne $a.Child.($pair[0])) { $failures.Add('Server Child SPI does not match the client') }
                }
            }
        } catch { $failures.Add('Invalid client SPI encoding') }
    }
    $local = Test-MobikeEvidence $ClientBefore $ClientAfter -ProbeOnly:$ProbeOnly
    foreach ($failure in $local.Failures) { $failures.Add($failure) }
    [pscustomobject]@{ Passed=($failures.Count -eq 0); ProbeOnly=[bool]$ProbeOnly;
        Outcome=$(if ($failures.Count) { 'SERVER_ENDPOINT_VERIFICATION_FAILED' } elseif ($ProbeOnly) { 'PASS_SERVER_CONFIRMED_UDP_REBIND_ONLY' } else { 'PASS_SERVER_CONFIRMED_MOBIKE' });
        Failures=$failures.ToArray() }
}
