#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$policy = Get-Content -LiteralPath (Join-Path $root 'scripts/openwrt/swanbridge-fw4.sh') -Raw
$network = Get-Content -LiteralPath (Join-Path $root 'scripts/openwrt/Configure-Network.sh') -Raw
$inspect = Get-Content -LiteralPath (Join-Path $root 'scripts/openwrt/Inspect-ClashConnections.sh') -Raw

function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}

Check ($policy -match 'nft -j list chain' -and $policy -match 'rule\.family != "inet"' -and
    $policy -match 'rule\.table != "fw4"' -and $policy -match 'rule\.chain != chain') 'rule migration uses structured data and checks ownership'
Check ($policy -match 'rule\.comment == "SwanBridge VPN bypass"' -and
    $policy -match 'delete rule inet fw4 %s handle %d') 'legacy whole-VPN bypass is removed by its exact owned comment'
Check ($policy -notmatch 'return comment \\"SwanBridge VPN bypass\\"') 'whole-VPN bypass is never recreated'
Check ($policy -match 'udp sport \{ 500, 4500 \}' -and $policy -match 'meta l4proto esp' -and
    $policy -match 'chain != "openclash_mangle_output".*chain != "openclash_mangle_output_v6"') 'encrypted IPsec transport is protected in output chains'
Check ($policy -match 'iifname \\"VPN_XFRM\\" ip saddr 10\.77\.0\.0/24' -and
    $policy -match 'oifname \\"VPN_XFRM\\" ip daddr 10\.77\.0\.0/24') 'MSS rules are scoped to VPN ingress and egress'

$mtu = [int][regex]::Match($network, "network\.VPN_XFRM\.mtu='([0-9]+)'").Groups[1].Value
$caps = @([regex]::Matches($policy, 'maxseg size > ([0-9]+) tcp option maxseg size set ([0-9]+)'))
Check ($mtu -ge 1280 -and $caps.Count -eq 2) 'both forwarding directions have explicit MSS caps'
foreach ($cap in $caps) {
    Check ([int]$cap.Groups[1].Value -eq ($mtu - 40) -and
        [int]$cap.Groups[2].Value -eq ($mtu - 40)) 'MSS cap matches VPN IPv4 MTU and never increases smaller peer MSS'
}
Check ($policy.IndexOf('nft -c -f') -lt $policy.IndexOf('nft -f') -and
    $policy -match 'if \[ "\$check_only" -eq 1 \]' -and
    $policy -notmatch '(?m)^nft (insert|delete|flush)') 'rule changes are validated, dry-runnable and applied as one transaction'
Check ($inspect -match 'header = %J' -and $inspect -match 'curl --config -' -and
    $inspect -notmatch 'curl.*-H' -and $inspect -match 'int\(address\[1\]\) < 2' -and
    $inspect -match 'int\(address\[1\]\) > 254') 'inspection keeps controller credentials off argv and excludes non-client pool addresses'
