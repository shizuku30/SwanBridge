#!/bin/sh
set -eu
check_only=0
case "$*" in
  '') ;;
  --check) check_only=1 ;;
  *) printf 'Usage: swanbridge-fw4.sh [--check]\n' >&2; exit 2 ;;
esac
work=$(mktemp -d /tmp/swanbridge-fw4.XXXXXX)
trap 'rm -f "$work/chain.json" "$work/rules.nft"; rmdir "$work"' EXIT
: > "$work/rules.nft"

# Inner VPN traffic follows the same OpenClash rules as LAN traffic.
# Only locally generated IKE/ESP transport must stay outside the proxy.
for chain in openclash_mangle dstnat openclash_mangle_output openclash_mangle_output_v6 mangle_forward; do
  nft -j list chain inet fw4 "$chain" > "$work/chain.json" 2>/dev/null || continue
  ucode -D "chain=$chain" -e '
    let data = json(require("fs").stdin.read("all"));
    let present = {};
    for (let i = 0; i < length(data.nftables); i++) {
      let rule = data.nftables[i].rule;
      if (!rule || rule.family != "inet" || rule.table != "fw4" || rule.chain != chain) continue;
      if ((chain == "openclash_mangle" || chain == "dstnat") &&
          rule.comment == "SwanBridge VPN bypass")
        printf("delete rule inet fw4 %s handle %d\n", chain, rule.handle);
      if (rule.comment) present[rule.comment] = true;
    }
    if (chain == "mangle_forward") {
      // VPN_XFRM MTU is 1280; WAN-only clamping misses Clash TUN return traffic.
      if (!present["SwanBridge VPN ingress MSS"])
        print("insert rule inet fw4 mangle_forward iifname \"VPN_XFRM\" ip saddr 10.77.0.0/24 tcp flags & syn == syn tcp option maxseg size > 1240 tcp option maxseg size set 1240 counter comment \"SwanBridge VPN ingress MSS\"\n");
      if (!present["SwanBridge VPN egress MSS"])
        print("insert rule inet fw4 mangle_forward oifname \"VPN_XFRM\" ip daddr 10.77.0.0/24 tcp flags & syn == syn tcp option maxseg size > 1240 tcp option maxseg size set 1240 counter comment \"SwanBridge VPN egress MSS\"\n");
      exit(0);
    }
    if (chain != "openclash_mangle_output" && chain != "openclash_mangle_output_v6") exit(0);
    if (!present["SwanBridge IPsec UDP transport"])
      printf("insert rule inet fw4 %s meta l4proto udp udp sport { 500, 4500 } counter return comment \"SwanBridge IPsec UDP transport\"\n", chain);
    if (!present["SwanBridge IPsec ESP transport"])
      printf("insert rule inet fw4 %s meta l4proto esp counter return comment \"SwanBridge IPsec ESP transport\"\n", chain);
  ' < "$work/chain.json" >> "$work/rules.nft"
done

[ -s "$work/rules.nft" ] || exit 0
nft -c -f "$work/rules.nft"
if [ "$check_only" -eq 1 ]; then
  cat "$work/rules.nft"
else
  nft -f "$work/rules.nft"
fi
