#!/bin/sh
set -eu
port=$(uci -q get openclash.config.cn_port)
case "$port" in
  ''|*[!0-9]*) printf 'Invalid local controller port\n' >&2; exit 1 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ]

# Pass the controller token through an anonymous pipe, not argv or a file.
ucode -e '
  let c = require("uci").cursor().get_all("openclash", "config");
  if (!c) die("OpenClash configuration not found\n");
  let secret = c.dashboard_password;
  if (secret) {
    if (type(secret) != "string" || match(secret, /[\r\n]/)) die("Invalid controller credential\n");
    printf("header = %J\n", "Authorization: Bearer " + secret);
  }
' | curl --config - --noproxy '*' --silent --show-error --fail \
    --connect-timeout 3 --max-time 8 "http://127.0.0.1:$port/connections" |
ucode -e '
  let data = json(require("fs").stdin.read("all"));
  if (type(data) != "object" || type(data.connections) != "array") die("Invalid controller response\n");
  let connections = [];
  for (let i = 0; i < length(data.connections); i++) {
    let c = data.connections[i];
    let m = c.metadata;
    if (!m || type(m.sourceIP) != "string") continue;
    let address = match(m.sourceIP, /^10\.77\.0\.([0-9]{1,3})$/);
    if (!address || int(address[1]) < 2 || int(address[1]) > 254) continue;
    let chains = c.chains || [];
    let proxy = length(chains) > 0;
    for (let j = 0; j < length(chains); j++)
      if (chains[j] == "DIRECT" || chains[j] == "REJECT" ||
          chains[j] == "REJECT-DROP" || chains[j] == "PASS") proxy = false;
    push(connections, {
      SourceIP: m.sourceIP, Network: m.network, Host: m.host,
      DestinationIP: m.destinationIP, DestinationPort: m.destinationPort,
      Rule: c.rule, Chains: chains, Upload: c.upload, Download: c.download,
      ProxySelected: proxy
    });
  }
  printf("%J\n", {
    CapturedAtUnix: time(), Outcome: "OBSERVED_CLASH_VPN_CONNECTIONS",
    ConnectionCount: length(connections), Connections: connections
  });
'
