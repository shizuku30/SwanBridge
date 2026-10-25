// stdin is an SSH-encrypted anonymous pipe, never a command argument or log.
let fs = require('fs');
let uci = require('uci');
let data = json(fs.stdin.read('all'));
if (type(data) != 'object' || type(data.local_id) != 'string' ||
    !match(data.local_id, /^@[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$/) ||
    type(data.server_id) != 'string' || !match(data.server_id, /^@?[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$/) || type(data.psk) != 'string' ||
    !match(data.psk, /^0x[0-9a-f]+$/) || length(data.psk) % 2 != 0 ||
    type(data.server_host) != 'string' || length(data.server_host) > 253 ||
    !match(data.server_host, /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/))
    die('Credential input validation failed.\n');
fs.chmod('/etc/config/ipsec', 0600);
let c = uci.cursor();
function section(name, kind, options) {
    c.set('ipsec', name, kind);
    for (let key, value in options) c.set('ipsec', name, key, value);
}
section('swanbridge', 'ipsec', { debug: '1', rtinstall_enabled: '0',
    ignore_routing_tables: [ '354' ] });
section('sb_ike', 'crypto_proposal', { encryption_algorithm: 'aes256',
    hash_algorithm: 'sha256', dh_group: 'modp2048' });
section('sb_esp', 'crypto_proposal', { encryption_algorithm: 'aes256',
    hash_algorithm: 'sha256' });
section('sb_ipv4', 'pools', { addrs: '10.77.0.2-10.77.0.254',
    dns: [ '10.77.0.1', '8.8.8.8' ] });
section('sb_child', 'tunnel', { local_subnet: [ '0.0.0.0/0' ],
    remote_subnet: [ 'dynamic' ], crypto_proposal: [ 'sb_esp' ],
    if_id: '42', startaction: 'none', dpdaction: 'clear', closeaction: 'none',
    rekeytime: '0s', lifetime: '24h', replay_window: '128' });
let remote_options = { enabled: '1', gateway: 'any',
    authentication_method: 'psk', local_identifier: data.server_id,
    remote_identifier: data.local_id, pre_shared_key: data.psk,
    keyexchange: 'ikev2', mobike: '1', encap: '1', fragmentation: 'yes',
    send_certreq: '0', dpddelay: '20s', rekeytime: '0s', keyingtries: '6',
    pools: [ 'sb_ipv4' ], crypto_proposal: [ 'sb_ike' ], tunnel: [ 'sb_child' ] };
section('sb_roadwarrior', 'remote', remote_options);
if (match(data.server_host, /[a-zA-Z]/)) {
    remote_options.local_identifier = '@' + data.server_host;
    section('sb_roadwarrior_dnsid', 'remote', remote_options);
}
if (!c.commit('ipsec')) die('Configuration commit failed.\n');
fs.chmod('/etc/config/ipsec', 0600);
print('Original PSK and IKE identities imported; no secret printed.\n');
