// Clone only the server identity; never print or change the original PSK.
let fs = require('fs');
let uci = require('uci');
let endpoint = ARGV[0];
if (length(ARGV) < 3 || length(ARGV) > 4 || !length(ARGV[1]) || !length(ARGV[2]) ||
    (length(ARGV) == 4 && ARGV[3] != '--check'))
    die('Usage: Ensure-IdentityAlias.uc server-dns-name expected-server-id expected-client-id [--check]\n');
let check_only = ARGV[3] == '--check';
if (type(endpoint) != 'string' || length(endpoint) > 253 ||
    !match(endpoint, /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/) ||
    !match(endpoint, /[a-zA-Z]/)) die('An explicit DNS server identity is required.\n');
let c = uci.cursor();
let source = c.get_all('ipsec', 'sb_roadwarrior');
let target = 'sb_roadwarrior_dnsid';
if (type(source) != 'object' || source['.type'] != 'remote' ||
    source.authentication_method != 'psk' || source.keyexchange != 'ikev2' ||
    source.local_identifier != ARGV[1] || source.remote_identifier != ARGV[2] ||
    type(source.pre_shared_key) != 'string' || !length(source.pre_shared_key))
    die('Original connection differs from the expected protected PSK profile.\n');
let expected = {};
for (let key, value in source) if (substr(key, 0, 1) != '.') expected[key] = value;
expected.local_identifier = '@' + endpoint;
function same_option(a, b) {
    if (type(a) != type(b)) return false;
    if (type(a) != 'array') return a == b;
    if (length(a) != length(b)) return false;
    for (let i = 0; i < length(a); i++) if (a[i] != b[i]) return false;
    return true;
}
let existing = c.get_all('ipsec', target);
if (existing) {
    if (existing['.type'] != 'remote') die('Refusing to overwrite an unrelated alias section.\n');
    for (let key, value in expected)
        if (!same_option(existing[key], value)) die('Existing alias differs; nothing changed.\n');
    for (let key, value in existing)
        if (substr(key, 0, 1) != '.' && !(key in expected)) die('Existing alias has unrelated options; nothing changed.\n');
    print('DNS identity alias already matches the original connection.\n');
} else if (check_only) {
    print('Validated: only a DNS identity alias would be added.\n');
} else {
    fs.chmod('/etc/config/ipsec', 0600);
    if (!c.set('ipsec', target, 'remote')) die('Could not stage the alias section.\n');
    for (let key, value in expected)
        if (!c.set('ipsec', target, key, value)) die('Could not stage the identity alias.\n');
    if (!c.commit('ipsec')) die('Could not commit the identity alias.\n');
    fs.chmod('/etc/config/ipsec', 0600);
    print('DNS identity alias added; original profile, PSK, pools and policies retained.\n');
}
