let uci = require('uci');
let c = uci.cursor();
let remote = c.get_all('ipsec', 'sb_roadwarrior');
let child = c.get_all('ipsec', 'sb_child');
if (length(ARGV) != 1 || !length(ARGV[0]) || !remote || !child || remote.remote_identifier != ARGV[0] ||
    c.get('ipsec', 'sb_rekey_acceptance') || c.get('ipsec', 'sb_rekey_child'))
    die('Unexpected production configuration or existing rekey lab.\n');
function clone(name, kind, source) {
    c.set('ipsec', name, kind);
    for (let key, value in source)
        if (substr(key, 0, 1) != '.') c.set('ipsec', name, key, value);
}
clone('sb_rekey_child', 'tunnel', child);
c.set('ipsec', 'sb_rekey_child', 'rekeytime', '0s');
c.set('ipsec', 'sb_rekey_child', 'lifetime', '10m');
clone('sb_rekey_acceptance', 'remote', remote);
c.set('ipsec', 'sb_rekey_acceptance', 'remote_identifier', '@swanbridge-rekey-acceptance');
c.set('ipsec', 'sb_rekey_acceptance', 'tunnel', [ 'sb_rekey_child' ]);
c.set('ipsec', 'sb_rekey_acceptance', 'rekeytime', '0s');
if (!c.commit('ipsec')) die('Cannot commit isolated test connection.\n');
print('Isolated rekey identity added; production connection values unchanged.\n');
