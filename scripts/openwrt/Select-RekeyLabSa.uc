let fs = require('fs');
let data = json(fs.stdin.read('all'));
if (length(ARGV) != 1 || (ARGV[0] != 'ike' && ARGV[0] != 'child') ||
    type(data.errors) != 'array' || length(data.errors)) die('Invalid SA selection request.\n');
let ids = [];
for (let i = 0; i < length(data.data); i++) {
    let sa = data.data[i].sb_rekey_acceptance;
    if (!sa || sa.state != 'ESTABLISHED' || sa['remote-id'] != 'swanbridge-rekey-acceptance') continue;
    if (ARGV[0] == 'ike') push(ids, sa.uniqueid);
    else for (let name, child in sa['child-sas'])
        if (child.state == 'INSTALLED' && child.name == 'sb_rekey_child') push(ids, child.uniqueid);
}
if (length(ids) != 1 || !match(ids[0], /^[1-9][0-9]*$/)) die('Test SA is missing or ambiguous; nothing was changed.\n');
printf('%s\n', ids[0]);
