#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || exit 2
[ "$#" = 2 ] || [ "$#" = 3 ] || exit 2
action=$1
dir=$2
expected_client=${3:-}
case "$dir" in /tmp/swanbridge-rekey-*) ;; *) exit 2 ;; esac
case "$dir" in *[!a-zA-Z0-9/._-]*|*/../*|*/..|*/./*) exit 2 ;; esac
script=$(readlink -f "$0")
digest() { sha256sum /etc/config/ipsec | cut -d ' ' -f 1; }
restore() {
    [ -f "$dir/restored.txt" ] && return 0
    [ -f "$dir/ipsec.original" ] && [ -f "$dir/original.sha256" ] || return 1
    mkdir "$dir/restore.lock" 2>/dev/null || return 1
    trap 'rmdir "$dir/restore.lock" 2>/dev/null || true' EXIT
    current=$(digest)
    if [ "$current" != "$(cat "$dir/original.sha256")" ] &&
       [ -f "$dir/applied.sha256" ] && [ "$current" != "$(cat "$dir/applied.sha256")" ]; then
        printf 'Configuration changed externally; backup retained, no overwrite.\n' > "$dir/restore-conflict.txt"
        rmdir "$dir/restore.lock"
        return 1
    fi
    swanctl --terminate --ike sb_rekey_acceptance --timeout 5 > "$dir/terminate.log" 2>&1 || true
    cp -p "$dir/ipsec.original" /etc/config/ipsec
    /etc/init.d/swanctl reload > "$dir/restore-load.log" 2>&1
    [ "$(digest)" = "$(cat "$dir/original.sha256")" ] || return 1
    swanmon get-shared > "$dir/shared-after-restore.json"
    ucode -e 'let d=json(require("fs").stdin.read("all")); if(type(d.errors)!="array" || length(d.errors) || type(d.data.keys)!="array") die("Invalid shared-key inspection\n"); for(let i=0;i<length(d.data.keys);i++) if(d.data.keys[i]=="ike-sb_rekey_acceptance") die("Test credential was not removed\n");' < "$dir/shared-after-restore.json"
    date > "$dir/restored.txt"
    rmdir "$dir/restore.lock"
    trap - EXIT
    printf 'Original UCI bytes restored; connections hot-reloaded without restarting charon.\n'
}
trigger() {
    kind=$1
    [ -f "$dir/prepared.txt" ] && [ ! -f "$dir/restored.txt" ] || return 1
    id=$(swanmon list-sas | ucode "$(dirname "$script")/Select-RekeyLabSa.uc" "$kind")
    case "$id" in ''|*[!0-9]*) return 1 ;; esac
    log="$dir/server-$kind-$(date +%s).log"
    date > "$log"
    swanctl --rekey "--$kind-id" "$id" --pretty >> "$log" 2>&1
    printf 'Requested %s rekey for isolated test SA %s.\n' "$kind" "$id"
}
case "$action" in
prepare)
    case "$expected_client" in ''|*[!a-zA-Z0-9@._-]*) printf 'An explicit expected client identity is required.\n' >&2; exit 2 ;; esac
    umask 077
    mkdir "$dir"
    cp -p /etc/config/ipsec "$dir/ipsec.original"
    chmod 600 "$dir/ipsec.original"
    digest > "$dir/original.sha256"
    setsid sh "$script" guard "$dir" < /dev/null > "$dir/guard.log" 2>&1 &
    printf '%s\n' "$!" > "$dir/guard.pid"
    i=0
    while [ ! -f "$dir/guard-ready.txt" ] && [ "$i" -lt 10 ]; do sleep 1; i=$((i+1)); done
    [ -f "$dir/guard-ready.txt" ] || exit 1
    if ! ucode "$(dirname "$script")/Configure-RekeyLab.uc" "$expected_client"; then restore; exit 1; fi
    digest > "$dir/applied.sha256"
    if ! /etc/init.d/swanctl reload > "$dir/test-load.log" 2>&1; then restore; exit 1; fi
    date > "$dir/prepared.txt"
    printf 'Rekey lab ready. Independent rollback armed for at most 30 minutes.\n'
    ;;
guard)
    date > "$dir/guard-ready.txt"
    i=0
    while [ "$i" -lt 1800 ] && [ ! -f "$dir/restored.txt" ]; do sleep 1; i=$((i+1)); done
    [ -f "$dir/restored.txt" ] || restore
    ;;
restore) restore ;;
child) trigger child ;;
ike) trigger ike ;;
exercise)
    sleep 10; trigger child
    sleep 20; trigger ike
    sleep 20; trigger child
    date > "$dir/server-exercise-completed.txt"
    ;;
*) exit 2 ;;
esac
