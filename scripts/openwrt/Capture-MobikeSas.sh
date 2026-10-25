#!/bin/sh
set -eu
[ "$#" -ge 1 ] || exit 2
dest=$1
seconds=300
[ "$#" -lt 2 ] || seconds=$2
case "$dest" in /tmp/swanbridge-*) ;; *) exit 2 ;; esac
case "$dest" in *[!a-zA-Z0-9/._-]*|*/../*|*/..) exit 2 ;; esac
case "$seconds" in ''|*[!0-9]*) exit 2 ;; esac
[ "$seconds" -ge 1 ] && [ "$seconds" -le 1800 ]
umask 077
mkdir "$dest"
trap 'date > "$dest/stopped.txt"' EXIT
trap 'exit 0' INT TERM
date > "$dest/started.txt"
i=0
while [ "$i" -lt "$seconds" ]; do
  swanmon list-sas > "$dest/sample-$i.json"
  sleep 2
  i=$((i + 2))
done
