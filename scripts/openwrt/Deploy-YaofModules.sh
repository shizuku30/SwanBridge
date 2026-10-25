#!/bin/sh
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test "$(uname -m)" = x86_64
test "$(uname -r)" = 6.12.112
expected=b06d1845935db9b48470f975bfdca7105b2ad508a8cadf637adb064198438e67
actual=$(sha256sum /boot/vmlinuz | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
  printf 'Refusing mismatched kernel image. No packages or network settings changed.\n' >&2
  exit 1
fi
apk verify --keys-dir /etc/apk/keys "$BASE/packages/"kmod-*.apk
apk add --no-network "$BASE/packages/"kmod-*.apk
modprobe xfrm_interface
modprobe xfrm_user
modprobe esp4
modprobe esp6
printf 'Native XFRM modules loaded. No network services were restarted.\n'
