#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p signing
test -f signing/private-key.pem || openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 -out signing/private-key.pem
chmod 600 signing/private-key.pem
openssl pkey -in signing/private-key.pem -pubout -out signing/swanbridge-25.12.pem
[ "${1:-}" != --prepare ] || exit 0
sdk/staging_dir/host/bin/apk verify --keys-dir "$PWD/signing" \
  sdk/bin/packages/x86_64/base/strongswan*.apk
