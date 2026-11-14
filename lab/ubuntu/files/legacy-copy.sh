#!/bin/bash
# Copy the TLS libraries as an application bundle would ship them, before the system is patched.
set -eu
for f in libssl.so.3 libcrypto.so.3 libssl.so.1.1 libcrypto.so.1.1; do
  p=$(ls /usr/lib/x86_64-linux-gnu/$f 2>/dev/null || true)
  [ -n "$p" ] && cp -L "$p" /opt/legacy/lib/
done
ls -la /opt/legacy/lib
