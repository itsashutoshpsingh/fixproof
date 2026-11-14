#!/bin/bash
# Start the long-running processes a server would have: sshd, nginx (TLS), an open root sudo session.
set -u
mkdir -p /run/sshd; chmod 0755 /run/sshd
/usr/sbin/sshd
nginx
if command -v sudo >/dev/null; then setsid sudo -n sleep infinity </dev/null >/dev/null 2>&1 & fi
sleep 1
