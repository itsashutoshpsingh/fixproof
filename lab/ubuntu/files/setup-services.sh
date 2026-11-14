#!/bin/bash
# Build-time setup shared by every Ubuntu lab image: TLS site for nginx, sshd host keys.
set -eux
mkdir -p /etc/nginx/tls /opt/legacy/lib
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=lab.invalid" \
  -keyout /etc/nginx/tls/key.pem -out /etc/nginx/tls/cert.pem 2>/dev/null
cat > /etc/nginx/sites-available/default <<'CONF'
server {
    listen 127.0.0.1:443 ssl;
    ssl_certificate     /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    ssl_verify_client optional_no_ca;
    root /var/www/html;
}
CONF
# a second nginx, run from a vendored copy of the TLS libraries (state S9)
sed -e 's#127.0.0.1:443#127.0.0.1:8443#' /etc/nginx/sites-available/default > /opt/legacy/site.conf
sed -e 's#/run/nginx.pid#/run/nginx-legacy.pid#' -e 's#include /etc/nginx/sites-enabled/\*;#include /opt/legacy/site.conf;#' \
  /etc/nginx/nginx.conf > /opt/legacy/nginx.conf
grep -q nginx-legacy.pid /opt/legacy/nginx.conf || sed -i '1i pid /run/nginx-legacy.pid;' /opt/legacy/nginx.conf
ssh-keygen -A
chmod +x /opt/fixproof-lab/*.sh
