#!/bin/bash
set -eu
LD_LIBRARY_PATH=/opt/legacy/lib nginx -c /opt/legacy/nginx.conf
sleep 1
