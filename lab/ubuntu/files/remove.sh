#!/bin/bash
# Remove the server packages (apt-get remove keeps conffiles: dpkg state "rc").
set -eu
export DEBIAN_FRONTEND=noninteractive SUDO_FORCE_REMOVE=yes NEEDRESTART_MODE=l
apt-get --no-download remove openssh-server sudo
