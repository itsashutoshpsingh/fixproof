#!/bin/bash
# State S6: an old kernel package stays installed; the running kernel is a different, fixed one.
set -eu
export DEBIAN_FRONTEND=noninteractive
dpkg -i /opt/fixproof-lab/kernel/*.deb
