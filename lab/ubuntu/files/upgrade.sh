#!/bin/bash
# Install the security updates that were downloaded at image build time. No network is used.
# Maintainer scripts may not restart services (policy-rc.d) and needrestart only lists (mode l),
# which is the "updated, restart deferred" condition.
set -eu
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=
apt-get --no-download -o Dpkg::Options::=--force-confold upgrade --with-new-pkgs
