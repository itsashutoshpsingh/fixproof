#!/bin/bash
# State S6: an old kernel package stays installed; the running kernel is a different, fixed one.
# On 20.04 the upgraded libkmod2 is newer than the one the release-pocket kmod asks for (same
# soname), so libkmod2 is not downgraded and dpkg is told to accept that. Lab workaround only.
set -eu
export DEBIAN_FRONTEND=noninteractive
cd /opt/fixproof-lab/kernel
list=""
for d in *.deb; do
  pkg=${d%%_*}
  if [ "$pkg" = libkmod2 ] && dpkg-query -W -f='${Status}' libkmod2 2>/dev/null | grep -q 'ok installed'; then
    continue
  fi
  list="$list $d"
done
dpkg -i --force-depends $list
