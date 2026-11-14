# One lab "host" image per Ubuntu release, in state S0 (vulnerable).
# Packages come only from the release pocket, which never changes, so S0 is reproducible.
# The fixed versions are downloaded (not installed) from a dated snapshot.ubuntu.com view
# of -updates and -security, so S2/S3 can be built later with no network at all.
ARG BASE
FROM ${BASE}
ARG RELEASE
ARG FIXED_SNAPSHOT
ARG PACKAGES
ARG KERNEL_PACKAGE=""
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY proxy-ca.crt /tmp/proxy-ca.crt
COPY files/ /opt/fixproof-lab/
RUN set -eux; \
    printf 'Acquire::https::CAInfo "/tmp/proxy-ca.crt";\n' > /etc/apt/apt.conf.d/99lab-ca; \
    printf 'APT::Install-Recommends "false";\nAPT::Get::Assume-Yes "true";\nAPT::Periodic::Unattended-Upgrade "0";\n' > /etc/apt/apt.conf.d/99lab; \
    rm -f /etc/apt/sources.list.d/* ; \
    echo "deb https://archive.ubuntu.com/ubuntu ${RELEASE} main universe" > /etc/apt/sources.list; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install ${PACKAGES}; \
    dpkg-query -W -f='${Package}\t${Version}\n' > /opt/fixproof-lab/installed-at-build.tsv
# old kernel package for S6, downloaded only
RUN set -eux; if [ -n "${KERNEL_PACKAGE}" ]; then \
      mkdir -p /opt/fixproof-lab/kernel && cd /opt/fixproof-lab/kernel && \
      apt-get install --download-only ${KERNEL_PACKAGE} && mv /var/cache/apt/archives/*.deb . ; fi
# fixed versions: dated snapshot of -updates and -security, downloaded only
RUN set -eux; \
    for p in updates security; do \
      echo "deb https://snapshot.ubuntu.com/ubuntu/${FIXED_SNAPSHOT} ${RELEASE}-${p} main universe" ; \
    done > /etc/apt/sources.list.d/fixed.list; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get --download-only upgrade --with-new-pkgs; \
    ls /var/cache/apt/archives/*.deb | wc -l; \
    rm -f /etc/apt/apt.conf.d/99lab-ca /tmp/proxy-ca.crt
RUN bash /opt/fixproof-lab/setup-services.sh
