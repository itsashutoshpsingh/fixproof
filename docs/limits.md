# Limits: what this does not show

## The lab

- **Containers, not machines.** Every host shares the lab kernel (6.18.44). That rules out the
  guide's state S4 (new kernel installed, old kernel running): nothing here can boot an old
  kernel, so S4 is not built and no number in this repo is about it. S6 (old kernel package on
  disk, fixed kernel running) is built, but the "fixed kernel" is the lab's own 6.18 kernel, not
  a newer Ubuntu kernel package.
- **No systemd.** Services are started directly (`/usr/sbin/sshd`, `nginx`). On a real Ubuntu
  server, `apt upgrade` of openssh-server restarts the sshd listener through its maintainer
  script, and needrestart in its default interactive mode offers to restart the rest (on 24.04
  unattended-upgrades restarts services automatically). S3 here is the state you get when that
  restart does not happen: `policy-rc.d` denies it (as in container images, some golden images
  and some configuration-management setups), needrestart is in list mode, or the operator
  defers it. For shared libraries (glibc, OpenSSL) and for an open sudo session, no maintainer
  script restarts anything, so S3 is the default outcome on a real host too.
- **Debian, Alpine, Rocky and Alma were not upgraded by their package managers.** Their archives
  are not reachable from this lab. "Updated" is the newer official image; "updated, not
  restarted" writes the newer image's files over the running host by rename (method section 1).
  The package database and files end up exactly as in the newer image, but maintainer scripts do
  not run and files that the newer image deleted stay on disk. Only Ubuntu hosts went through a
  real `apt-get upgrade`.
- **PID 1 is `sleep infinity`.** It stands in for any long-running process that maps libc and
  the loader. On a real host PID 1 is systemd, which re-executes itself after a glibc update;
  other long-running daemons do not.
- **One release kernel, one kernel CVE.** CVE-2024-1086 on 20.04 and 22.04 only.

## Scanners that did not run

| Scanner | Status | Why |
|---|---|---|
| OpenVAS / Greenbone Community Edition | not run | The feed and image registry (`registry.community.greenbone.net`, `feed.community.greenbone.net`) are blocked from this lab, and the documented minimum (4 GB RAM, 8 GB recommended) is above the 3.5 GB cap for all lab containers together. The guide's authenticated/unauthenticated comparison is therefore not measured; the SSH banner check is a stand-in for the unauthenticated side and is labelled as mine. |
| Wazuh vulnerability detection | not run | Needs the Wazuh indexer (OpenSearch, 1 GB heap minimum) plus manager, and its CVE feed (`cti.wazuh.com`) is blocked. |
| Grype | not run | Its database is served only from `grype.anchore.io`, which is blocked. Building the database with grype-db/vunnel would need the same blocked upstream feeds. |
| OpenSCAP with vendor OVAL | not run | Ubuntu OVAL (`security-metadata.canonical.com`), Debian OVAL (`www.debian.org/security/oval`), Red Hat OVAL (`access.redhat.com`) and AlmaLinux OVAL are all blocked. Converting someone else's JSON copy back into OVAL would not be the vendor's feed. |
| Vuls detection phase | not run | The vuls2 database is published only as a ghcr.io blob; ghcr.io manifests resolve but blob downloads (`pkg-containers.githubusercontent.com`) are blocked. The Vuls **scan** phase ran, and its restart detection is scored. |
| Ubuntu Pro client (`pro fix --dry-run`) | not run | Needs network access from the scanned host to `ubuntu.com`; lab hosts have no network. |
| Nessus Essentials, Qualys | not run | Licences restrict publishing benchmark results; not attempted. |

So the CVE-scanner columns are two scanners, Trivy and OSV-Scanner. Both are version-based by
design. The result that they report "fixed" on stale processes is what their documentation
implies; the point of the measurement is the size of that gap on realistic states, not a claim
that either tool is broken.

## The truth

- **"Vulnerable code loaded" is strict.** A stale process counts even if it would never run the
  vulnerable path (for example a sudo session for a sudo argument-parsing bug, or the sshd
  listener, which re-executes the new binary for each connection). The `stale_reachable`
  column separates the cases where the stale process is the one that would handle new input;
  that column is a judgment per CVE, written down with the reason in each case file, not a
  measurement. No exploit was run to test reachability.
- **Affected binary packages and files are my reading of the advisories.** Trackers publish
  fixes per source package (`openssh`, `glibc`, `openssl`). Which binary package and which file
  carry the bug (sshd only for CVE-2024-6387; the loader only for CVE-2023-4911; the
  ISO-2022-CN-EXT gconv module only for CVE-2024-2961) is decided from the advisory text and
  recorded in `cases/*.yml`. A scanner that flags openssh-client for CVE-2024-6387 is following
  the vendor's source-level data; this repo counts that as a false vulnerable only when the
  binary package with the bug is absent, and reports those cells separately.
- **Mitigations are checked by a shell test, not by attacking the service.** For example
  `sshd -T | grep -x 'logingracetime 0'`.
- **The fixed versions are the vendors'.** If a vendor's tracker is wrong, the truth is wrong in
  the same way. Rocky's OSV feed is missing two 2023 advisories; the fixed version there comes
  from the Red Hat/Rocky advisory and was confirmed in the fixed image's rpm changelog.

## The numbers

- 22 CVEs and 8 distro images is a designed sample, not a random sample of CVEs or hosts. Rates
  are rates over this matrix. Most cells are Ubuntu.
- Three repeats of a deterministic recipe give the same answer; the repeats show the pipeline is
  stable, they do not add statistical independence. Confidence intervals are given for the
  counts as measured.
- Feeds are frozen at one date (Trivy DB 2026-11-14T13:05:54Z, OSV exports downloaded
  2026-11-14). A later feed could change "no check" cells, in particular on Rocky Linux.
- The OSV database was filtered to records that name a studied CVE. OSV-Scanner matches records
  one at a time, so this cannot change verdicts on these CVEs; on 8 hosts (one vulnerable host per
  distro plus a 22.04 S3 host) the full export and the filtered copy flagged exactly the same studied
  CVEs (`results/osv_full_db_check.json`).
