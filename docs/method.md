# Method

## 1. Hosts

There is no KVM in this lab, so every "host" is a Docker container with its own filesystem,
package database and processes. It shares the lab machine's kernel (Linux 6.18.44). Each host
runs with `--network none`, `--memory 384m` and `--cap-add SYS_PTRACE` (root on a real host can
read every process's `/proc` entries; Docker's default capability set cannot). Nothing in a host
can reach a network, so no vulnerable service is ever exposed.

**Ubuntu 20.04, 22.04 and 24.04** (`lab/ubuntu/Dockerfile`). Packages are installed from the
release pocket only (`archive.ubuntu.com <release> main universe`), which never changes, so the
vulnerable versions are reproducible. The base image is the official image from release week
(`focal-20200423`, `jammy-20220421`, `noble-20240423`). At build time the image also downloads,
without installing, the updates from a dated view of `-updates` and `-security`
(`snapshot.ubuntu.com/ubuntu/20261101T000000Z`). Every later state is built from those cached
`.deb` files with no network.

**Debian 12, Alpine 3.18, Rocky Linux 9, AlmaLinux 9.** Their package archives are not reachable
from this lab. The "before" and "after" states are two official images published at different
dates (`lab/images.yml`; digests in `results/lab_images.json`):

| Host | Before | After |
|---|---|---|
| debian-12-base | `debian:bookworm-20230919` | `debian:bookworm-20231009` |
| debian-12-nginx | `nginx:1.25.2` (bookworm) | `nginx:1.25.3` |
| alpine-3.18-nginx | `nginx:1.25.2-alpine3.18` | `nginx:1.25.3-alpine3.18` |
| rocky-9 | `rockylinux:9.2.20230513` | `rockylinux:9.3.20231119` |
| alma-9 | `almalinux:9.2-20230718` | `almalinux:9.3-20231124` |

For "updated, not restarted" on these distros, `lab.overlay()` writes every file of the newer
image that differs over the running host. Each file is written next to the old one and renamed
into place, which is what dpkg, rpm and apk do, so a process that mapped the old file keeps the
old inode and `/proc/<pid>/maps` shows it as `(deleted)`. The package database files are among
the files replaced. Maintainer scripts do not run. This is the end state of an in-place upgrade
to the newer image's package set.

## 2. Host states

| Code | State | Recipe (`lab/hosts.yml`) |
|---|---|---|
| S0 | Vulnerable | release pocket (Ubuntu) or old image; services started |
| S1 | Fixed, upstream version | newer image where the fix came with a new upstream release (Alpine) |
| S2 | Fixed by backport | Ubuntu: upgrade, reboot, start services. Others: newer image where the distro patched the old upstream version |
| S3 | Updated, not restarted | start services, upgrade (no restart; `policy-rc.d` returns 101 and needrestart is in list mode) |
| S4 | New kernel installed, old running | **not built**: a container cannot boot a kernel (see limits) |
| S5 | Config-only mitigation | vulnerable packages plus the vendor's documented mitigation, then services started |
| S6 | Old kernel on disk, fixed kernel running | upgrade, install the release kernel package, reboot; the running kernel is the lab's 6.18 |
| S7 | Package removed, config left | `apt-get remove openssh-server sudo` (dpkg state `rc`), nothing running |
| S8 | Package removed, process still running | start services, then remove the packages; sshd and an open sudo session keep running |
| S9 | Patched, old copy still used | copy the TLS libraries to `/opt/legacy/lib`, upgrade, reboot, run a second nginx with `LD_LIBRARY_PATH=/opt/legacy/lib` |

"Reboot" is a container restart: every process, PID 1 included, starts again from the files on
disk. Long-running processes on Ubuntu hosts: `sshd`, nginx with a TLS site that asks for client
certificates, and a root `sudo sleep infinity` session (an administrator's shell left open).
PID 1 is `sleep infinity`, standing in for any long-running process that maps libc. Debian and
Alpine nginx hosts run nginx; Rocky and Alma run a Python process that has imported `ssl`.

Each host recipe is scored only for the CVEs it targets (for example S7 only for the openssh and
sudo CVEs). Every host is built three times from scratch (repeats r1 to r3).

## 3. CVEs

22 public CVEs in `cases/*.yml`. Every fixed version comes from the distribution's own advisory
data, with the URL or advisory ID in the case file: the Ubuntu CVE tracker JSON
(`ubuntu.com/security/cves/<id>.json`), and the OSV export of the Debian, Alpine and AlmaLinux
trackers. Rocky Linux's errata feed in OSV has no entry for RLSA-2023:5453 (glibc) or
RLSA-2023:3722 (openssl); for those the fixed version is the Red Hat/Rocky advisory and it was
confirmed in the `rpm --changelog` of the fixed image (the 9.3 glibc changelog names
CVE-2023-4911 at 2.34-83.6, openssl-libs names CVE-2023-2650, libcurl-minimal names
CVE-2023-38545; the 9.2 changelogs name none of them). Every case file also lists the files
that carry the vulnerable code (for example `ld-linux-x86-64.so.2` for CVE-2023-4911,
`ISO-2022-CN-EXT.so` for CVE-2024-2961, `libcrypto.so.3` for the OpenSSL CVEs).

No exploit is run, written or stored. Truth comes only from how the host was built and what the
collector reads.

## 4. Evidence collector and the truth rule

`src/fixproof/evidence.py` runs from the Docker host against a running lab host (or against the
local machine for `fixproof verify`). It records:

- every package with version and dpkg state (`installed`, `config-files`), from the package
  database itself (dpkg status file, apk installed db, `rpm -qa`);
- for every file a case file names: path, real path, owning package and version, sha256 and GNU
  build ID;
- for every process: start time, executable, every deleted mapping, and for each mapped object
  that is deleted or of interest, its sha256 and build ID read through
  `/proc/<pid>/map_files/<range>` (this works for deleted files);
- the running kernel, mitigation checks (a shell test per case), and CVE ids named in the
  package changelog (rpm; the Ubuntu images are minimised and ship no changelogs).

A **build-ID index** maps each build ID seen on disk in any host of a distro to the package
version that installed it. For S3, S8 and S9 the collector also runs before the update, so the
vulnerable builds are always in the index.

**Truth rule** (`src/fixproof/truth.py`). For a CVE on a host:

- **vulnerable** if an affected package is installed (dpkg state `installed`) at a version older
  than the vendor's fixed version, *or* a running process maps an object whose build ID belongs
  to a vulnerable version of an affected file;
- **mitigated** if it would be vulnerable but the case's mitigation check passes, every
  vulnerable package is covered by that mitigation, and any process that must re-read the
  configuration started after it was changed;
- **fixed** otherwise (including a package that is absent or in state `rc`).

For kernel CVEs, the running kernel decides: CVE-2024-1086 was fixed upstream in 6.8-rc2, and
the lab kernel is 6.18.44, so an old vulnerable `linux-image-*` package on disk is "fixed (old
kernel on disk only)".

**stale_only** marks cells where the package on disk is fixed and only a running process still
has the vulnerable code. **stale_reachable** marks the subset where that process is the one that
would run the vulnerable path on new input. This is a judgment per CVE, written in the case file
with a reason. Examples: nginx workers fork from the master without exec and keep using the TLS
library mapped at start, so they are reachable for the OpenSSL CVEs. sshd re-executes the binary
on disk for every new connection, which the connection probe confirms on every S3 host (the
listener's executable is deleted, the child serving the new connection is not). So a stale sshd
listener is strictly vulnerable but not reachable for CVE-2024-6387. The glibc loader bug
(CVE-2023-4911) is reached only by a new exec, which loads the new loader.

## 5. Scanners

Run one at a time, each in its own memory-capped container, against the same host:

| Scanner | How it ran | Feed |
|---|---|---|
| Trivy 0.76.2 | `trivy image --input <snapshot>.tar --scanners vuln --pkg-types os --skip-db-update --offline-scan` | trivy-db v2 from `mirror.gcr.io/aquasec/trivy-db:2`, UpdatedAt 2026-11-14T13:05:54Z, frozen for every scan |
| OSV-Scanner 2.7.1 | `osv-scanner scan image --archive --offline --offline-vulnerabilities` with the OS extractors (`os/dpkg`, `os/apk`, `os/rpm`) | OSV per-ecosystem exports downloaded 2026-11-14 (`results/feeds/osv_db.json`) |
| Vuls 0.42.0 (scan phase) | binary copied into the host, `vuls scan` with `scanMode = ["fast-root", "offline"]`, `port = "local"`, removed afterwards | none needed for the scan phase |
| needrestart (Ubuntu package) | `needrestart -b -r l` on the host | n/a |
| SSH banner check (baseline, mine) | reads the sshd banner and compares the upstream OpenSSH version with the CVE's affected range | NVD-style upstream ranges in the case files |
| fixproof verify (mine) | `verify.assess()` on the same evidence, without the cross-host build-ID index | vendor fixed versions |

The snapshot given to Trivy and OSV-Scanner is `docker commit` + `docker save` of the running
host, taken after the evidence is collected and before Vuls is copied in. Both tools read only
the filesystem in either mode; their documentation describes OS-package scanning for images and
root filesystems, and neither inspects running processes.

The OSV database given to OSV-Scanner keeps only the records that name a studied CVE in `id`,
`aliases`, `upstream` or `related` (`lab/tools/osv_filter.py`). OSV-Scanner matches every record
on its own, so dropping records about other CVEs cannot change a verdict on a studied CVE.

## 6. Verdicts and outcomes

A scanner's verdict on a CVE is **vulnerable** if its output names the CVE on any package
(Trivy `VulnerabilityID`; OSV `id`, `aliases`, `upstream` or `related`), otherwise **not
vulnerable**. If a scanner never flags a CVE on any S0 host of that distro, its silence elsewhere
is **no check** rather than "not vulnerable". For the kernel CVE, a scanner with no finding on any
kernel package at all is "no check".

| Truth \ verdict | vulnerable | not vulnerable |
|---|---|---|
| vulnerable | correct | **false fixed** (the dangerous error) |
| fixed | **false vulnerable** (the expensive error) | correct |
| mitigated | flagged by version | credited the mitigation |

**via_other_package** marks a "vulnerable" verdict given only through a package other than the
one carrying the vulnerable code (for example openssh-client for the sshd-only CVE-2024-6387).
Trackers list fixes per source package, so the scanner is following the vendor's data; it is
counted as a false vulnerable when the affected binary package is absent, and as correct but
noted when the host is vulnerable for another reason.

**Restart detectors.** For every process that maps a deleted object with a vulnerable build ID,
a detector counts as having flagged it if needrestart lists its service (`ssh` for sshd, `nginx`)
or Vuls lists its PID in `NeedRestartProcs`. A detector is "unavailable" when the scan says its
helper (checkrestart, needs-restarting, sudo) is missing.

**Rates and intervals.** Rates are verdicts over verdicts across all repeats; 95% intervals are
Wilson score intervals (`report.wilson`). Repeats are not independent draws of a random process
(the same recipe gives the same state), so the intervals describe the count, not a population;
the repeat-stability line in `results/tables.md` says whether anything changed between repeats.
