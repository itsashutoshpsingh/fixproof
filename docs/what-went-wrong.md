# What went wrong

Every miss, dead end and limit met while building this, and what each does to the numbers.

## Blocked feeds and registries (changes which scanners exist in the table)

- **Debian, Alpine, Rocky and Alma package archives are blocked** from the lab
  (`deb.debian.org`, `snapshot.debian.org`, `dl-cdn.alpinelinux.org`, `dl.rockylinux.org`,
  `vault.almalinux.org` all refused by the egress proxy). Only Ubuntu's archive, security pocket,
  `snapshot.ubuntu.com` and `old-releases` are reachable. So only Ubuntu hosts were upgraded by a
  real package manager; the other distros use two official images and a file overlay
  (method section 1). Effect: the S3 rows for Debian, Alpine, Rocky and Alma rest on the overlay
  doing what dpkg/apk/rpm do; the collector confirms the old files are mapped as `(deleted)`, but
  maintainer scripts did not run.
- **Greenbone (OpenVAS), Wazuh, Grype, OpenSCAP/OVAL and the Vuls detection database could not
  be fetched** (limits.md has the host for each). The guide's main comparison, OpenVAS
  authenticated against unauthenticated, is not in this repo. The CVE-scanner columns are two
  scanners. The SSH banner check is my stand-in for an unauthenticated version check and is
  labelled as such everywhere.
- **ghcr.io manifests load but blobs do not.** That killed the OSV-Scanner container image and
  the Vuls database. OSV-Scanner 2.7.1 and Vuls 0.42.0 were instead built from the Go module proxy
  (`lab/tools/build_tools.sh`); OSV-Scanner needed Go 1.27.3 (fetched by `GOTOOLCHAIN=auto`), Vuls
  needed `GOEXPERIMENT=jsonv2`.
- **Docker Hub rate limits (HTTP 429)** hit halfway through pulling images, since the limit is
  shared with other builds on the same machine. Images are pulled through `mirror.gcr.io`; two
  AlmaLinux images had already come from Docker Hub directly and are referenced that way. Digests
  for all are in `results/lab_images.json`.
- **The novelty-check search tool ran out of credit** after the first query; the searches were
  redone with a different web search. GitHub's own search pages are blocked, so GitHub was only
  searched through a general search engine. A repository that is only findable through GitHub's
  search could have been missed.

## Scanner plumbing

- **OSV-Scanner `scan source` found nothing** on an extracted root filesystem: first because it
  honours `.gitignore` and the lab's `work/` directory is ignored, then because the OS extractors
  are not part of source scanning. OS packages are documented only for `scan image`, so the host
  snapshot is given to it as an image archive.
- **The full Ubuntu OSV export (816 MB) took about three minutes to load per scan.** The lab uses a
  copy filtered to records naming a studied CVE. Matching is per record, so verdicts on these
  CVEs cannot change; `results/osv_full_db_check.json` checks that on one host per distro.
- **Trivy tried to download its Java DB** on the first Ubuntu host (it found a jar) and failed with
  no network. All scans use `--pkg-types os`; every studied CVE is in an OS package.
- **Bind-mounting a live container's root into the scanner failed** (`/proc/<pid>/root` cannot be
  bind-mounted, and the overlay mount lives in containerd's mount namespace). Scanners get a
  `docker commit` + `docker save` snapshot instead, taken after the evidence is collected.
- **checkrestart crashed** with `PermissionError: /proc/19/exe` because Docker drops
  `CAP_SYS_PTRACE` and nginx workers run as `www-data`. Hosts now run with `--cap-add SYS_PTRACE`,
  which a root shell on a real host has anyway. checkrestart also needs `python3`, which the
  `--no-install-recommends` install had left out; `python3-minimal` was added to the image.
- **My first scoring said Vuls missed every stale process.** Vuls reports PIDs as the host sees
  them inside its namespace; the collector records PIDs as the Docker host sees them. The collector
  now records `NSpid` and the matcher uses it. Before the fix the Vuls restart column was 0%;
  after it, it is the number in the README.
- **Vuls needs `sudo` even when run as root.** On hosts where sudo was removed (S7, S8) and on the
  Debian, Alpine, Rocky and Alma images (no sudo, no checkrestart, no needs-restarting) its restart
  check could not run. These are counted as "unavailable", not as misses.
- **Snapshot tags with capital letters** (`S3`) were rejected by `docker commit`; lower-cased.

## Truth-rule mistakes caught before the final run

- **"Updated and restarted" was still vulnerable** on the first 22.04 run: PID 1 (`sleep`) had been
  started before the glibc upgrade, so it mapped the old loader. S2, S6 and S9 now end with a
  reboot (container restart). Without the fix, S2 would have shown false fixed verdicts that were
  really an artefact of my recipe.
- **The Terrapin mitigation check passed on a host with no sshd** (S8): an empty `sshd -T` output
  contains no chacha20. The check now requires `sshd -T` to succeed. I had also scored Terrapin as
  server-only; the client is affected too, so `openssh-client` is now an affected package and the
  server-side mitigation no longer counts as mitigating a host that still has the old client.
- **Rocky Linux CVEs were scored "no check" for both scanners.** That is a real result, not a bug:
  Rocky's errata feed as exported to OSV has no RLSA-2023:5453 (glibc, CVE-2023-4911) or
  RLSA-2023:3722 (openssl, CVE-2023-2650), Trivy's Rocky data comes from the same errata source,
  and the one record that exists for CVE-2023-38545 names the source package `curl` while the
  image has `curl-minimal`/`libcurl-minimal`. The vendor fix is confirmed by the rpm changelog of
  the 9.3 image. AlmaLinux, built from the same sources, is covered by both scanners.
- **20.04 kernel install failed**: the release-pocket `kmod` requires the release `libkmod2`, and
  the upgraded one is newer. `install-old-kernel.sh` keeps the newer libkmod2 and installs with
  `--force-depends`; the affected package (`linux-image-5.4.0-26-generic`) is unaffected by this.
- `/run/sshd` was created world-writable in the container and sshd refused to start; fixed with
  an explicit `chmod 0755`.

## An assumption the data overturned

- I wrote the OpenSSH case files assuming sshd re-executes itself for every connection on all
  three Ubuntu releases, so a stale listener would never be reachable. The connection probe showed
  that on 24.04 (OpenSSH 9.6p1) the process serving a new connection still ran the deleted binary
  in all three builds. Reachability for the sshd CVEs is now taken from the probe on each host, which
  moved 12 S3 verdicts from "not reachable" to "reachable".

## Judgments that move numbers

- **stale_reachable is my reading of each code path**, with the reason in the case file. Only
  sshd's is measured (connection probe). If you disagree with a call, the
  strict column does not depend on it.
- **Affected binary packages per CVE are my reading of the advisories.** The source-package
  matching cells (`via_other_package`) are listed separately so they can be re-scored either way.
- **needrestart is scored by service name** (it reports `ssh`, `nginx`), so all nginx processes
  count as one program. An open `sudo` session and PID 1 are not services; needrestart's user
  session check did not list them in batch mode.
