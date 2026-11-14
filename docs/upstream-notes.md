# Notes to send to maintainers (drafts, not yet sent)

The guide asks for results to go to maintainers before publication. These are the drafts. None
has been sent from this lab (no outbound mail or issue tracker access); the owner sends them.

## Rocky Linux errata / OSV export

> The Rocky Linux 9 OSV export (`Rocky Linux/all.zip`, downloaded 2026-11-14) has no record for
> RLSA-2023:5453 (glibc, CVE-2023-4911, fixed in 2.34-60.el9_2.7) or RLSA-2023:3722 (openssl,
> CVE-2023-2650, fixed in 1:3.0.7-16.el9_2), although the rpm changelogs in
> `rockylinux:9.3.20231119` name both CVEs. The AlmaLinux export has the matching ALSA records.
> The one Rocky record for CVE-2023-38545 (RLSA-2023:5763) lists the source package `curl`, while
> Rocky 9 images install `curl-minimal` and `libcurl-minimal`, so name-based matchers miss it.
> Effect measured: on `rockylinux:9.2.20230513`, Trivy 0.76.2 and OSV-Scanner 2.7.1 report none of
> the three CVEs.

## Trivy and OSV-Scanner

> Not a bug report: both tools are documented as package-version scanners. A note for the docs:
> on a host where a library was updated but its users were not restarted, a clean scan means the
> files are fixed, not the running processes. In this benchmark every such cell was reported as
> not vulnerable. A one-line pointer to `needrestart` / `needs-restarting` in the "host scanning"
> docs would set expectations.

## Vuls

> `fast-root` scans call `sudo checkrestart` even when the scan runs as root, so on hosts without
> sudo the restart check fails ("sudo: not found") and the scan reports no processes needing a
> restart, only a warning. On Alpine there is no restart check at all. Suggest running the helper
> directly when uid is 0, and saying in the summary (not only in warnings) that the restart check
> did not run.
