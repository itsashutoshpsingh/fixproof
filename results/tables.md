# fixproof results

114 host builds (38 host states x 3 repeats), 22 CVEs, 8 distro images, 155 CVE x distro x state cells, 1455 verdicts. Written by `fixproof report` from results/cells.csv.

## Correct verdicts by state

Truth column: vulnerable / fixed / mitigated verdict slots per scanner (all repeats). Each cell: correct verdicts / verdicts. For mitigated hosts, "correct" means the scanner credited the mitigation; none did (they report by version).

| State | Meaning | Truth v/f/m | Trivy 0.76.2 | OSV-Scanner 2.7.1 | SSH banner check (baseline) | fixproof verify (this repo) |
|---|---|---|---|---|---|---|
| S0 | vulnerable | 117 / 0 / 0 | 108/117 (92.3%) | 108/117 (92.3%) | 12/12 (100.0%) | 117/117 (100.0%) |
| S1 | fixed, upstream version | 0 / 6 / 0 | 6/6 (100.0%) | 6/6 (100.0%) | not run | 6/6 (100.0%) |
| S2 | fixed by backport | 3 / 108 / 0 | 102/111 (91.9%) | 102/111 (91.9%) | 0/12 (0.0%) | 111/111 (100.0%) |
| S3 | updated, not restarted | 78 / 39 / 0 | 39/117 (33.3%) | 39/117 (33.3%) | 12/12 (100.0%) | 117/117 (100.0%) |
| S5 | config mitigation | 6 / 0 / 24 | 6/30 (20.0%) | 6/30 (20.0%) | 6/12 (50.0%) | 6/30 (20.0%) |
| S6 | old kernel on disk, fixed kernel running | 0 / 6 / 0 | 0/6 (0.0%) | 0/6 (0.0%) | not run | 6/6 (100.0%) |
| S7 | package removed, config left | 6 / 24 / 0 | 24/30 (80.0%) | 24/30 (80.0%) | not run | 30/30 (100.0%) |
| S8 | package removed, process still running | 30 / 0 / 0 | 12/30 (40.0%) | 12/30 (40.0%) | 12/12 (100.0%) | 30/30 (100.0%) |
| S9 | patched, vendored old copy in use | 18 / 0 / 0 | 0/18 (0.0%) | 0/18 (0.0%) | not run | 18/18 (100.0%) |

## False fixed rate by state

Share of verdicts that said "not vulnerable" where the truth was vulnerable (scanner has a check for the CVE on that distro; 95% Wilson interval over all repeats).

| State | Trivy 0.76.2 | OSV-Scanner 2.7.1 | SSH banner check (baseline) |
|---|---|---|---|
| S0 | 0/108 (0.0%; CI 0 to 3%) | 0/108 (0.0%; CI 0 to 3%) | 0/12 (0.0%; CI 0 to 24%) |
| S2 | 0/3 (0.0%; CI 0 to 56%) | 0/3 (0.0%; CI 0 to 56%) |  |
| S3 | 69/72 (95.8%; CI 88 to 99%) | 69/72 (95.8%; CI 88 to 99%) | 0/12 (0.0%; CI 0 to 24%) |
| S5 | 0/6 (0.0%; CI 0 to 39%) | 0/6 (0.0%; CI 0 to 39%) | 0/6 (0.0%; CI 0 to 39%) |
| S7 | 0/6 (0.0%; CI 0 to 39%) | 0/6 (0.0%; CI 0 to 39%) |  |
| S8 | 18/30 (60.0%; CI 42 to 75%) | 18/30 (60.0%; CI 42 to 75%) | 0/12 (0.0%; CI 0 to 24%) |
| S9 | 18/18 (100.0%; CI 82 to 100%) | 18/18 (100.0%; CI 82 to 100%) |  |

### Confusion: Trivy 0.76.2

| Truth \ verdict | vulnerable | not vulnerable | no check | error |
|---|---|---|---|---|
| vulnerable | 138 | 105 | 15 | 0 |
| fixed | 12 | 159 | 12 | 0 |
| mitigated | 24 | 0 | 0 | 0 |

### Confusion: OSV-Scanner 2.7.1

| Truth \ verdict | vulnerable | not vulnerable | no check | error |
|---|---|---|---|---|
| vulnerable | 138 | 105 | 15 | 0 |
| fixed | 6 | 159 | 18 | 0 |
| mitigated | 24 | 0 | 0 | 0 |

### Confusion: SSH banner check (baseline)

| Truth \ verdict | vulnerable | not vulnerable | no check | error |
|---|---|---|---|---|
| vulnerable | 42 | 0 | 0 | 0 |
| fixed | 12 | 0 | 0 | 0 |
| mitigated | 6 | 0 | 0 | 0 |

### Confusion: fixproof verify (this repo)

| Truth \ verdict | vulnerable | not vulnerable | no check | error |
|---|---|---|---|---|
| vulnerable | 258 | 0 | 0 | 0 |
| fixed | 0 | 183 | 0 | 0 |
| mitigated | 24 | 0 | 0 | 0 |

## Stale code: strict rule against reachable path

Verdicts on cells where the installed package is fixed but a running process maps vulnerable code: 222. Said fixed: 210 (94.6%). Of these, 108 are cells where the stale process is the one that would run the vulnerable path for new input (TLS workers, vendored library, sshd where the probe showed it); said fixed: 96 (88.9%).

| State | Stale path reachable | Verdicts | Said fixed | Rate |
|---|---|---|---|---|
| S3 | yes | 60 | 60 | 100.0% |
| S3 | no | 78 | 78 | 100.0% |
| S8 | yes | 12 | 0 | 0.0% |
| S8 | no | 36 | 36 | 100.0% |
| S9 | yes | 36 | 36 | 100.0% |

## Every S3 cell (updated, not restarted)

| CVE | Distro | Truth | Trivy 0.76.2 | OSV-Scanner 2.7.1 | SSH banner check (baseline) | Evidence |
|---|---|---|---|---|---|---|
| CVE-2023-38545 | alma-9 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2023-4911 | alma-9 | vulnerable | fixed x3 | fixed x3 |  | python3 maps ld-linux-x86-64.so.2 2.34-60.el9 (deleted); sleep maps ld-linux-x86-64.so.2 2.34-60.el9 (deleted) |
| CVE-2023-5363 | alma-9 | vulnerable | vulnerable x3 | vulnerable x3 |  | installed: openssl-libs 1:3.0.7-24.el9 < 1:3.0.7-25.el9_3; python3 maps libcrypto.so.3.0.7 1:3.0.7-16.el9_2 (d |
| CVE-2023-46218 | alpine-3.18-nginx | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2023-5363 | alpine-3.18-nginx | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.3 3.1.3-r0 (deleted) |
| CVE-2023-5678 | alpine-3.18-nginx | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.3 3.1.3-r0 (deleted) |
| CVE-2023-4911 | debian-12-base | vulnerable | fixed x3 | fixed x3 |  | sleep maps ld-linux-x86-64.so.2 2.36-9+deb12u1 (deleted) |
| CVE-2023-46218 | debian-12-nginx | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2023-5363 | debian-12-nginx | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.3 3.0.11-1~deb12u1 (deleted) |
| CVE-2023-6246 | debian-12-nginx | vulnerable | fixed x3 | fixed x3 |  | nginx maps libc.so.6 2.36-9+deb12u3 (deleted); sleep maps libc.so.6 2.36-9+deb12u3 (deleted) |
| CVE-2023-2650 | rocky-9 | vulnerable | no_check x3 | no_check x3 |  | python3 maps libcrypto.so.3.0.7 1:3.0.7-6.el9_2 (deleted) |
| CVE-2023-38545 | rocky-9 | fixed | no_check x3 | no_check x3 |  |  |
| CVE-2023-4911 | rocky-9 | vulnerable | no_check x3 | no_check x3 |  | python3 maps ld-linux-x86-64.so.2 2.34-60.el9 (deleted); sleep maps ld-linux-x86-64.so.2 2.34-60.el9 (deleted) |
| CVE-2021-3156 | ubuntu-20.04 | vulnerable | fixed x3 | fixed x3 |  | sudo maps sudo 1.8.31-1ubuntu1 (deleted); sudo maps sudoers.so 1.8.31-1ubuntu1 (deleted) |
| CVE-2021-4034 | ubuntu-20.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2022-0778 | ubuntu-20.04 | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.1.1 1.1.1f-1ubuntu2 (deleted); sshd maps libcrypto.so.1.1 1.1.1f-1ubuntu2 (deleted) |
| CVE-2022-1271 | ubuntu-20.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2023-0286 | ubuntu-20.04 | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.1.1 1.1.1f-1ubuntu2 (deleted); sshd maps libcrypto.so.1.1 1.1.1f-1ubuntu2 (deleted) |
| CVE-2023-22809 | ubuntu-20.04 | vulnerable | fixed x3 | fixed x3 |  | sudo maps sudo 1.8.31-1ubuntu1 (deleted); sudo maps sudoers.so 1.8.31-1ubuntu1 (deleted) |
| CVE-2023-48795 | ubuntu-20.04 | vulnerable | fixed x3 | fixed x3 | vulnerable x3 | sshd maps sshd 1:8.2p1-4 (deleted) |
| CVE-2024-2961 | ubuntu-20.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2024-7264 | ubuntu-20.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2023-0286 | ubuntu-22.04 | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.3 3.0.2-0ubuntu1 (deleted); sshd maps libcrypto.so.3 3.0.2-0ubuntu1 (deleted) |
| CVE-2023-22809 | ubuntu-22.04 | vulnerable | fixed x3 | fixed x3 |  | sudo maps sudo 1.9.9-1ubuntu2 (deleted); sudo maps sudoers.so 1.9.9-1ubuntu2 (deleted) |
| CVE-2023-38545 | ubuntu-22.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2023-48795 | ubuntu-22.04 | vulnerable | fixed x3 | fixed x3 | vulnerable x3 | sshd maps sshd 1:8.9p1-3 (deleted) |
| CVE-2023-4911 | ubuntu-22.04 | vulnerable | fixed x3 | fixed x3 |  | nginx maps ld-linux-x86-64.so.2 2.35-0ubuntu3 (deleted); sleep maps ld-linux-x86-64.so.2 2.35-0ubuntu3 (delete |
| CVE-2024-2961 | ubuntu-22.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2024-6119 | ubuntu-22.04 | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.3 3.0.2-0ubuntu1 (deleted); sshd maps libcrypto.so.3 3.0.2-0ubuntu1 (deleted) |
| CVE-2024-6387 | ubuntu-22.04 | vulnerable | fixed x3 | fixed x3 | vulnerable x3 | sshd maps sshd 1:8.9p1-3 (deleted) |
| CVE-2024-7264 | ubuntu-22.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2025-32462 | ubuntu-22.04 | vulnerable | fixed x3 | fixed x3 |  | sudo maps sudo 1.9.9-1ubuntu2 (deleted); sudo maps sudoers.so 1.9.9-1ubuntu2 (deleted) |
| CVE-2024-2961 | ubuntu-24.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2024-5535 | ubuntu-24.04 | vulnerable | fixed x3 | fixed x3 |  | nginx maps libssl.so.3 3.0.13-0ubuntu3 (deleted); sudo maps libssl.so.3 3.0.13-0ubuntu3 (deleted) |
| CVE-2024-6119 | ubuntu-24.04 | vulnerable | fixed x3 | fixed x3 |  | nginx maps libcrypto.so.3 3.0.13-0ubuntu3 (deleted); sshd maps libcrypto.so.3 3.0.13-0ubuntu3 (deleted); sudo  |
| CVE-2024-6387 | ubuntu-24.04 | vulnerable | fixed x3 | fixed x3 | vulnerable x3 | sshd maps sshd 1:9.6p1-3ubuntu13 (deleted) |
| CVE-2024-7264 | ubuntu-24.04 | fixed | fixed x3 | fixed x3 |  |  |
| CVE-2025-32462 | ubuntu-24.04 | vulnerable | fixed x3 | fixed x3 |  | sudo maps sudo 1.9.15p5-3ubuntu5 (deleted); sudo maps sudoers.so 1.9.15p5-3ubuntu5 (deleted) |
| CVE-2025-32463 | ubuntu-24.04 | vulnerable | fixed x3 | fixed x3 |  | sudo maps sudo 1.9.15p5-3ubuntu5 (deleted); sudo maps sudoers.so 1.9.15p5-3ubuntu5 (deleted) |

## Coverage on vulnerable hosts (S0)

No check = the scanner did not flag the CVE on any vulnerable host of that distro, so its silence elsewhere is not counted as a "fixed" verdict.

| Distro | Scanner | Flagged on S0 | CVEs with no check |
|---|---|---|---|
| alma-9 | Trivy 0.76.2 | 9/9 | none |
| alma-9 | OSV-Scanner 2.7.1 | 9/9 | none |
| alpine-3.18-nginx | Trivy 0.76.2 | 9/9 | none |
| alpine-3.18-nginx | OSV-Scanner 2.7.1 | 9/9 | none |
| debian-12-base | Trivy 0.76.2 | 3/3 | none |
| debian-12-base | OSV-Scanner 2.7.1 | 3/3 | none |
| debian-12-nginx | Trivy 0.76.2 | 9/9 | none |
| debian-12-nginx | OSV-Scanner 2.7.1 | 9/9 | none |
| rocky-9 | Trivy 0.76.2 | 0/9 | CVE-2023-2650, CVE-2023-38545, CVE-2023-4911 |
| rocky-9 | OSV-Scanner 2.7.1 | 0/9 | CVE-2023-2650, CVE-2023-38545, CVE-2023-4911 |
| ubuntu-20.04 | Trivy 0.76.2 | 27/27 | none |
| ubuntu-20.04 | OSV-Scanner 2.7.1 | 27/27 | none |
| ubuntu-22.04 | Trivy 0.76.2 | 30/30 | none |
| ubuntu-22.04 | OSV-Scanner 2.7.1 | 30/30 | none |
| ubuntu-24.04 | Trivy 0.76.2 | 21/21 | none |
| ubuntu-24.04 | OSV-Scanner 2.7.1 | 21/21 | none |

## False vulnerable rate by state

| State | Trivy 0.76.2 | OSV-Scanner 2.7.1 | SSH banner check (baseline) |
|---|---|---|---|
| S1 | 0/6 (0.0%) | 0/6 (0.0%) |  |
| S2 | 0/99 (0.0%) | 0/99 (0.0%) | 12/12 (100.0%) |
| S3 | 0/36 (0.0%) | 0/36 (0.0%) |  |
| S6 | 6/6 (100.0%) |  |  |
| S7 | 6/24 (25.0%) | 6/24 (25.0%) |  |

Verdicts that flagged a CVE only through a package other than the one carrying the vulnerable code (source-package matching): 132, in states {'S0': 75, 'S5': 21, 'S7': 18, 'S8': 18}.

## Restart detectors on processes running stale vulnerable code

| Tool | Process | Flagged | Missed | Unavailable | Flagged % |
|---|---|---|---|---|---|
| needrestart | nginx | 9 | 0 | 0 | 100.0% |
| needrestart | sleep | 0 | 3 | 0 | 0.0% |
| needrestart | sshd | 9 | 9 | 0 | 50.0% |
| needrestart | sudo | 0 | 18 | 0 | 0.0% |
| vuls (checkrestart / needs-restarting) | nginx | 9 | 0 | 6 | 100.0% |
| vuls (checkrestart / needs-restarting) | python3 | 0 | 0 | 6 | n/a |
| vuls (checkrestart / needs-restarting) | sleep | 0 | 3 | 12 | 0.0% |
| vuls (checkrestart / needs-restarting) | sshd | 9 | 0 | 9 | 100.0% |
| vuls (checkrestart / needs-restarting) | sudo | 9 | 0 | 9 | 100.0% |

Hosts with no stale vulnerable process: needrestart: 51 quiet, 0 raised a restart flag, 0 unavailable; vuls (checkrestart / needs-restarting): 42 quiet, 0 raised a restart flag, 39 unavailable

## Vuls restart check availability

The check could not run on 21 of 38 host states: alma-9/S0, alma-9/S3, alma-9/SU, alpine-3.18-nginx/S0, alpine-3.18-nginx/S3, alpine-3.18-nginx/SU, debian-12-base/S0, debian-12-base/S3, debian-12-base/SU, debian-12-nginx/S0, debian-12-nginx/S3, debian-12-nginx/SU, rocky-9/S0, rocky-9/S3, rocky-9/SU, ubuntu-20.04/S7, ubuntu-20.04/S8, ubuntu-22.04/S7, ubuntu-22.04/S8, ubuntu-24.04/S7, ubuntu-24.04/S8.

## sshd connection probe on S3 hosts

One TCP connection, no login. Does the listener, and the process serving the new connection, run a deleted (replaced) sshd binary?

| Distro | Repeat | Listener deleted | Connection child deleted | Banner |
|---|---|---|---|---|
| ubuntu-20.04 | r1 | True | False | SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13 |
| ubuntu-20.04 | r2 | True | False | SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13 |
| ubuntu-20.04 | r3 | True | False | SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13 |
| ubuntu-22.04 | r1 | True | False | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18 |
| ubuntu-22.04 | r2 | True | False | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18 |
| ubuntu-22.04 | r3 | True | False | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18 |
| ubuntu-24.04 | r1 | True | True | SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13 |
| ubuntu-24.04 | r2 | True | True | SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13 |
| ubuntu-24.04 | r3 | True | True | SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13 |

## Repeat stability

Verdict identical in every repeat: 485/485 (cell, scanner) groups. Truth identical in every repeat: 155/155 cells.

