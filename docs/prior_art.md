# Prior art and novelty check

Searched on 14 November 2026, before the first result was produced. The guide's searches were
"scanner ground truth benchmark", "vulnerability scanner false negative backport",
"needrestart vulnerability scanner", "openvas trivy comparison benchmark", and the Scholar
queries on Nessus/OpenVAS accuracy and backported patches. GitHub's own search pages could not
be reached from the lab (the proxy returns 403 for github.com pages), so GitHub was searched
through a general web search instead.

**I could not find an open benchmark that builds hosts into known remediation states and
checks host scanners against what is actually running.** The closest work:

| Work | What it does | How fixproof differs |
|---|---|---|
| SVS-TEST, Rosso et al., SAC 2026 ([arXiv 2512.17710](https://arxiv.org/abs/2512.17710v1)) | Ground truth of 16 hand-built SBOMs, 7 SBOM-based scanners; finds false negatives and silent failures | Inputs are SBOMs, not hosts; no notion of running versus installed |
| [A Ground-Truth-Based Evaluation of Vulnerability Detection Across Multiple Ecosystems](https://www.emergentmind.com/papers/2604.21111) (2026) | Ground truth from OSV mapped to package versions; Trivy, Snyk, Dependency-Track and others | Dependency manifests; again version against advisory, which is exactly the check this repo shows is not enough |
| Badawy, El-Fishawy, Elshakankiry ([Springer](https://springerlink.bibliotecabuap.elogim.com/content/pdf/10.1007/978-3-642-40597-6_16.pdf)) | Scanners against missed Windows patches; false positives and negatives on every scanner | Windows patches, no backports, no process state |
| [SC Labs review of open source vulnerability management](https://www.scworld.com/product-test/vulnerability-management/sw-labs-review-free-and-open-source-vulnerability-management-software/) | OpenVAS and others on a test network; notes high false positives for Nmap + Vulners | Product review, no constructed ground truth |
| [needrestart](https://releasealert.dev/github/liske/needrestart/cves), `checkrestart` (debian-goodies), [glue](https://codeberg.org/klausman/glue), KernelCare [uchecker](https://ostechnix.com/detect-outdated-shared-libraries-in-memory-with-uchecker/) | Find processes that still map deleted or outdated libraries; uchecker compares in-memory build IDs | Restart detectors, not CVE scanners, and none is benchmarked against known states. fixproof scores two of them (needrestart and Vuls's checkrestart path) and uses the same build-ID idea for its ground truth |
| [Vuls](https://github.com/future-architect/vuls) fast-root scan | Documents detection of "processes which updated before but not restarting yet" via checkrestart / needs-restarting | Vuls is the one scanner that claims to look at this; it is a column here, scored on what that scan reports |

Background on the mechanism (a replaced shared object stays mapped as "(deleted)"):
[Russell Coker, "Deleted Mapped Files"](https://etbe.coker.com.au/2020/02/04/deleted-mapped-files/).

## Reading the Vuls documentation

The Vuls README lists, under Fast Root Scan: "Detect processes affected by update using yum-ps
(Amazon Linux, CentOS, Alma Linux, Rocky Linux, Oracle Linux, Fedora, and RedHat)" and "Detect
processes which updated before but not restarting yet using checkrestart of debian-goodies
(Debian and Ubuntu)". It also warns when a kernel was updated without a reboot. So Vuls was
expected to score well on state S3 on Ubuntu, and it does (see `results/tables.md`). The Vuls
detection phase (CVE matching) needs the vuls2 database, which is distributed only through
ghcr.io blob storage; that host is blocked from this lab, so only the scan phase could run.
That is recorded in `docs/limits.md`.
