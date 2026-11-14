"""OSV-Scanner 2.7.1: `osv-scanner scan image --archive`, offline, local OSV database.

OS package scanning is documented for container images, so the host snapshot is given to it
as an image archive. The local database is the per-ecosystem OSV export filtered to the
records that name a studied CVE (see lab/tools/osv_filter.py); matching is per record, so
verdicts on those CVEs are the same as with the full export (checked in docs/method.md).
Only the OS package extractors are enabled: every studied CVE is in an OS package."""
from __future__ import annotations

import gzip
import json
import subprocess
from pathlib import Path

MEM = "1500m"


def run(snapshot_tar: Path, out: Path, binary: Path, dbdir: Path) -> dict:
    cmd = ["docker", "run", "--rm", "--name", "fp-scan-osv", "--memory", MEM, "--network", "none",
           "-e", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db", "-v", f"{dbdir}:/db", "-v", f"{binary}:/osv-scanner:ro",
           "-v", f"{snapshot_tar.parent}:/in:ro", "alpine:3.20",
           "/osv-scanner", "scan", "image", "--archive", "--offline", "--offline-vulnerabilities",
           "--x-no-default-plugins", "--x-plugins", "os/dpkg", "--x-plugins", "os/apk", "--x-plugins", "os/rpm",
           "--format", "json", f"/in/{snapshot_tar.name}"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    with gzip.open(out, "wt") as f:
        f.write(p.stdout)
    return {"rc": p.returncode, "stderr": p.stderr[-2000:]}


def ids_of(v: dict) -> set[str]:
    return {v.get("id", ""), *v.get("aliases", []), *v.get("upstream", []), *v.get("related", [])}


def parse(path: Path) -> dict:
    with gzip.open(path, "rt") as f:
        text = f.read()
    if not text.strip():
        return {"error": "no output", "findings": {}, "meta": {}}
    d = json.loads(text)
    findings: dict[str, list] = {}
    for r in d.get("results") or []:
        for p in r.get("packages") or []:
            pkg = p.get("package", {})
            for v in p.get("vulnerabilities") or []:
                for cve in (i for i in ids_of(v) if i.startswith("CVE-")):
                    findings.setdefault(cve, []).append(
                        {"pkg": pkg.get("name"), "installed": pkg.get("version"), "record": v.get("id")})
    return {"findings": findings, "meta": {"ecosystems": sorted({p.get("package", {}).get("ecosystem", "")
                                                                for r in d.get("results") or []
                                                                for p in r.get("packages") or []})}}
