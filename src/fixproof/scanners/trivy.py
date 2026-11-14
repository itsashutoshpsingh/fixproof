"""Trivy 0.76.2: `trivy image --input <snapshot.tar>`, vulnerability DB frozen (--skip-db-update)."""
from __future__ import annotations

import gzip
import json
import subprocess
from pathlib import Path

IMAGE = "mirror.gcr.io/aquasec/trivy:0.76.2"
MEM = "1g"


def run(snapshot_tar: Path, out: Path, cache: Path) -> dict:
    cmd = ["docker", "run", "--rm", "--name", "fp-scan-trivy", "--memory", MEM, "--network", "none",
           "-v", f"{cache}:/cache", "-v", f"{snapshot_tar.parent}:/in:ro", IMAGE,
           "--cache-dir", "/cache", "image", "--input", f"/in/{snapshot_tar.name}", "--skip-db-update",
           "--offline-scan", "--no-progress", "--quiet", "--scanners", "vuln", "--pkg-types", "os", "--format", "json"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    with gzip.open(out, "wt") as f:
        f.write(p.stdout)
    return {"rc": p.returncode, "stderr": p.stderr[-2000:]}


def parse(path: Path) -> dict:
    with gzip.open(path, "rt") as f:
        text = f.read()
    if not text.strip():
        return {"error": "no output", "findings": {}, "meta": {}}
    d = json.loads(text)
    findings: dict[str, list] = {}
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            findings.setdefault(v["VulnerabilityID"], []).append(
                {"pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion"),
                 "status": v.get("Status")})
    os_ = (d.get("Metadata") or {}).get("OS") or {}
    return {"findings": findings, "meta": {"os": f"{os_.get('Family')} {os_.get('Name')}", "eosl": os_.get("EOSL", False),
                                           "version": (d.get("Trivy") or {}).get("Version")}}
