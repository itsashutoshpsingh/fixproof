"""Vuls v0.42.0 scan phase, fast-root + offline mode, run on the host itself.

The detection phase (`vuls report`) needs the vuls2 database, published only on ghcr.io blob
storage, which this lab cannot reach. The scan phase still runs and is scored for what it
reports about restarts: checkrestart (Debian family) / needs-restarting (Red Hat family)."""
from __future__ import annotations

import gzip
import json
import subprocess
from pathlib import Path

CONFIG = """[servers.lab]
host = "localhost"
port = "local"
scanMode = ["fast-root", "offline"]
"""


def run(container: str, out: Path, binary: Path) -> dict:
    def ex(cmd, timeout=600):
        return subprocess.run(["docker", "exec", container, "sh", "-c", cmd], capture_output=True, text=True,
                              timeout=timeout)
    ex("mkdir -p /tmp/fp-vuls")
    subprocess.run(["docker", "cp", str(binary), f"{container}:/tmp/fp-vuls/vuls"], check=True, capture_output=True)
    ex(f"cat > /tmp/fp-vuls/config.toml <<'EOF'\n{CONFIG}EOF")
    p = ex("cd /tmp/fp-vuls && ./vuls scan -config=/tmp/fp-vuls/config.toml -results-dir=/tmp/fp-vuls/results")
    res = ex("cat /tmp/fp-vuls/results/*/lab.json")
    ex("rm -rf /tmp/fp-vuls")
    with gzip.open(out, "wt") as f:
        f.write(res.stdout)
    return {"rc": p.returncode, "stdout": p.stdout[-3000:]}


def parse(path: Path) -> dict:
    with gzip.open(path, "rt") as f:
        text = f.read()
    if not text.strip():
        return {"error": "no scan result", "restart": {}, "meta": {}}
    d = json.loads(text)
    restart = {}
    for name, pkg in (d.get("packages") or {}).items():
        for proc in pkg.get("NeedRestartProcs") or []:
            restart.setdefault(str(proc.get("pid")), []).append({"package": name, "path": proc.get("path"),
                                                                  "service": proc.get("serviceName")})
    warn = " ".join(d.get("warnings") or [])
    unavailable = any(k in warn for k in ("need-restarting", "needs-restarting", "yum-ps", "checkrestart")) or \
        d.get("family") == "alpine"  # fast-root has no restart check for Alpine
    return {"restart": restart, "restart_unavailable": unavailable, "errors": [e[:300] for e in d.get("errors") or []],
            "warnings": [w[:300] for w in d.get("warnings") or []],
            "meta": {"family": d.get("family"), "release": d.get("release"),
                     "kernel": d.get("runningKernel"), "packages": len(d.get("packages") or {})}}
