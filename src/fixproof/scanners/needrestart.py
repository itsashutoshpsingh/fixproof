"""needrestart in batch mode (`needrestart -b -r l`): lists services and processes that still
map replaced files. Installed on the Ubuntu hosts only (it is not a CVE scanner)."""
from __future__ import annotations

import subprocess
from pathlib import Path


def run(container: str, out: Path) -> dict:
    p = subprocess.run(["docker", "exec", container, "sh", "-c",
                        "command -v needrestart >/dev/null || exit 127; needrestart -b -r l"],
                       capture_output=True, text=True, timeout=600)
    out.write_text(p.stdout + p.stderr)
    return {"rc": p.returncode}


def parse(path: Path) -> dict:
    text = path.read_text()
    if "NEEDRESTART-VER" not in text:
        return {"error": "not installed", "services": [], "meta": {}}
    svcs = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.startswith("NEEDRESTART-SVC:")]
    sess = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.startswith("NEEDRESTART-SESS:")]
    ver = next((ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.startswith("NEEDRESTART-VER:")), "")
    return {"services": svcs, "sessions": sess, "meta": {"version": ver}}
