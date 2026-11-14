"""Build one host state, collect evidence, scan it with every scanner, tear it down.

Raw outputs go to results/raw/<distro>/<state>/r<repeat>/. Only one host and one scanner
run at a time, so memory stays well under the lab cap.
"""

from __future__ import annotations

import gzip
import json
import subprocess
import time
from pathlib import Path

from . import evidence, lab, truth
from .scanners import needrestart, osv, trivy, vuls

REPO = lab.REPO
RAW = REPO / "results/raw"
WORK = REPO / "work"
TOOLS = REPO / ".tools"


def _dump(path: Path, obj):
    with gzip.open(path, "wt") as f:
        json.dump(obj, f, indent=0, sort_keys=True, default=sorted)


def ssh_probe(host: lab.Host) -> dict:
    """Open one TCP connection to sshd and look at the process that serves it (no login)."""
    rc, _ = host.exec("command -v bash >/dev/null && pgrep -x sshd >/dev/null")
    if rc:
        return {"ran": False}
    subprocess.Popen(["docker", "exec", host.name, "bash", "-c",
                      "exec 3<>/dev/tcp/127.0.0.1/22; read -t 20 l <&3; echo \"$l\" > /tmp/fp-banner; sleep 8"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)
    tgt = evidence.DockerTarget(host.name)
    procs = [evidence.process_info(p, {"sshd"}, evidence._btime()) for p in tgt.pids()]
    procs = [p for p in procs if p and p["comm"] == "sshd"]
    rc, banner = host.exec("cat /tmp/fp-banner 2>/dev/null; rm -f /tmp/fp-banner")
    listener = [p for p in procs if "listener" in p["cmdline"] or p["ppid"] not in {q["pid"] for q in procs}]
    lpids = {p["pid"] for p in listener}
    children = [p for p in procs if p["ppid"] in lpids]
    return {"ran": True, "banner": banner.strip(),
            "listener": [{"pid": p["pid"], "exe_deleted": p["exe_deleted"]} for p in listener],
            "connection": [{"pid": p["pid"], "cmdline": p["cmdline"], "exe_deleted": p["exe_deleted"],
                            "exe_build_id": next((o.get("build_id") for o in p["objects"]
                                                  if o["path"].endswith("/sshd")), None)} for p in children]}


def run_host(distro: str, state: str, repeat: int, scanners=("trivy", "osv-scanner", "vuls", "needrestart")) -> Path:
    cases = truth.load_cases()
    interest = truth.interest_files(cases, distro)
    checks = truth.mitigation_checks(cases, distro)
    out = RAW / distro / state / f"r{repeat}"
    out.mkdir(parents=True, exist_ok=True)
    host = lab.Host(distro, state, repeat)
    meta = {"distro": distro, "state": state, "repeat": repeat, "image": host.image, "started": time.time()}
    WORK.mkdir(exist_ok=True)
    snap = WORK / f"{host.name}.tar"
    try:
        host.start()
        for step in host.recipe["steps"]:
            if step == "collect-before":
                _dump(out / "evidence_before.json.gz",
                      evidence.collect(evidence.DockerTarget(host.name), interest, checks, label="before"))
                continue
            host.run_step(step)
        ev = evidence.collect(evidence.DockerTarget(host.name), interest, checks, label="after")
        _dump(out / "evidence.json.gz", ev)
        probe = ssh_probe(host)
        (out / "ssh_probe.json").write_text(json.dumps(probe, indent=1))
        scan_meta = {}
        if {"trivy", "osv-scanner"} & set(scanners):
            tag = f"fixproof-snap/{host.name.lower()}:latest"
            lab.sh(["docker", "commit", host.name, tag])
            lab.sh(["docker", "save", "-o", str(snap), tag])
            lab.sh(["docker", "rmi", "-f", tag], check=False)
            if "trivy" in scanners:
                t0 = time.time()
                scan_meta["trivy"] = {**trivy.run(snap, out / "trivy.json.gz", REPO / ".cache/trivy"),
                                      "seconds": round(time.time() - t0, 1)}
            if "osv-scanner" in scanners:
                t0 = time.time()
                scan_meta["osv-scanner"] = {**osv.run(snap, out / "osv.json.gz", TOOLS / "osv-scanner",
                                                      REPO / ".cache/osv-filtered"), "seconds": round(time.time() - t0, 1)}
            snap.unlink(missing_ok=True)
        if "vuls" in scanners:
            t0 = time.time()
            scan_meta["vuls"] = {**vuls.run(host.name, out / "vuls.json.gz", TOOLS / "vuls"),
                                 "seconds": round(time.time() - t0, 1)}
        if "needrestart" in scanners and not host.official:
            scan_meta["needrestart"] = needrestart.run(host.name, out / "needrestart.txt")
        meta["scans"] = scan_meta
    finally:
        snap.unlink(missing_ok=True)
        meta["steps"] = host.log
        meta["finished"] = time.time()
        (out / "run.json").write_text(json.dumps(meta, indent=1, default=str))
        host.stop()
    return out
