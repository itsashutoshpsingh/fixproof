"""Join truth and scanner verdicts for every host run -> results/cells.csv, results/restart.csv."""

from __future__ import annotations

import csv
import gzip
import json
import re
from collections import defaultdict
from pathlib import Path

from . import lab, truth, verify
from .scanners import needrestart, osv, trivy, vuls
from .versions import dpkg_cmp

REPO = lab.REPO
RAW = REPO / "results/raw"
CVE_SCANNERS = ("trivy", "osv-scanner", "ssh-banner")  # fixproof-verify is scored too, but it is mine
SERVICE_OF = {"sshd": "ssh", "nginx": "nginx"}


def _load(p: Path):
    with gzip.open(p, "rt") as f:
        return json.load(f)


def runs():
    for run_json in sorted(RAW.glob("*/*/r*/run.json")):
        meta = json.loads(run_json.read_text())
        if "scans" in meta:
            yield run_json.parent, meta


def targets(cases: dict, distro: str, spec) -> list[str]:
    mine = {c: v for c, v in cases.items() if distro in v["distros"]}
    if spec == "all":
        return [c for c, v in mine.items() if v.get("kind") != "kernel"]
    if spec == "mitigated":
        return [c for c, v in mine.items() if v.get("mitigation")]
    if spec == "kernel":
        return [c for c, v in mine.items() if v.get("kind") == "kernel"]
    if spec == "tls":
        return [c for c, v in mine.items() if any(f.startswith(("libssl", "libcrypto")) for f in v.get("files") or [])]
    return [c for c, v in mine.items() if set(v["distros"][distro].get("fixed", {})) & set(spec)]


def state_label(state: str, case_d: dict) -> str:
    if state == "SU":
        return "S1" if case_d.get("fix_type") == "upstream" else "S2"
    return state


def banner_verdict(case: dict, probe: dict) -> str | None:
    bc = case.get("banner_check")
    if not bc or not probe.get("ran"):
        return None
    m = re.search(r"OpenSSH_([0-9][0-9.p]*)", probe.get("banner", ""))
    if not m:
        return "error"
    v = m.group(1)
    vulnerable = dpkg_cmp(v, bc["fixed"]) < 0 and (bc["introduced"] == "0" or dpkg_cmp(v, bc["introduced"]) >= 0)
    return "vulnerable" if vulnerable else "fixed"


def outcome(t: str, verdict: str) -> str:
    if verdict in ("no_check", "error"):
        return verdict
    if t == "vulnerable":
        return "correct" if verdict == "vulnerable" else "false_fixed"
    if t == "mitigated":
        return "flagged_mitigated" if verdict == "vulnerable" else "credited_mitigation"
    return "false_vulnerable" if verdict == "vulnerable" else "correct"


def main():
    cases = truth.load_cases()
    hosts = lab.load_hosts()
    index = truth.BuildIdIndex()
    allruns = list(runs())
    for d, meta in allruns:
        for f in ("evidence_before.json.gz", "evidence.json.gz"):
            if (d / f).exists():
                index.add(meta["distro"], _load(d / f))
    rows, restart_rows = [], []
    for d, meta in allruns:
        distro, state, rep = meta["distro"], meta["state"], meta["repeat"]
        official = distro in lab.load_images()["official"]
        recipe = (hosts["official_states"] if official else hosts["ubuntu_states"])[state]
        ev = _load(d / "evidence.json.gz")
        probe = json.loads((d / "ssh_probe.json").read_text()) if (d / "ssh_probe.json").exists() else {}
        parsed = {}
        for name, mod, fname in (("trivy", trivy, "trivy.json.gz"), ("osv-scanner", osv, "osv.json.gz")):
            p = d / fname
            rc = meta["scans"].get(name, {}).get("rc")
            if not p.exists():
                parsed[name] = None
                continue
            res = mod.parse(p)
            bad = res.get("error") or (name == "trivy" and rc not in (0, None))
            parsed[name] = None if bad else res
        stale = {}
        for cve in targets(cases, distro, recipe["targets"]):
            case = cases[cve]
            cd = case["distros"][distro]
            t = truth.evaluate(cve, case, distro, ev, index)
            reachable = t["stale_only"] and case.get("stale_reachable", False)
            nspid = {p["pid"]: p.get("nspid", p["pid"]) for p in ev["processes"]}
            for r in t["running_vulnerable"]:
                if r["deleted"]:
                    stale.setdefault(r["pid"], {"comm": r["comm"], "nspid": nspid[r["pid"]], "cves": set()})["cves"].add(cve)
            verdicts, flagged = {}, {}
            for name in ("trivy", "osv-scanner"):
                res = parsed[name]
                verdicts[name] = "error" if res is None else ("vulnerable" if cve in res["findings"] else "fixed")
                flagged[name] = sorted({f["pkg"] for f in (res or {"findings": {}})["findings"].get(cve, [])})
                if case.get("kind") == "kernel" and res is not None and verdicts[name] == "fixed" and not any(
                        f["pkg"].startswith("linux-") for fs in res["findings"].values() for f in fs if f.get("pkg")):
                    verdicts[name] = "no_check"  # no finding on any kernel package at all
            va = verify.assess(cve, case, distro, ev)
            verdicts["fixproof-verify"] = "fixed" if va["verdict"] == "remediated" else "vulnerable"
            bv = banner_verdict(case, probe)
            if bv:
                verdicts["ssh-banner"] = bv
            for sc, v in verdicts.items():
                rows.append({"distro": distro, "host_state": state, "state": state_label(state, cd), "repeat": rep,
                             "cve": cve, "scanner": sc, "truth": t["truth"], "stale_only": int(t["stale_only"]),
                             "stale_reachable": int(reachable), "verdict": v,
                             "flagged_pkgs": " ".join(flagged.get(sc, [])),
                             "via_other_package": int(v == "vulnerable" and bool(flagged.get(sc)) and not (
                                 set(flagged[sc]) & set(cd.get("fixed", {})) or any(
                                     x.startswith("linux-") for x in flagged[sc]))),
                             "basis": "; ".join(t["basis"])[:400]})
        # restart detectors: does the tool name each process that still runs vulnerable deleted code?
        vres = vuls.parse(d / "vuls.json.gz") if (d / "vuls.json.gz").exists() else None
        nres = needrestart.parse(d / "needrestart.txt") if (d / "needrestart.txt").exists() else None
        tools = {}
        if vres is not None:
            tools["vuls (checkrestart / needs-restarting)"] = (
                None if vres.get("error") or vres.get("restart_unavailable")
                else lambda pid, comm, v=vres: str(pid) in v["restart"])
        if nres is not None:
            tools["needrestart"] = (None if nres.get("error") else
                                    lambda pid, comm, n=nres: SERVICE_OF.get(comm) in n["services"])
        # one row per stale program per host run (nginx's master and workers count once; all must be flagged)
        groups = defaultdict(list)
        for pid, info in stale.items():
            groups[info["comm"]].append((pid, info))
        for comm, members in sorted(groups.items()):
            cves_ = sorted(set().union(*(i["cves"] for _, i in members)))
            for tool, fn in tools.items():
                res = "unavailable" if fn is None else (
                    "flagged" if all(fn(i["nspid"], comm) for _, i in members) else "missed")
                restart_rows.append({"distro": distro, "state": state, "repeat": rep,
                                     "pid": " ".join(str(p) for p, _ in members), "comm": comm,
                                     "cves": " ".join(cves_), "tool": tool, "result": res})
        if not stale:
            for tool, fn in tools.items():
                flagged = None
                if fn is not None:
                    flagged = bool(vres["restart"]) if tool.startswith("vuls") else bool(nres["services"])
                restart_rows.append({"distro": distro, "state": state, "repeat": rep, "pid": "", "comm": "",
                                     "cves": "", "tool": tool,
                                     "result": "unavailable" if fn is None
                                     else ("alarm_no_stale" if flagged else "quiet_no_stale")})
    # a scanner "has a check" for (distro, cve) only if it flags it on some S0 host of that distro
    flagged_s0 = defaultdict(bool)
    for r in rows:
        if r["host_state"] == "S0" and r["verdict"] == "vulnerable":
            flagged_s0[(r["scanner"], r["distro"], r["cve"])] = True
    for r in rows:
        kernel = cases[r["cve"]].get("kind") == "kernel"
        if not kernel and r["verdict"] == "fixed" and not flagged_s0[(r["scanner"], r["distro"], r["cve"])]:
            r["verdict"] = "no_check"
        r["outcome"] = outcome(r["truth"], r["verdict"])
    out = REPO / "results"
    write_csv(out / "cells.csv", rows)
    write_csv(out / "restart.csv", restart_rows)
    print(f"{len(rows)} verdict rows, {len(restart_rows)} restart rows from {len(allruns)} host runs")


def write_csv(path: Path, rows: list[dict]):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
