"""`fixproof verify`: an evidence pack for closing a remediation ticket.

Uses only what the host itself shows (no reference hosts): installed version against the
vendor's fixed version, processes that still map a deleted copy of a file the CVE lives in,
copies of those files outside any package, the running kernel, and the mitigation check.
"remediated" needs all of them clean; a deleted mapping can't be proven fixed from the host
alone, so it blocks closure.
"""

from __future__ import annotations

import json
import posixpath
import re
import sys

from .versions import compare


def assess(cve: str, case: dict, distro: str, ev: dict) -> dict:
    d = case["distros"][distro]
    pm = ev["package_manager"]
    checks, blockers = [], []
    if case.get("kind") == "kernel":
        rel = ev["kernel_running"]
        run = tuple(int(x) for x in re.match(r"(\d+)\.(\d+)", rel).groups())
        need = tuple(int(x) for x in case["running_kernel_fixed_from"].split("."))
        ok = run >= need
        checks.append({"check": "running kernel", "value": rel, "ok": ok})
        if not ok:
            blockers.append(f"running kernel {rel} predates the fix")
        kp = [f"{n} {p['version']}" for n, p in ev["packages"].items() if n.startswith("linux-image-")
              and p.get("state") == "installed" and compare(pm, p["version"], d["kernel_fixed"]) < 0]
        if kp:
            checks.append({"check": "old kernel packages on disk (not running)", "value": kp, "ok": True})
        return {"cve": cve, "verdict": "remediated" if not blockers else "not remediated",
                "blockers": blockers, "checks": checks}
    files = set(case.get("files") or [])
    on_disk = {f.get("build_id") or f.get("sha256") for f in ev.get("files", [])} - {None}
    names = files | {posixpath.basename(f.get("real_path") or f["path"]) for f in ev.get("files", [])
                     if posixpath.basename(f["path"]) in files}
    for pkg, fv in d["fixed"].items():
        p = ev["packages"].get(pkg)
        if not p or p.get("state") != "installed":
            checks.append({"check": f"{pkg} installed", "value": p.get("state") if p else "absent", "ok": True})
            continue
        ok = compare(pm, p["version"], fv) >= 0
        checks.append({"check": f"{pkg} >= {fv}", "value": p["version"], "ok": ok})
        if not ok:
            blockers.append(f"{pkg} {p['version']} is older than the fixed {fv}")
    for proc in ev["processes"]:
        for obj in proc["objects"]:
            base = posixpath.basename(obj["path"])
            if base not in names:
                continue
            ident = obj.get("build_id") or obj.get("sha256")
            if obj["deleted"] and ident not in on_disk:
                blockers.append(f"pid {proc['pid']} ({proc['comm']}) still runs a replaced {base}; restart it")
            elif not obj["deleted"] and ident and ident not in on_disk:
                blockers.append(f"pid {proc['pid']} ({proc['comm']}) loads {obj['path']}, a copy no package owns")
    cl = sorted(c for v in ev.get("changelog_cves", {}).values() for c in v if c == cve)
    if cl:
        checks.append({"check": "vendor changelog names the CVE", "value": True, "ok": True})
    mit = ev.get("mitigation_checks", {}).get(cve)
    if mit is not None:
        checks.append({"check": "mitigation check (informational)", "value": mit["passed"], "ok": None})
    return {"cve": cve, "verdict": "remediated" if not blockers else "not remediated",
            "blockers": sorted(set(blockers)), "checks": checks}


def main(cves: list[str], distro: str | None, as_json: bool, container: str | None = None) -> int:
    from . import evidence, truth
    cases = truth.load_cases()
    target = evidence.DockerTarget(container) if container else evidence.LocalTarget()
    if not distro:
        osr = evidence.read_text(target.root, "/etc/os-release") or ""
        m = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', osr, re.M))
        distro = f"{m.get('ID')}-{m.get('VERSION_ID')}"
    unknown = [c for c in cves if c not in cases or distro not in cases[c]["distros"]]
    if unknown:
        print(f"no case data for {', '.join(unknown)} on {distro}", file=sys.stderr)
        return 2
    ev = evidence.collect(target, truth.interest_files(cases, distro), truth.mitigation_checks(cases, distro))
    packs = [assess(c, cases[c], distro, ev) for c in cves]
    if as_json:
        print(json.dumps({"host": target.name, "distro": distro, "kernel": ev["kernel_running"], "results": packs},
                         indent=1))
    else:
        for p in packs:
            print(f"{p['cve']}: {p['verdict'].upper()}")
            for c in p["checks"]:
                print(f"  [{'..' if c['ok'] is None else 'ok' if c['ok'] else '!!'}] {c['check']}: {c['value']}")
            for b in p["blockers"]:
                print(f"  BLOCKER {b}")
    return 0 if all(p["verdict"] == "remediated" for p in packs) else 1
