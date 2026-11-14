"""Truth rule (docs/method.md): a host is vulnerable to a CVE if a vulnerable version of an
affected package is installed as the active version, or a running process (or the running
kernel) has vulnerable code loaded. It is mitigated if the vulnerable code is present but the
vendor's documented mitigation is in force. Anything else is fixed.

"Vulnerable code loaded" is decided by build ID: every file a case names is identified on
disk (with the package version that installed it) in every host built, and a process counts
only if it maps an object whose build ID belongs to a vulnerable version.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

import yaml

from .versions import compare

REPO = Path(__file__).resolve().parents[2]


def load_cases() -> dict[str, dict]:
    return {p.stem: yaml.safe_load(p.read_text()) for p in sorted((REPO / "cases").glob("CVE-*.yml"))}


def interest_files(cases: dict, distro: str) -> set[str]:
    out = set()
    for c in cases.values():
        if distro in c["distros"]:
            out.update(c.get("files") or [])
    return out


def mitigation_checks(cases: dict, distro: str) -> dict[str, str]:
    return {cve: c["mitigation"]["check"] for cve, c in cases.items()
            if distro in c["distros"] and c.get("mitigation")}


class BuildIdIndex:
    """build ID (or sha256) -> (package, version, file names) seen on disk in any lab host of a distro."""

    def __init__(self):
        self.ids: dict[tuple[str, str], dict] = {}

    def add(self, distro: str, evidence: dict):
        for f in evidence.get("files", []):
            # Alpine builds carry no GNU build ID, so the file hash is the fallback identity
            for ident in (f.get("build_id"), f.get("sha256") and "sha256:" + f["sha256"]):
                if not ident:
                    continue
                ent = self.ids.setdefault((distro, ident), {"package": f["package"], "version": f["version"],
                                                            "names": set()})
                ent["names"].update({posixpath.basename(f["path"]),
                                     posixpath.basename(f.get("real_path") or f["path"])})

    def get(self, distro: str, obj: dict) -> dict | None:
        bid = obj.get("build_id")
        if bid and (distro, bid) in self.ids:
            return self.ids[(distro, bid)]
        return self.ids.get((distro, "sha256:" + obj["sha256"])) if obj.get("sha256") else None


def _kernel_tuple(release: str) -> tuple[int, ...]:
    m = re.match(r"(\d+)\.(\d+)", release)
    return tuple(int(x) for x in m.groups()) if m else (0, 0)


def evaluate(cve: str, case: dict, distro: str, ev: dict, index: BuildIdIndex) -> dict:
    d = case["distros"][distro]
    pm = ev["package_manager"]
    basis: list[str] = []
    pkgs = ev["packages"]
    if case.get("kind") == "kernel":
        kpkgs = {n: p["version"] for n, p in pkgs.items()
                 if re.match(r"^(linux-image-\d|kernel-core$)", n) and p.get("state") == "installed"}
        disk = [f"{n} {v}" for n, v in kpkgs.items() if compare(pm, v, d["kernel_fixed"]) < 0]
        run_fixed = _kernel_tuple(ev["kernel_running"]) >= _kernel_tuple(case["running_kernel_fixed_from"])
        if not run_fixed:
            return {"truth": "vulnerable", "basis": [f"running kernel {ev['kernel_running']}"], "stale_only": False,
                    "disk_vulnerable": disk, "running_vulnerable": []}
        basis = [f"running kernel {ev['kernel_running']} has the fix"]
        if disk:
            basis.append("old kernel package on disk only: " + ", ".join(disk))
        return {"truth": "fixed", "basis": basis, "stale_only": False, "disk_vulnerable": disk,
                "running_vulnerable": [], "old_kernel_on_disk": bool(disk)}

    fixed = d["fixed"]
    files = set(case.get("files") or [])
    disk = []
    present = []
    for name, fv in fixed.items():
        p = pkgs.get(name)
        if not p or p.get("state") != "installed":
            continue
        present.append(name)
        if compare(pm, p["version"], fv) < 0:
            disk.append(f"{name} {p['version']} < {fv}")
    running = []
    for proc in ev["processes"]:
        for obj in proc["objects"]:
            ent = index.get(distro, obj)
            if not ent or not (ent["names"] & files) or ent["package"] not in fixed:
                continue
            if compare(pm, ent["version"], fixed[ent["package"]]) < 0:
                running.append({"pid": proc["pid"], "comm": proc["comm"], "path": obj["path"], "package": ent["package"],
                                "deleted": obj["deleted"], "version": ent["version"],
                                "package_file": not obj["path"].startswith("/opt/")})
    basis += [f"installed: {x}" for x in disk]
    stale = [r for r in running if r["deleted"] or not r["package_file"]]
    if stale:
        seen = sorted({f"{r['comm']} maps {posixpath.basename(r['path'])} {r['version']}"
                       f"{' (deleted)' if r['deleted'] else ' (copy outside the package)'}" for r in stale})
        basis += seen
    if not present:
        basis.append("package not installed")
    mitigated = False
    if case.get("mitigation") and (disk or running):
        chk = ev.get("mitigation_checks", {}).get(cve, {})
        mitigated = bool(chk.get("passed"))
        covers = set(case["mitigation"].get("covers") or fixed)
        if any(x.split()[0] not in covers for x in disk) or any(r["package"] not in covers for r in running):
            mitigated = False  # the mitigation does not reach every vulnerable package (e.g. the ssh client)
        need = case["mitigation"].get("restart_needed") or []
        mtime = ev.get("file_mtimes", {}).get("/etc/ssh/sshd_config", 0)
        for proc in ev["processes"]:
            if proc["comm"] in need and proc["start_time"] + 1 < mtime:
                mitigated = False
        if mitigated:
            basis.append("mitigation in force: " + case["mitigation"]["description"])
    truth = "fixed"
    if disk or running:
        truth = "mitigated" if mitigated else "vulnerable"
    return {"truth": truth, "basis": basis, "stale_only": bool(running) and not disk,
            "disk_vulnerable": disk, "running_vulnerable": running}
