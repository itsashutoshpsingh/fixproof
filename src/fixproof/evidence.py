"""Ground-truth evidence collector.

Records what is installed and what running processes actually map: package versions from
the package database, the build ID and hash of every file the case files care about, and
for every process the mapped objects that are deleted or of interest, read through
/proc/<pid>/map_files so a deleted library can still be identified. Runs against a lab
container from the Docker host, or against the local machine (``fixproof verify``).
"""

from __future__ import annotations

import gzip
import os
import posixpath
import re
import shlex
import subprocess
import time

from .elf import identify

CLK_TCK = os.sysconf("SC_CLK_TCK")


# ------------------------------------------------------------------ targets

class LocalTarget:
    name = "localhost"

    def __init__(self):
        self.root = "/"

    def sh(self, cmd: str, timeout: int = 120) -> tuple[int, str]:
        p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr

    def pids(self) -> list[int]:
        return sorted(int(d) for d in os.listdir("/proc") if d.isdigit())


class DockerTarget:
    def __init__(self, container: str):
        self.name = container
        pid1 = subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", container],
                              capture_output=True, text=True, check=True).stdout.strip()
        self.root = f"/proc/{pid1}/root"

    def sh(self, cmd: str, timeout: int = 600) -> tuple[int, str]:
        p = subprocess.run(["docker", "exec", self.name, "sh", "-c", cmd], capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout + p.stderr

    def pids(self) -> list[int]:
        out = subprocess.run(["docker", "top", self.name, "-eo", "pid"], capture_output=True, text=True,
                             check=True).stdout.split()[1:]
        return sorted(int(x) for x in out)


# ------------------------------------------------------------------ filesystem helpers

def resolve(root: str, path: str, depth: int = 0) -> str:
    """Resolve ``path`` inside ``root`` following symlinks as the target would see them."""
    if depth > 40:
        raise OSError("symlink loop")
    parts = [p for p in path.split("/") if p and p != "."]
    cur = "/"
    for i, part in enumerate(parts):
        if part == "..":
            cur = posixpath.dirname(cur.rstrip("/")) or "/"
            continue
        nxt = posixpath.join(cur, part)
        full = root.rstrip("/") + nxt
        if os.path.islink(full):
            link = os.readlink(full)
            base = link if link.startswith("/") else posixpath.join(cur, link)
            rest = "/".join(parts[i + 1:])
            return resolve(root, posixpath.join(base, rest) if rest else base, depth + 1)
        cur = nxt
    return root.rstrip("/") + cur


def read_text(root: str, path: str) -> str | None:
    try:
        with open(resolve(root, path), errors="replace") as f:
            return f.read()
    except OSError:
        return None


# ------------------------------------------------------------------ package databases

def _dpkg_packages(root: str) -> tuple[dict, dict]:
    pkgs, files = {}, {}
    text = read_text(root, "/var/lib/dpkg/status") or ""
    for block in text.split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z-]+): ?(.*)$", block, re.M))
        if "Package" not in f:
            continue
        name = f["Package"]
        status = f.get("Status", "")
        state = "installed" if status.endswith(" installed") else status.split()[-1] if status else ""
        pkgs[name] = {"version": f.get("Version", ""), "state": state,
                      "source": (f.get("Source") or name).split()[0], "arch": f.get("Architecture", "")}
        for suffix in (f":{f.get('Architecture', '')}", ""):
            lst = read_text(root, f"/var/lib/dpkg/info/{name}{suffix}.list")
            if lst is not None:
                files[name] = [x for x in lst.splitlines() if x]
                break
    return pkgs, files


def _apk_packages(root: str) -> tuple[dict, dict]:
    pkgs, files = {}, {}
    text = read_text(root, "/lib/apk/db/installed") or ""
    for block in text.split("\n\n"):
        name = ver = origin = None
        cur_dir, flist = "", []
        for line in block.splitlines():
            k, _, v = line.partition(":")
            if k == "P":
                name = v
            elif k == "V":
                ver = v
            elif k == "o":
                origin = v
            elif k == "F":
                cur_dir = v
            elif k == "R":
                flist.append(f"/{cur_dir}/{v}")
        if name:
            pkgs[name] = {"version": ver, "state": "installed", "source": origin or name}
            files[name] = flist
    return pkgs, files


def _rpm_packages(target) -> tuple[dict, dict]:
    pkgs, files = {}, {}
    rc, out = target.sh("rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{SOURCERPM}\\n'")
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        name, ver, srpm = parts
        if ver.startswith("0:"):
            ver = ver[2:]
        src = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", srpm)
        pkgs[name] = {"version": ver, "state": "installed", "source": src}
    return pkgs, files


def _rpm_files(target, names) -> dict:
    files = {}
    for n in names:
        rc, out = target.sh(f"rpm -ql {shlex.quote(n)}")
        if rc == 0:
            files[n] = [x for x in out.splitlines() if x.startswith("/")]
    return files


def package_db(target) -> tuple[str, dict, dict]:
    root = target.root
    if os.path.exists(resolve(root, "/var/lib/dpkg/status")):
        return ("dpkg", *_dpkg_packages(root))
    if os.path.exists(resolve(root, "/lib/apk/db/installed")):
        return ("apk", *_apk_packages(root))
    if os.path.isdir(resolve(root, "/var/lib/rpm")):
        return ("rpm", *_rpm_packages(target))
    return ("none", {}, {})


# ------------------------------------------------------------------ processes

_MAPS = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ (\d+)\s+(.*)$")


def _btime() -> float:
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("btime"):
                return float(line.split()[1])
    return 0.0


def process_info(pid: int, interest: set[str], btime: float) -> dict | None:
    base = f"/proc/{pid}"
    try:
        with open(f"{base}/stat") as f:
            stat = f.read()
        with open(f"{base}/cmdline", "rb") as f:
            cmdline = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
        with open(f"{base}/maps") as f:
            maps = f.read().splitlines()
        exe = os.readlink(f"{base}/exe")
        with open(f"{base}/status") as f:
            nspid = next((ln.split()[-1] for ln in f if ln.startswith("NSpid:")), str(pid))
    except OSError:
        return None
    fields = stat[stat.rindex(")") + 2:].split()
    start = btime + int(fields[19]) / CLK_TCK
    comm = stat[stat.index("(") + 1:stat.rindex(")")]
    seen, objs, deleted_paths = set(), [], set()
    for line in maps:
        m = _MAPS.match(line)
        if not m or not m.group(5).startswith("/"):
            continue
        path = m.group(5)
        deleted = path.endswith(" (deleted)")
        clean = path[: -len(" (deleted)")] if deleted else path
        if deleted:
            deleted_paths.add(clean)
        if clean in seen:
            continue
        name = posixpath.basename(clean)
        if not (deleted or name in interest):
            continue
        seen.add(clean)
        info = identify(f"{base}/map_files/{m.group(1)}-{m.group(2)}")
        objs.append({"path": clean, "deleted": deleted, **info})
    return {"pid": pid, "nspid": int(nspid), "ppid": int(fields[1]), "comm": comm, "cmdline": cmdline[:300],
            "exe": exe.replace(" (deleted)", ""), "exe_deleted": exe.endswith(" (deleted)"),
            "start_time": round(start, 2), "deleted_mappings": sorted(deleted_paths), "objects": objs}


# ------------------------------------------------------------------ collector

def collect(target, interest: set[str], checks: dict[str, str] | None = None,
            watch_files: tuple[str, ...] = ("/etc/ssh/sshd_config",), label: str = "") -> dict:
    root = target.root
    osr = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', read_text(root, "/etc/os-release") or "", re.M))
    pm, pkgs, files = package_db(target)
    if pm == "rpm":
        owners = [n for n in pkgs if n.startswith(("glibc", "openssl", "libcurl", "curl", "sudo", "openssh",
                                                   "kernel", "python3-libs"))]
        files = _rpm_files(target, owners)
    on_disk, interest = [], set(interest)
    for pkg, flist in files.items():
        for path in flist:
            if posixpath.basename(path) in interest:
                full = resolve(root, path)
                if not os.path.isfile(full):
                    continue
                real = "/" + os.path.relpath(full, root) if root != "/" else full
                interest.add(posixpath.basename(real))
                on_disk.append({"path": path, "real_path": real, "package": pkg,
                                "version": pkgs[pkg]["version"], **identify(full)})
    btime = _btime()
    procs = [p for p in (process_info(pid, interest, btime) for pid in target.pids()) if p]
    mit = {}
    for key, cmd in (checks or {}).items():
        rc, out = target.sh(cmd)
        mit[key] = {"rc": rc, "passed": rc == 0, "output": out[-300:]}
    mtimes = {}
    for f in watch_files:
        try:
            mtimes[f] = os.stat(resolve(root, f)).st_mtime
        except OSError:
            pass
    changelog = changelog_cves(target, pm, pkgs, interest_pkgs=list(files))
    return {
        "label": label, "target": target.name, "collected_at": time.time(),
        "os": {"id": osr.get("ID"), "version_id": osr.get("VERSION_ID"), "pretty": osr.get("PRETTY_NAME")},
        "kernel_running": os.uname().release, "package_manager": pm,
        "packages": pkgs, "files": on_disk, "processes": procs, "mitigation_checks": mit,
        "file_mtimes": mtimes, "changelog_cves": changelog,
    }


def changelog_cves(target, pm: str, pkgs: dict, interest_pkgs: list[str]) -> dict:
    """CVE ids named in each package's changelog (vendor evidence of a backport)."""
    out = {}
    for name in interest_pkgs:
        text = None
        if pm == "dpkg":
            src = pkgs.get(name, {}).get("source", name)
            for doc in (name, src):
                p = resolve(target.root, f"/usr/share/doc/{doc}/changelog.Debian.gz")
                if os.path.exists(p):
                    with gzip.open(p, "rt", errors="replace") as f:
                        text = f.read()
                    break
        elif pm == "rpm":
            rc, text = target.sh(f"rpm -q --changelog {shlex.quote(name)}")
        if text:
            out[name] = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
    return out
