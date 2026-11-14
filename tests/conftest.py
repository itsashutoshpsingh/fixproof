import copy

import pytest

VULN_BID, FIXED_BID = "a" * 40, "b" * 40


def _ev(**kw):
    ev = {"package_manager": "dpkg", "kernel_running": "6.18.44", "packages": {}, "files": [], "processes": [],
          "mitigation_checks": {}, "file_mtimes": {}, "changelog_cves": {}}
    ev.update(kw)
    return ev


@pytest.fixture
def case():
    return {"cve": "CVE-2024-6387", "files": ["sshd"], "stale_reachable": False,
            "mitigation": {"description": "LoginGraceTime 0", "check": "true", "restart_needed": ["sshd"]},
            "distros": {"ubuntu-22.04": {"fixed": {"openssh-server": "1:8.9p1-3ubuntu0.10"}, "fix_type": "backport"}}}


@pytest.fixture
def index():
    from fixproof.truth import BuildIdIndex
    idx = BuildIdIndex()
    idx.add("ubuntu-22.04", {"files": [
        {"path": "/usr/sbin/sshd", "package": "openssh-server", "version": "1:8.9p1-3", "build_id": VULN_BID},
        {"path": "/usr/sbin/sshd", "package": "openssh-server", "version": "1:8.9p1-3ubuntu0.18", "build_id": FIXED_BID}]})
    return idx


def proc(bid, deleted, path="/usr/sbin/sshd", start=100.0):
    return {"pid": 10, "nspid": 7, "ppid": 1, "comm": "sshd", "cmdline": "sshd", "exe": path, "exe_deleted": deleted,
            "start_time": start, "deleted_mappings": [path] if deleted else [],
            "objects": [{"path": path, "deleted": deleted, "build_id": bid}]}


@pytest.fixture
def make_ev():
    def make(version="1:8.9p1-3", state="installed", procs=(), **kw):
        pk = {"openssh-server": {"version": version, "state": state, "source": "openssh"}} if version else {}
        on_disk = [{"path": "/usr/sbin/sshd", "package": "openssh-server", "version": version,
                    "build_id": VULN_BID if version == "1:8.9p1-3" else FIXED_BID}] if version and state == "installed" else []
        return _ev(packages=pk, files=on_disk, processes=[copy.deepcopy(p) for p in procs], **kw)
    return make
