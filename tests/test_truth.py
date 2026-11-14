from conftest import FIXED_BID, VULN_BID, proc
from fixproof.truth import evaluate

D = "ubuntu-22.04"


def test_s0_installed_vulnerable(case, index, make_ev):
    t = evaluate("CVE-2024-6387", case, D, make_ev(procs=[proc(VULN_BID, False)]), index)
    assert t["truth"] == "vulnerable" and not t["stale_only"]


def test_s2_updated_and_restarted(case, index, make_ev):
    t = evaluate("CVE-2024-6387", case, D, make_ev("1:8.9p1-3ubuntu0.18", procs=[proc(FIXED_BID, False)]), index)
    assert t["truth"] == "fixed"


def test_s3_stale_process_is_vulnerable(case, index, make_ev):
    t = evaluate("CVE-2024-6387", case, D, make_ev("1:8.9p1-3ubuntu0.18", procs=[proc(VULN_BID, True)]), index)
    assert t["truth"] == "vulnerable" and t["stale_only"]
    assert t["running_vulnerable"][0]["version"] == "1:8.9p1-3"


def test_s7_removed_config_left(case, index, make_ev):
    t = evaluate("CVE-2024-6387", case, D, make_ev(state="config-files"), index)
    assert t["truth"] == "fixed" and "package not installed" in t["basis"]


def test_s8_removed_but_running(case, index, make_ev):
    t = evaluate("CVE-2024-6387", case, D, make_ev(state="config-files", procs=[proc(VULN_BID, True)]), index)
    assert t["truth"] == "vulnerable" and t["stale_only"]


def test_s9_copy_outside_package(case, index, make_ev):
    ev = make_ev("1:8.9p1-3ubuntu0.18", procs=[proc(VULN_BID, False, path="/opt/legacy/sshd")])
    t = evaluate("CVE-2024-6387", case, D, ev, index)
    assert t["truth"] == "vulnerable" and "copy outside the package" in "; ".join(t["basis"])


def test_s5_mitigation_needs_check_and_restart(case, index, make_ev):
    ok = make_ev(procs=[proc(VULN_BID, False, start=200.0)],
                 mitigation_checks={"CVE-2024-6387": {"passed": True}}, file_mtimes={"/etc/ssh/sshd_config": 150.0})
    assert evaluate("CVE-2024-6387", case, D, ok, index)["truth"] == "mitigated"
    stale_daemon = make_ev(procs=[proc(VULN_BID, False, start=100.0)],
                           mitigation_checks={"CVE-2024-6387": {"passed": True}},
                           file_mtimes={"/etc/ssh/sshd_config": 150.0})
    assert evaluate("CVE-2024-6387", case, D, stale_daemon, index)["truth"] == "vulnerable"
    failed = make_ev(mitigation_checks={"CVE-2024-6387": {"passed": False}})
    assert evaluate("CVE-2024-6387", case, D, failed, index)["truth"] == "vulnerable"


def test_mitigation_must_cover_every_vulnerable_package(case, index, make_ev):
    case["mitigation"]["covers"] = ["openssh-server"]
    case["distros"][D]["fixed"]["openssh-client"] = "1:8.9p1-3ubuntu0.10"
    ev = make_ev(mitigation_checks={"CVE-2024-6387": {"passed": True}})
    ev["packages"]["openssh-client"] = {"version": "1:8.9p1-3", "state": "installed", "source": "openssh"}
    assert evaluate("CVE-2024-6387", case, D, ev, index)["truth"] == "vulnerable"


def test_kernel_on_disk_only_is_fixed(make_ev):
    case = {"kind": "kernel", "running_kernel_fixed_from": "6.8",
            "distros": {D: {"kernel_fixed": "5.15.0-101.111"}}}
    ev = make_ev(None)
    ev["packages"]["linux-image-5.15.0-25-generic"] = {"version": "5.15.0-25.25", "state": "installed"}
    t = evaluate("CVE-2024-1086", case, D, ev, None)
    assert t["truth"] == "fixed" and t["old_kernel_on_disk"]
    ev["kernel_running"] = "5.15.0-25-generic"
    assert evaluate("CVE-2024-1086", case, D, ev, None)["truth"] == "vulnerable"


def test_hash_identifies_files_without_build_id(case, make_ev):
    from fixproof.truth import BuildIdIndex
    idx = BuildIdIndex()
    idx.add(D, {"files": [{"path": "/usr/sbin/sshd", "package": "openssh-server", "version": "1:8.9p1-3",
                           "build_id": None, "sha256": "c" * 64}]})
    p = proc(None, True)
    p["objects"][0]["sha256"] = "c" * 64
    t = evaluate("CVE-2024-6387", case, D, make_ev("1:8.9p1-3ubuntu0.18", procs=[p]), idx)
    assert t["truth"] == "vulnerable" and t["stale_only"]
