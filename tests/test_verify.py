from conftest import FIXED_BID, VULN_BID, proc
from fixproof.verify import assess

D = "ubuntu-22.04"


def test_verify_blocks_on_stale_process(case, make_ev):
    r = assess("CVE-2024-6387", case, D, make_ev("1:8.9p1-3ubuntu0.18", procs=[proc(VULN_BID, True)]))
    assert r["verdict"] == "not remediated" and any("replaced sshd" in b for b in r["blockers"])


def test_verify_passes_clean_host(case, make_ev):
    r = assess("CVE-2024-6387", case, D, make_ev("1:8.9p1-3ubuntu0.18", procs=[proc(FIXED_BID, False)]))
    assert r["verdict"] == "remediated" and not r["blockers"]


def test_verify_blocks_on_old_version(case, make_ev):
    assert assess("CVE-2024-6387", case, D, make_ev())["verdict"] == "not remediated"


def test_verify_flags_unowned_copy(case, make_ev):
    ev = make_ev("1:8.9p1-3ubuntu0.18", procs=[proc(VULN_BID, False, path="/opt/legacy/sshd")])
    r = assess("CVE-2024-6387", case, D, ev)
    assert any("no package owns" in b for b in r["blockers"])
