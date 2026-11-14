from pathlib import Path

from fixproof.scanners import needrestart, osv, trivy, vuls

DATA = Path(__file__).parent / "data/scanners"


def test_trivy_findings_by_cve():
    r = trivy.parse(DATA / "trivy.json.gz")
    assert {"CVE-2021-3156", "CVE-2022-0778"} <= set(r["findings"])
    assert r["meta"]["version"] == "0.76.2"


def test_osv_matches_cves_named_in_notices():
    r = osv.parse(DATA / "osv.json.gz")
    # USN-5844-1 lists CVE-2023-0286 in "upstream"; the CVE counts as reported
    assert "CVE-2023-0286" in r["findings"] and "CVE-2021-3156" in r["findings"]
    assert not any(k.startswith("UBUNTU-") for k in r["findings"])


def test_needrestart_services():
    r = needrestart.parse(DATA / "needrestart.txt")
    assert r["services"] == ["nginx", "ssh"]


def test_vuls_restart_processes():
    r = vuls.parse(DATA / "vuls.json.gz")
    assert not r["restart_unavailable"]
    assert {p["package"] for ps in r["restart"].values() for p in ps} == {"nginx-core", "openssh-server", "sudo"}
