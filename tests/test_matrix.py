from fixproof.matrix import banner_verdict, outcome, state_label
from fixproof.report import wilson


def test_outcomes():
    assert outcome("vulnerable", "fixed") == "false_fixed"
    assert outcome("fixed", "vulnerable") == "false_vulnerable"
    assert outcome("mitigated", "vulnerable") == "flagged_mitigated"
    assert outcome("vulnerable", "no_check") == "no_check"
    assert outcome("fixed", "fixed") == "correct"


def test_state_label_from_fix_type():
    assert state_label("SU", {"fix_type": "upstream"}) == "S1"
    assert state_label("SU", {"fix_type": "backport"}) == "S2"
    assert state_label("S3", {}) == "S3"


def test_banner_uses_upstream_version_only():
    case = {"banner_check": {"introduced": "8.5p1", "fixed": "9.8p1"}}
    backported = {"ran": True, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18"}
    assert banner_verdict(case, backported) == "vulnerable"
    assert banner_verdict(case, {"ran": True, "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4"}) == "fixed"
    assert banner_verdict(case, {"ran": False}) is None


def test_wilson_interval():
    lo, hi = wilson(0, 10)
    assert lo == 0 and 0.27 < hi < 0.32
    assert wilson(5, 10)[0] < 0.5 < wilson(5, 10)[1]
