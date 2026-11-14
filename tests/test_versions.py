import json
from pathlib import Path

import pytest

from fixproof.versions import compare

PAIRS = json.loads((Path(__file__).parent / "data/version_pairs.json").read_text())


@pytest.mark.parametrize("row", PAIRS, ids=lambda r: f"{r['kind']}:{r['a']}?{r['b']}")
def test_matches_real_package_manager(row):
    # expected values were produced by dpkg, rpm.labelCompare and apk themselves
    assert compare(row["kind"], row["a"], row["b"]) == row["expected"]
    assert compare(row["kind"], row["b"], row["a"]) == -row["expected"]
