"""Build the local OSV-Scanner database used in the lab.

Downloads each ecosystem's all.zip from the public OSV bucket (once), records its hash and
Last-Modified date, and writes a copy that keeps only records naming a studied CVE in id,
aliases, upstream or related. OSV-Scanner matches each record on its own, so the verdict on
a studied CVE does not depend on the records that are dropped; the filtered copy just loads
in seconds instead of minutes.

Run: python lab/tools/osv_filter.py
"""
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / ".cache/osv/osv-scalibr"
DST = REPO / ".cache/osv-filtered/osv-scalibr"
ECOS = ["Ubuntu", "Debian", "Alpine", "Rocky Linux", "AlmaLinux"]
BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"


def studied_cves():
    return {p.stem for p in (REPO / "cases").glob("CVE-*.yml")}


def main(download=False):
    cves = studied_cves()
    meta = {}
    for eco in ECOS:
        src = SRC / eco / "all.zip"
        url = f"{BUCKET}/{eco.replace(' ', '%20')}/all.zip"
        if download or not src.exists():
            src.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(url, src)
        head = urllib.request.urlopen(urllib.request.Request(url, method="HEAD"))
        kept, total = 0, 0
        dst = DST / eco / "all.zip"
        dst.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
            for n in zin.namelist():
                total += 1
                raw = zin.read(n)
                d = json.loads(raw)
                ids = {d.get("id"), *d.get("aliases", []), *d.get("upstream", []), *d.get("related", [])}
                if ids & cves:
                    zout.writestr(n, raw)
                    kept += 1
        meta[eco] = {"url": url, "sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                     "bucket_last_modified_now": head.headers.get("Last-Modified"), "records": total,
                     "kept": kept, "filtered_sha256": hashlib.sha256(dst.read_bytes()).hexdigest()}
        print(eco, total, "->", kept)
    (REPO / "results/feeds").mkdir(parents=True, exist_ok=True)
    (REPO / "results/feeds/osv_db.json").write_text(json.dumps(meta, indent=1) + "\n")


if __name__ == "__main__":
    main(download="--download" in sys.argv)
