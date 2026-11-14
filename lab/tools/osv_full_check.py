"""Check that filtering the OSV database does not change verdicts on the studied CVEs.

Builds one vulnerable (S0) and one updated-not-restarted (S3) host per distro, snapshots it,
and runs OSV-Scanner twice on the same snapshot: with the full per-ecosystem export and with
the filtered copy. Writes results/osv_full_db_check.json.

Run: python lab/tools/osv_full_check.py   (after `make feeds`; one host at a time)
"""
import json
import subprocess
import time

from fixproof import lab, run, truth
from fixproof.scanners import osv

REPO = lab.REPO
HOSTS = [("ubuntu-22.04", "S0"), ("ubuntu-22.04", "S3"), ("ubuntu-20.04", "S0"), ("ubuntu-24.04", "S0"),
         ("debian-12-nginx", "S0"), ("alpine-3.18-nginx", "S0"), ("rocky-9", "S0"), ("alma-9", "S0")]


def main():
    cases = truth.load_cases()
    out = []
    for distro, state in HOSTS:
        host = lab.Host(distro, state, 0)
        snap = run.WORK / f"{host.name}-osvcheck.tar"
        run.WORK.mkdir(exist_ok=True)
        try:
            host.start()
            for step in host.recipe["steps"]:
                if step != "collect-before":
                    host.run_step(step)
            tag = f"fixproof-snap/{host.name.lower()}-osvcheck:latest"
            lab.sh(["docker", "commit", host.name, tag])
            lab.sh(["docker", "save", "-o", str(snap), tag])
            lab.sh(["docker", "rmi", "-f", tag], check=False)
        finally:
            host.stop()
        studied = {c for c, v in cases.items() if distro in v["distros"]}
        res = {}
        for label, db in (("filtered", REPO / ".cache/osv-filtered"), ("full", REPO / ".cache/osv")):
            t0 = time.time()
            osv.MEM = "2500m"
            meta = osv.run(snap, run.WORK / f"osvcheck-{label}.json.gz", REPO / ".tools/osv-scanner", db)
            parsed = osv.parse(run.WORK / f"osvcheck-{label}.json.gz")
            res[label] = {"seconds": round(time.time() - t0, 1), "rc": meta["rc"],
                          "studied_cves_flagged": sorted(set(parsed["findings"]) & studied),
                          "all_cves_flagged": len(parsed["findings"])}
        snap.unlink(missing_ok=True)
        same = res["filtered"]["studied_cves_flagged"] == res["full"]["studied_cves_flagged"]
        out.append({"distro": distro, "state": state, "same_verdicts_on_studied_cves": same, **res})
        print(distro, state, "same" if same else "DIFFERENT", res["full"]["seconds"], "s full", flush=True)
    (REPO / "results/osv_full_db_check.json").write_text(json.dumps(out, indent=1) + "\n")
    subprocess.run(["docker", "ps", "-a", "--filter", "name=fp-", "--format", "{{.Names}}"])


if __name__ == "__main__":
    main()
