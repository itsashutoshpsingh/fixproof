"""Run `fixproof verify` against freshly built lab hosts; writes results/verify_demo/<distro>_<state>.txt."""
import subprocess

from fixproof import lab

REPO = lab.REPO
DEMOS = [("ubuntu-22.04", "S3"), ("ubuntu-22.04", "S2"), ("ubuntu-24.04", "S3")]
CVES = {"ubuntu-22.04": ["CVE-2024-6387", "CVE-2023-4911", "CVE-2023-0286", "CVE-2024-2961", "CVE-2025-32462"],
        "ubuntu-24.04": ["CVE-2024-6387", "CVE-2024-5535", "CVE-2025-32463"]}

for distro, state in DEMOS:
    host = lab.Host(distro, state, 9)
    try:
        host.start()
        for step in host.recipe["steps"]:
            if step != "collect-before":
                host.run_step(step)
        p = subprocess.run(["fixproof", "verify", "--container", host.name, *CVES[distro]], capture_output=True, text=True)
        text = f"$ fixproof verify {' '.join(CVES[distro])}   # on a {distro} host in state {state}\n{p.stdout}{p.stderr}exit code {p.returncode}\n"
        (REPO / f"results/verify_demo/{distro}_{state}.txt").write_text(text)
        print(text)
    finally:
        host.stop()
