"""Ask the real package managers to order version pairs; writes tests/data/version_pairs.json.

Run: python lab/tools/version_oracle.py  (needs docker and the lab base images)
"""
import json
import subprocess
from pathlib import Path

PAIRS = {
    "dpkg": [("1:8.9p1-3", "1:8.9p1-3ubuntu0.10"), ("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.9"),
             ("2.35-0ubuntu3", "2.35-0ubuntu3.4"), ("2.35-0ubuntu3.10", "2.35-0ubuntu3.4"),
             ("3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1.8"), ("1.9.15p5-3ubuntu5", "1.9.15p5-3ubuntu5.24.04.1"),
             ("1.8.31-1ubuntu1.5+esm1", "1.8.31-1ubuntu1.5"), ("3.0.11-1~deb12u1", "3.0.11-1~deb12u2"),
             ("3.0.11-1~deb12u2", "3.0.11-1"), ("2.36-9+deb12u3", "2.36-9+deb12u10"), ("1.0~rc1", "1.0"),
             ("1:1.0", "2.0"), ("7.81.0-1", "7.81.0-1ubuntu1.14"), ("0.105-26ubuntu1", "0.105-26ubuntu1.2"),
             ("5.2.4-1", "5.2.4-1ubuntu1.1"), ("1.0a", "1.0+"), ("1.0", "1.0-0"), ("9.6p1-3ubuntu13.3", "9.6p1-3ubuntu13"),
             ("5.15.0-25.25", "5.15.0-101.111"), ("1.10-0ubuntu4", "1.10-0ubuntu4.1")],
    "rpm": [("2.34-60.el9", "2.34-60.el9_2.7"), ("2.34-83.el9.7", "2.34-60.el9_2.7"),
            ("1:3.0.7-6.el9_2", "1:3.0.7-16.el9_2"), ("1:3.0.7-24.el9", "1:3.0.7-16.el9_2"),
            ("7.76.1-23.el9_2.1", "7.76.1-23.el9_2.4"), ("7.76.1-26.el9_3.2", "7.76.1-23.el9_2.4"),
            ("7.76.1-26.el9_3.2.0.1", "7.76.1-26.el9_3.2"), ("1.0~rc1-1", "1.0-1"), ("1.0^git1-1", "1.0-1"),
            ("1.0^git1-1", "1.0.1-1"), ("0:2.34-60.el9", "2.34-60.el9"), ("1.0a-1", "1.0-1"), ("1.0-1", "1:0.5-1"),
            ("3.0.7-24.el9", "1:3.0.7-24.el9")],
    "apk": [("3.1.3-r0", "3.1.4-r0"), ("3.1.4-r1", "3.1.4-r0"), ("3.1.4-r5", "3.1.4-r1"), ("8.4.0-r0", "8.5.0-r0"),
            ("1.36.1-r2", "1.36.1-r7"), ("1.2.4-r1", "1.2.4-r3"), ("1.0_rc1-r0", "1.0-r0"), ("1.0_p1-r0", "1.0-r0"),
            ("1.0a-r0", "1.0-r0"), ("1.0-r10", "1.0-r9"), ("1.10-r0", "1.9-r0"), ("2.0_alpha2-r0", "2.0_beta1-r0")],
}

IMAGES = {"dpkg": "ubuntu:22.04", "rpm": "rockylinux:9.3.20231119", "apk": "alpine:3.18.5"}


def oracle(kind, a, b):
    if kind == "dpkg":
        cmd = f"dpkg --compare-versions '{a}' lt '{b}' && echo -1 || (dpkg --compare-versions '{a}' eq '{b}' && echo 0 || echo 1)"
    elif kind == "rpm":
        cmd = ("python3 -c \"import rpm,sys\n"
               "def s(v):\n e,_,v=v.rpartition(':') if ':' in v else ('0','',v)\n"
               " r=v.rsplit('-',1)\n return (e or '0',r[0],r[1])\n"
               f"print(rpm.labelCompare(s('{a}'),s('{b}')))\"")
    else:
        cmd = f"r=$(apk version -t '{a}' '{b}'); case $r in '<') echo -1;; '=') echo 0;; *) echo 1;; esac"
    out = subprocess.run(["docker", "run", "--rm", "--network", "none", "--memory", "128m", IMAGES[kind], "sh", "-c", cmd],
                         capture_output=True, text=True, check=True).stdout.strip()
    return int(out)


rows = [{"kind": k, "a": a, "b": b, "expected": oracle(k, a, b), "oracle": IMAGES[k]} for k, ps in PAIRS.items() for a, b in ps]
Path(__file__).resolve().parents[2].joinpath("tests/data/version_pairs.json").write_text(json.dumps(rows, indent=1) + "\n")
print(len(rows), "pairs")
