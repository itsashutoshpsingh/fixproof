"""fixproof command line.

  fixproof images            build the Ubuntu lab images, pull the official ones, record digests
  fixproof run [--repeats N] [--only distro/state ...]   build, collect and scan every host
  fixproof score             truth + verdicts -> results/cells.csv and summaries
  fixproof report            tables and results/summary.json
  fixproof charts            docs/img/*.png
  fixproof verify CVE...     evidence pack for this machine or --container NAME
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback

from . import lab


def all_hosts() -> list[tuple[str, str]]:
    cfg, hosts = lab.load_images(), lab.load_hosts()
    out = [(d, s) for d in cfg["ubuntu"] for s in hosts["ubuntu_states"]]
    out += [(d, s) for d in cfg["official"] for s in hosts["official_states"]]
    return [h for h in out if f"{h[0]}/{h[1]}" not in hosts.get("skip", [])]


def cmd_images(args):
    cfg = lab.load_images()
    rec = {}
    for d in cfg["ubuntu"]:
        if args.build:
            print("building", d, flush=True)
            lab.build_ubuntu(d)
        rec[d] = {"s0": lab.image_digest(lab.ubuntu_tag(d)), "base": cfg["ubuntu"][d]["base"]}
    for d, spec in cfg["official"].items():
        rec[d] = {}
        for k in ("old", "new"):
            if lab.sh(["docker", "image", "inspect", spec[k]], check=False).returncode:
                lab.sh(["docker", "pull", "-q", spec[k]])
            rec[d][k] = lab.image_digest(spec[k])
    (lab.REPO / "results/lab_images.json").write_text(json.dumps(rec, indent=1) + "\n")
    print("wrote results/lab_images.json")


def cmd_run(args):
    from .run import RAW, run_host
    hosts = all_hosts()
    if args.only:
        hosts = [h for h in hosts if any(f"{h[0]}/{h[1]}".startswith(o) for o in args.only)]
    for rep in range(1, args.repeats + 1):
        for d, s in hosts:
            done = RAW / d / s / f"r{rep}" / "run.json"
            if done.exists() and not args.force and "scans" in json.loads(done.read_text()):
                continue
            t0 = time.time()
            try:
                run_host(d, s, rep)
                print(f"ok   {d} {s} r{rep} {time.time() - t0:.0f}s", flush=True)
            except Exception as e:  # keep going; the failure is in run.json and the log
                print(f"FAIL {d} {s} r{rep}: {e}", flush=True)
                traceback.print_exc()


def cmd_verify(args):
    from .verify import main as verify_main
    return verify_main(args.cves, args.distro, args.json, args.container)


def main(argv=None):
    p = argparse.ArgumentParser(prog="fixproof")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("images")
    s.add_argument("--build", action="store_true")
    s.set_defaults(func=cmd_images)
    s = sub.add_parser("run")
    s.add_argument("--repeats", type=int, default=3)
    s.add_argument("--only", nargs="*")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_run)
    s = sub.add_parser("score")
    s.set_defaults(func=lambda a: __import__("fixproof.matrix", fromlist=["main"]).main())
    s = sub.add_parser("report")
    s.set_defaults(func=lambda a: __import__("fixproof.report", fromlist=["main"]).main())
    s = sub.add_parser("charts")
    s.set_defaults(func=lambda a: __import__("fixproof.charts", fromlist=["main"]).main())
    s = sub.add_parser("verify")
    s.add_argument("cves", nargs="+")
    s.add_argument("--distro", help="case-file distro key, e.g. ubuntu-22.04 (default: from os-release)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--container", help="check a running container instead of this machine")
    s.set_defaults(func=cmd_verify)
    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
