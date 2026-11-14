"""Portfolio-style charts from results/cells.csv and results/restart.csv -> docs/img/*.png."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

from . import lab  # noqa: E402
from .report import LABEL, STATE_NAMES  # noqa: E402

REPO = lab.REPO
IMG = REPO / "docs/img"
BG, FG, MUTED, GRID = "#0E1522", "#E6EDF5", "#9FB0C3", "#22324A"
BLUE, GREEN, AMBER, RED, CYAN = "#5BA8FF", "#4FD8A0", "#F0B35B", "#FF5C7A", "#6BE4F0"
SC_COLOR = {"trivy": BLUE, "osv-scanner": CYAN, "ssh-banner": AMBER, "fixproof-verify": GREEN}
OUT_COLOR = {"correct": GREEN, "false_fixed": RED, "false_vulnerable": AMBER, "no_check": "#4A5A70",
             "flagged_mitigated": "#B08A4A", "credited_mitigation": GREEN, "error": "#7A2F45"}

plt.rcParams.update({
    "figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG, "text.color": FG,
    "axes.labelcolor": FG, "xtick.color": MUTED, "ytick.color": MUTED, "axes.edgecolor": GRID,
    "grid.color": GRID, "font.family": "DejaVu Sans", "font.size": 10, "axes.titlesize": 12,
    "axes.titleweight": "bold", "legend.frameon": False,
})


def _load():
    cells = list(csv.DictReader(open(REPO / "results/cells.csv")))
    restart = list(csv.DictReader(open(REPO / "results/restart.csv")))
    return cells, restart


def _style(ax, grid_axis="y"):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis=grid_axis, alpha=0.6)
    ax.set_axisbelow(True)


def _bar_labels(ax, bars, fmt="{:.0f}%", vals=None, extra=None):
    for i, b in enumerate(bars):
        v = b.get_height() if vals is None else vals[i]
        txt = fmt.format(v) + (extra[i] if extra else "")
        ax.annotate(txt, (b.get_x() + b.get_width() / 2, b.get_height()), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8, color=FG)


def hero(cells):
    states = ["S0", "S3", "S8", "S9"]
    scanners = ["trivy", "osv-scanner", "ssh-banner"]
    fig, ax = plt.subplots(figsize=(10, 5.2))
    w = 0.26
    for j, s in enumerate(scanners):
        vals, ns, ks = [], [], []
        for st in states:
            rr = [r for r in cells if r["state"] == st and r["scanner"] == s and r["truth"] == "vulnerable"
                  and r["verdict"] != "no_check"]
            k = sum(1 for r in rr if r["verdict"] == "fixed")
            vals.append(100 * k / len(rr) if rr else 0)
            ns.append(len(rr))
            ks.append(k)
        xs = [i + (j - 1) * w for i in range(len(states))]
        bars = ax.bar(xs, vals, w, color=SC_COLOR[s], label=LABEL[s])
        _bar_labels(ax, bars, extra=[f"\n{k}/{n}" if n else "\nn/a" for k, n in zip(ks, ns, strict=True)])
    ax.set_xticks(range(len(states)), [f"{st}\n{STATE_NAMES[st]}" for st in states])
    ax.set_ylabel("vulnerable verdicts reported as not vulnerable (%)")
    ax.set_ylim(0, 125)
    ax.set_title("Once the package is updated, every scanner says fixed, even with the old code still running")
    ax.legend(loc="upper left", ncol=3, fontsize=9)
    _style(ax)
    fig.tight_layout()
    fig.savefig(IMG / "hero_false_fixed.png", dpi=200)
    plt.close(fig)


def cell_grid(cells):
    states = ["S0", "S1", "S2", "S3", "S5", "S6", "S7", "S8", "S9"]
    keys = sorted({(r["distro"], r["cve"]) for r in cells})
    by = defaultdict(list)
    for r in cells:
        by[(r["distro"], r["cve"], r["state"], r["scanner"])].append(r)
    truth = {}
    for r in cells:
        truth.setdefault((r["distro"], r["cve"], r["state"]), Counter())[r["truth"]] += 1
    fig, ax = plt.subplots(figsize=(11, 0.32 * len(keys) + 2.2))
    tcol = {"vulnerable": "#3A1E2A", "fixed": "#173229", "mitigated": "#3A3020"}
    for i, (d, cve) in enumerate(keys):
        y = len(keys) - 1 - i
        for j, st in enumerate(states):
            t = truth.get((d, cve, st))
            if not t:
                continue
            ax.add_patch(Rectangle((j, y), 1, 1, color=tcol[t.most_common(1)[0][0]], ec=BG, lw=1.2))
            for k, s in enumerate(("trivy", "osv-scanner")):
                rr = by.get((d, cve, st, s), [])
                if not rr:
                    continue
                oc = Counter(r["outcome"] for r in rr).most_common(1)[0][0]
                ax.add_patch(Rectangle((j + 0.14 + k * 0.38, y + 0.2), 0.32, 0.6, color=OUT_COLOR[oc]))
    ax.set_xlim(0, len(states))
    ax.set_ylim(0, len(keys))
    ax.set_xticks([j + 0.5 for j in range(len(states))], states)
    ax.set_yticks([len(keys) - 1 - i + 0.5 for i in range(len(keys))], [f"{c}  {d}" for d, c in keys], fontsize=7)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xlabel("host state (cell background = truth: dark red vulnerable, dark green fixed, brown mitigated)")
    ax.set_title("Every cell: left square Trivy, right square OSV-Scanner (red = said fixed, code still vulnerable)")
    handles = [Rectangle((0, 0), 1, 1, color=c) for c in (GREEN, RED, AMBER, OUT_COLOR["flagged_mitigated"],
                                                          OUT_COLOR["no_check"])]
    ax.legend(handles, ["correct", "false fixed", "false vulnerable", "flagged by version (mitigated)", "no check"],
              loc="upper center", bbox_to_anchor=(0.5, -0.035 - 1.0 / max(10, len(keys))), ncol=5, fontsize=8)
    fig.tight_layout()
    fig.savefig(IMG / "cell_grid.png", dpi=200)
    plt.close(fig)


def confusion(cells):
    scanners = ["trivy", "osv-scanner", "ssh-banner", "fixproof-verify"]
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.6))
    truths, verdicts = ["vulnerable", "mitigated", "fixed"], ["vulnerable", "fixed", "no_check"]
    for ax, s in zip(axes, scanners, strict=True):
        c = Counter((r["truth"], r["verdict"]) for r in cells if r["scanner"] == s)
        for i, t in enumerate(truths):
            for j, v in enumerate(verdicts):
                n = c[(t, v)]
                good = (t == "vulnerable" and v == "vulnerable") or (t == "fixed" and v == "fixed")
                bad = (t == "vulnerable" and v == "fixed") or (t == "fixed" and v == "vulnerable")
                col = GREEN if good else RED if bad else "#4A5A70" if v == "no_check" else AMBER
                ax.add_patch(Rectangle((j, 2 - i), 1, 1, color=col, alpha=0.25 + 0.75 * (n > 0), ec=BG, lw=2))
                ax.text(j + 0.5, 2 - i + 0.5, str(n), ha="center", va="center", fontsize=11, color=FG, weight="bold")
        ax.set_xlim(0, 3)
        ax.set_ylim(0, 3)
        ax.set_xticks([0.5, 1.5, 2.5], ["says\nvulnerable", "says\nnot vuln.", "no\ncheck"], fontsize=8)
        ax.set_yticks([2.5, 1.5, 0.5], ["truth\nvulnerable", "truth\nmitigated", "truth\nfixed"], fontsize=8)
        ax.set_title(LABEL[s], fontsize=10)
        ax.tick_params(length=0)
        for sp in ax.spines.values():
            sp.set_visible(False)
    fig.suptitle("Package scanners are right about packages and blind to processes (counts are verdicts)",
                 fontweight="bold", color=FG)
    fig.tight_layout()
    fig.savefig(IMG / "confusion.png", dpi=200)
    plt.close(fig)


def restart_detectors(restart):
    tools = sorted({r["tool"] for r in restart})
    comms = sorted({r["comm"] for r in restart if r["comm"]})
    fig, ax = plt.subplots(figsize=(10, 4.8))
    w = 0.8 / max(1, len(tools))
    colors = [GREEN, BLUE, CYAN]
    for j, t in enumerate(tools):
        vals, lab_ = [], []
        for c in comms:
            rr = [r for r in restart if r["tool"] == t and r["comm"] == c and r["result"] in ("flagged", "missed")]
            k = sum(1 for r in rr if r["result"] == "flagged")
            vals.append(100 * k / len(rr) if rr else 0)
            lab_.append(f"\n{k}/{len(rr)}" if rr else "\nn/a")
        xs = [i + (j - (len(tools) - 1) / 2) * w for i in range(len(comms))]
        bars = ax.bar(xs, vals, w, color=colors[j % 3], label=t)
        _bar_labels(ax, bars, extra=lab_)
    ax.set_xticks(range(len(comms)), comms)
    ax.set_xlabel("process still mapping replaced vulnerable code")
    ax.set_ylabel("processes flagged as needing a restart (%)")
    ax.set_ylim(0, 125)
    ax.set_title("Restart detectors catch daemons, not open sudo sessions or PID 1")
    ax.legend(loc="upper right", fontsize=9)
    _style(ax)
    fig.tight_layout()
    fig.savefig(IMG / "restart_detectors.png", dpi=200)
    plt.close(fig)


def backport_banner(cells):
    groups = [("S2", "fixed by backport"), ("S7", "package removed, config left"), ("S6", "old kernel on disk")]
    scanners = ["trivy", "osv-scanner", "ssh-banner"]
    fig, ax = plt.subplots(figsize=(10, 4.8))
    w = 0.26
    for j, s in enumerate(scanners):
        vals, lab_ = [], []
        for st, _ in groups:
            rr = [r for r in cells if r["state"] == st and r["scanner"] == s and r["truth"] == "fixed"
                  and r["verdict"] != "no_check"]
            k = sum(1 for r in rr if r["verdict"] == "vulnerable")
            vals.append(100 * k / len(rr) if rr else 0)
            lab_.append(f"\n{k}/{len(rr)}" if rr else "\nn/a")
        bars = ax.bar([i + (j - 1) * w for i in range(len(groups))], vals, w, color=SC_COLOR[s], label=LABEL[s])
        _bar_labels(ax, bars, extra=lab_)
    ax.set_xticks(range(len(groups)), [f"{st}\n{n}" for st, n in groups])
    ax.set_ylabel("fixed verdict slots reported as vulnerable (%)")
    ax.set_ylim(0, 125)
    ax.set_title("Backports fool the banner check; leftover packages fool the package scanners")
    ax.legend(loc="upper left", ncol=3, fontsize=9)
    _style(ax)
    fig.tight_layout()
    fig.savefig(IMG / "backport_banner.png", dpi=200)
    plt.close(fig)


def coverage(cells):
    distros = sorted({r["distro"] for r in cells})
    fig, ax = plt.subplots(figsize=(10, 4.8))
    w = 0.38
    for j, s in enumerate(["trivy", "osv-scanner"]):
        vals, lab_ = [], []
        for d in distros:
            rr = [r for r in cells if r["distro"] == d and r["scanner"] == s and r["state"] == "S0"]
            k = sum(1 for r in rr if r["verdict"] == "vulnerable")
            vals.append(100 * k / len(rr) if rr else 0)
            lab_.append(f"\n{k}/{len(rr)}")
        bars = ax.bar([i + (j - 0.5) * w for i in range(len(distros))], vals, w, color=SC_COLOR[s], label=LABEL[s])
        _bar_labels(ax, bars, extra=lab_)
    ax.set_xticks(range(len(distros)), [d.replace("-nginx", "\nnginx").replace("-base", "\nbase") for d in distros],
                  fontsize=8)
    ax.set_ylabel("vulnerable S0 verdict slots flagged (%)")
    ax.set_ylim(0, 125)
    ax.set_title("On vulnerable hosts both scanners flag almost everything, except on Rocky Linux")
    ax.legend(loc="upper left", ncol=2, fontsize=9)
    _style(ax)
    fig.tight_layout()
    fig.savefig(IMG / "coverage.png", dpi=200)
    plt.close(fig)


def pipeline():
    fig, ax = plt.subplots(figsize=(12, 4.6))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 4.6)
    ax.axis("off")

    def box(x, y, w, h, title, body, color):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.04,rounding_size=0.12", fc="#16213A",
                                    ec=color, lw=1.6))
        ax.text(x + w / 2, y + h - 0.22, title, ha="center", va="top", fontsize=10, weight="bold", color=color)
        ax.text(x + w / 2, y + h - 0.6, body, ha="center", va="top", fontsize=7.6, color=FG, linespacing=1.35)

    def arrow(x0, y0, x1, y1):
        ax.annotate("", (x1, y1), (x0, y0), arrowprops={"arrowstyle": "->", "color": MUTED, "lw": 1.4})

    box(0.1, 1.2, 2.3, 2.9, "Lab images", "Ubuntu 20.04 / 22.04 / 24.04:\nrelease pocket = vulnerable,\n"
        "dated snapshot debs cached\n\nDebian 12, Alpine 3.18,\nRocky 9, Alma 9:\nofficial images, old + new", BLUE)
    box(2.9, 1.2, 2.3, 2.9, "Host states", "container, --network none\nS0 vulnerable\nS1/S2 fixed (upstream/backport)\n"
        "S3 updated, not restarted\nS5 mitigated  S6 old kernel\nS7/S8 removed  S9 vendored copy\nx3 repeats", CYAN)
    box(5.7, 2.65, 2.6, 1.45, "Evidence collector", "packages, file build IDs,\n/proc/<pid>/maps + map_files\n"
        "(deleted), kernel, mitigations", GREEN)
    box(5.7, 0.35, 2.6, 1.95, "Scanners, one at a time", "Trivy 0.76.2 (frozen DB)\nOSV-Scanner 2.7.1 (offline)\n"
        "Vuls 0.42 scan (restart)\nneedrestart, SSH banner", AMBER)
    box(8.8, 1.2, 3.0, 2.9, "Scoring", "truth: vulnerable if a vulnerable\nbuild ID is installed or mapped\n"
        "by a running process\n\ncells.csv, restart.csv\nconfusion, false-fixed rate\nsummary.json, charts", RED)
    arrow(2.4, 2.65, 2.9, 2.65)
    arrow(5.2, 3.2, 5.7, 3.3)
    arrow(5.2, 2.0, 5.7, 1.4)
    arrow(8.3, 3.3, 8.8, 3.0)
    arrow(8.3, 1.4, 8.8, 1.9)
    ax.set_title("fixproof pipeline: build the state, prove it, scan it, compare", color=FG)
    fig.tight_layout()
    fig.savefig(IMG / "pipeline.png", dpi=200)
    plt.close(fig)


def main():
    IMG.mkdir(parents=True, exist_ok=True)
    cells, restart = _load()
    hero(cells)
    cell_grid(cells)
    confusion(cells)
    restart_detectors(restart)
    backport_banner(cells)
    coverage(cells)
    pipeline()
    print("charts written to docs/img")
