#!/usr/bin/env python3
# plot_results.py — Hermes thesis plots
#
# Files expected in ~/hermes/:
#   exp1_results.txt, exp2_1pps.txt, exp2_10pps.txt, exp2_50pps.txt,
#   exp2_100pps.txt, exp3_1pps_verbose.txt … exp3_200pps_verbose.txt,
#   exp3_results.txt
#
# Usage:
#   pip3 install matplotlib numpy --break-system-packages
#   python3 plot_results.py

import os, re
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE     = os.path.expanduser("~/tutorials/exercises/hermes_v2/results")
PLOT_DIR = os.path.join(BASE, "plots")
os.makedirs(PLOT_DIR, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif", "font.size": 11,
    "axes.titlesize": 12, "axes.labelsize": 11,
    "xtick.labelsize": 10, "ytick.labelsize": 10,
    "legend.fontsize": 10, "figure.dpi": 150, "pdf.fonttype": 42,
})
BLUE   = "#2166ac"
ORANGE = "#d6604d"
GREEN  = "#4dac26"
GREY   = "#888888"

def save(fig, name):
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(PLOT_DIR, f"{name}.{ext}"), bbox_inches="tight")
    print(f"  saved {name}.pdf + .png")
    plt.close(fig)

def even_xaxis(ax, rates):
    """Set x-axis to evenly spaced positions labelled with actual rate values."""
    x = list(range(len(rates)))
    ax.set_xticks(x)
    ax.set_xticklabels([str(r) for r in rates])
    ax.set_xlim(-0.3, len(rates) - 0.7)
    return x

PROBE_RE = re.compile(
    r"probe\s+\d+:\s+(ACCEPT|REJECT|TIMEOUT)"
    r"(?:\s+total=([\d.]+)ms\s+digest=([\d.]+)ms\s+verify=([\d.]+)ms)?"
)

def parse_probe_file(path):
    result = {"total": [], "digest": [], "verify": [], "outcomes": []}
    if not os.path.exists(path):
        return result
    with open(path) as f:
        for line in f:
            m = PROBE_RE.search(line)
            if m:
                result["outcomes"].append(m.group(1))
                if m.group(2):
                    result["total"].append(float(m.group(2)))
                    result["digest"].append(float(m.group(3)))
                    result["verify"].append(float(m.group(4)))
    return result

# ─── Experiment 1: DH RTT box plots ──────────────────────────────────────────
def plot_exp1():
    path = os.path.join(BASE, "exp1_results.txt")
    if not os.path.exists(path):
        print("  exp1_results.txt not found — skipping"); return
    raw_data = {}
    with open(path) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        m = re.match(r"s1\s+(\d+)\s+[\d.]+", line)
        if m:
            nk = int(m.group(1))
            j = i + 1
            while j < i + 3 and j < len(lines) and "raw:" not in lines[j]:
                j += 1
            if j < len(lines) and "raw:" in lines[j]:
                rm = re.search(r"\[(.+?)\]", lines[j])
                if rm:
                    raw_data[nk] = [float(x) for x in rm.group(1).split(",")]
    if not raw_data:
        print("  no raw data found — skipping"); return
    nk_vals = sorted(raw_data.keys())
    fig, ax = plt.subplots(figsize=(5, 4))
    bp = ax.boxplot([raw_data[nk] for nk in nk_vals],
                    labels=[str(nk) for nk in nk_vals],
                    patch_artist=True,
                    medianprops=dict(color="black", linewidth=2))
    for patch in bp["boxes"]:
        patch.set_facecolor(BLUE); patch.set_alpha(0.7)
    ax.set_xlabel("Number of keys $N_k$")
    ax.set_ylabel("RTT (ms)")
    ax.set_title("Experiment 1: DH Key-Exchange RTT (30 runs each)")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    save(fig, "exp1_dh_boxplot")

# ─── Experiment 2: latency line graph + box plot ─────────────────────────────
def load_exp2():
    result = {}
    for pps in [1, 10, 50, 100]:
        d = parse_probe_file(os.path.join(BASE+'/exp2', f"exp2_{pps}pps.txt"))
        if d["total"]:
            result[pps] = d
        else:
            print(f"  exp2_{pps}pps.txt: no probe data")
    return result

def plot_exp2():
    data = load_exp2()
    if not data:
        print("  no exp2 data — skipping"); return
    rates  = sorted(data.keys())
    labels = [str(r) for r in rates]
    t_meds = [np.median(data[r]["total"])  for r in rates]
    f_meds = [np.median(data[r]["digest"]) for r in rates]
    v_meds = [np.median(data[r]["verify"]) for r in rates]

    # ── Line graph ─────────────────────────────────────────────────────────────
    x = list(range(len(rates)))
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(x, t_meds, "o-",  color=BLUE,   linewidth=2, markersize=6,
            label="Total $t_{total}$")
    ax.plot(x, f_meds, "s--", color=ORANGE, linewidth=2, markersize=6,
            label="Forwarding $t_f$")
    ax.plot(x, v_meds, "^--", color=GREEN,  linewidth=2, markersize=6,
            label="Verification $t_v$")
    for i, t in enumerate(t_meds):
        ax.annotate(f"{t:.2f}", xy=(i, t), xytext=(0, 6),
                    textcoords="offset points", ha="center",
                    fontsize=8, color=BLUE)
    even_xaxis(ax, rates)
    ax.set_xlabel("Probe rate (pps)")
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("Experiment 2: End-to-End Latency Components vs Probe Rate")
    ax.legend(loc="center right")
    ax.set_ylim(0, 9)
    ax.grid(True, linestyle="--", alpha=0.4)
    save(fig, "exp2_latency_line")

    # ── Box plot ───────────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(6, 4))
    bp = ax.boxplot([data[r]["total"] for r in rates], labels=labels,
                    patch_artist=True,
                    medianprops=dict(color="black", linewidth=2))
    for patch in bp["boxes"]:
        patch.set_facecolor(BLUE); patch.set_alpha(0.7)
    ax.set_xlabel("Probe rate (pps)")
    ax.set_ylabel("Total latency (ms)")
    ax.set_title("Experiment 2: Total Verification Latency Distribution")
    ax.set_ylim(0, 9)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    save(fig, "exp2_latency_box")

# ─── Experiment 3: throughput line graph ─────────────────────────────────────
def load_exp3():
    result = {}
    for pps in [1, 10, 50, 100, 200]:
        d = parse_probe_file(os.path.join(BASE, f"exp3_{pps}pps_verbose.txt"))
        if d["outcomes"]:
            a = d["outcomes"].count("ACCEPT")
            r = d["outcomes"].count("REJECT")
            t = d["outcomes"].count("TIMEOUT")
            result[pps] = (a + r + t, a, r, t)
    if not result:
        csv = os.path.join(BASE, "exp3_results.txt")
        if os.path.exists(csv):
            with open(csv) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("rate_pps") or not line:
                        continue
                    parts = line.split(",")
                    if len(parts) >= 5:
                        pps  = int(parts[0])
                        sent = int(parts[1])
                        a    = int(parts[2]) // 2
                        r    = int(parts[3]) // 2
                        t    = int(parts[4]) // 2
                        result[pps] = (sent, a, r, t)
    return result

def plot_exp3():
    data = load_exp3()
    if not data:
        print("  no exp3 data — skipping"); return
    rates      = sorted(data.keys())
    sent       = [data[r][0] for r in rates]
    accept     = [data[r][1] for r in rates]
    reject     = [data[r][2] for r in rates]
    tmout      = [data[r][3] for r in rates]
    accept_pct = [100.0 * a / s for a, s in zip(accept, sent)]
    reject_pct = [100.0 * r / s for r, s in zip(reject, sent)]
    tmout_pct  = [100.0 * t / s for t, s in zip(tmout,  sent)]

    x = list(range(len(rates)))
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(x, accept_pct, "o-",  color=GREEN,  linewidth=2, markersize=6,
            label="ACCEPT")
    ax.plot(x, reject_pct, "s--", color=ORANGE, linewidth=2, markersize=6,
            label="REJECT")
    ax.plot(x, tmout_pct,  "^--", color=GREY,   linewidth=2, markersize=6,
            label="TIMEOUT")
    ax.axhline(100, color=GREEN, linewidth=0.8, linestyle=":", alpha=0.6)
    for i, (a, s) in enumerate(zip(accept, sent)):
        ax.annotate(f"{a}/{s}", xy=(i, 100.0 * a / s), xytext=(0, 8),
                    textcoords="offset points", ha="center",
                    fontsize=8, color=GREEN)
    even_xaxis(ax, rates)
    ax.set_xlabel("Probe rate (pps)")
    ax.set_ylabel("Outcome (%)")
    ax.set_title("Experiment 3: Verification Success Rate vs Probe Rate")
    ax.legend(loc="center right")
    ax.set_ylim(-5, 115)
    ax.grid(True, linestyle="--", alpha=0.4)
    save(fig, "exp3_throughput")

# ─── Combined latency across all rates ───────────────────────────────────────
def plot_combined_latency():
    all_data = {}
    for pps in [1, 10, 50, 100]:
        d = parse_probe_file(os.path.join(BASE, f"exp2_{pps}pps.txt"))
        if d["total"]:
            all_data[pps] = d
    for pps in [1, 10, 50, 100, 200]:
        if pps not in all_data:
            d = parse_probe_file(
                os.path.join(BASE, f"exp3_{pps}pps_verbose.txt"))
            if d["total"]:
                all_data[pps] = d
    if len(all_data) < 2:
        return
    rates  = sorted(all_data.keys())
    t_meds = [np.median(all_data[r]["total"])  for r in rates]
    d_meds = [np.median(all_data[r]["digest"]) for r in rates]
    v_meds = [np.median(all_data[r]["verify"]) for r in rates]

    x = list(range(len(rates)))
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(x, t_meds, "o-",  color=BLUE,   linewidth=2,
            label="Total $t_{total}$")
    ax.plot(x, d_meds, "s--", color=ORANGE, linewidth=1.5,
            label="Forwarding $t_f$")
    ax.plot(x, v_meds, "^--", color=GREEN,  linewidth=1.5,
            label="Verification $t_v$")
    even_xaxis(ax, rates)
    ax.set_xlabel("Probe rate (pps)")
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("Verification Latency Components vs Probe Rate")
    ax.legend()
    ax.set_ylim(0, 9)
    ax.grid(True, linestyle="--", alpha=0.4)
    save(fig, "combined_latency_vs_rate")

if __name__ == "__main__":
    print(f"Saving to {PLOT_DIR}/")
    plot_exp1()
    plot_exp2()
    plot_exp3()
    plot_combined_latency()
    print("Done.")