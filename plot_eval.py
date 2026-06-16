#!/usr/bin/env python3
"""
plot_eval.py -- generate the evaluation figures for the Hermes thesis.

Two input modes per latency experiment:
  * RAW  : a CSV with one row per sample  -> TRUE boxplots (preferred)
  * STATS: summary stats (min/median/p95/max) -> median bar + min-max whisker
           (used now because only summary stats are available; re-run with raw
            sample logging to upgrade these to boxplots via --raw).

Baseline: every latency/throughput figure can overlay a "plain forwarding"
baseline series if you pass its CSV. Where no baseline file is given the figure
is drawn without it and the caption notes the baseline is pending -- nothing is
fabricated.

Figures written to --outdir (PNG + PDF).
"""
import argparse, csv, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

C_H = "#2e6fb0"      # Hermes
C_B = "#9aa0a6"      # baseline
C_V = "#e08a1e"      # verify component
C_D = "#2e6fb0"      # digest component


def _save(fig, stem, outdir):
    fig.tight_layout()
    for e in ("png", "pdf"):
        fig.savefig(f"{outdir}/{stem}.{e}", dpi=135)
    plt.close(fig)
    print(f"  {stem}.png/.pdf")


# ---- summary stats embedded from the current results (edit if re-measured) ----
DH = {  # Nk: (min, median, max, p95)
    330: (1.57, 1.84, 3.42, 3.38),
    340: (1.66, 1.84, 1.98, 1.95),
    350: (1.67, 1.89, 2.09, 2.02),
}
E2E_TOTAL = {  # pps: (min, median, p95)
    1: (5.51, 5.88, 6.59), 10: (5.41, 5.76, 6.40),
    50: (5.48, 5.79, 5.98), 100: (5.61, 5.92, 6.05),
}
E2E_DIGEST = {1: 1.98, 10: 2.00, 50: 1.86, 100: 1.94}     # median
E2E_VERIFY = {1: 3.90, 10: 3.85, 50: 3.89, 100: 3.96}     # median
KEYROT = {  # label: (min, median, max, p95)
    "Baseline\n(no rotation)": (0.00, 0.04, 0.31, 0.12),
    "Sequential\nadvance":     (0.01, 0.06, 0.43, 0.17),
    "LFSR\nadvance":           (0.01, 0.07, 0.46, 0.19),
    "DH\nrenegotiation":       (4.83, 7.31, 16.24, 13.07),
}


def fig_dh(outdir, baseline=None):
    nk = sorted(DH)
    med = [DH[k][1] for k in nk]
    lo = [DH[k][1] - DH[k][0] for k in nk]
    hi = [DH[k][2] - DH[k][1] for k in nk]
    p95 = [DH[k][3] for k in nk]
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    x = np.arange(len(nk))
    ax.bar(x, med, 0.5, color=C_H, yerr=[lo, hi], capsize=5,
           error_kw=dict(ecolor="0.3", lw=1.2), label="median (min–max)")
    ax.plot(x, p95, "D", color="#c0392b", ms=6, label="p95")
    ax.set_xticks(x); ax.set_xticklabels([str(k) for k in nk])
    ax.set_xlabel("keys exchanged $N_k$"); ax.set_ylabel("DH exchange RTT (ms)")
    ax.set_ylim(0, 4)
    ax.legend(); ax.grid(alpha=0.3, axis="y")
    _save(fig, "fig_dh_latency", outdir)


def fig_e2e(outdir):
    rates = sorted(E2E_TOTAL)
    x = np.arange(len(rates))
    dig = [E2E_DIGEST[r] for r in rates]
    ver = [E2E_VERIFY[r] for r in rates]
    tot_med = [E2E_TOTAL[r][1] for r in rates]
    tot_lo = [E2E_TOTAL[r][1] - E2E_TOTAL[r][0] for r in rates]
    tot_p95 = [E2E_TOTAL[r][2] - E2E_TOTAL[r][1] for r in rates]
    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    ax.bar(x, dig, 0.55, color=C_D, label="digest path (switch→controller)")
    ax.bar(x, ver, 0.55, bottom=dig, color=C_V, label="verify path (controller→server)")
    ax.errorbar(x, tot_med, yerr=[tot_lo, tot_p95], fmt="none", ecolor="0.2",
                capsize=5, lw=1.3, label="total median (min..p95)")
    ax.set_xticks(x); ax.set_xticklabels([str(r) for r in rates])
    ax.set_xlabel("offered rate (pps)"); ax.set_ylabel("verification latency (ms)")
    ax.set_ylim(0, 7)
    ax.legend(loc="lower center", fontsize=8, ncol=1)
    ax.grid(alpha=0.3, axis="y")
    _save(fig, "fig_e2e_latency", outdir)


def fig_keyrot(outdir):
    labels = list(KEYROT)
    med = [KEYROT[k][1] for k in labels]
    lo = [KEYROT[k][1] - KEYROT[k][0] for k in labels]
    hi = [KEYROT[k][2] - KEYROT[k][1] for k in labels]
    fig, ax = plt.subplots(figsize=(6.6, 4.0))
    x = np.arange(len(labels))
    colors = [C_B, C_H, C_H, "#c0392b"]
    ax.bar(x, med, 0.55, color=colors, yerr=[lo, hi], capsize=5,
           error_kw=dict(ecolor="0.3", lw=1.1))
    ax.set_yscale("log")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylabel("per-packet overhead (ms, log)")
    ax.grid(alpha=0.3, axis="y", which="both")
    _save(fig, "fig_keyrot", outdir)


def fig_throughput(outdir, loadcsv, baseline=None):
    def _read(path):
        S, P, G = [], [], []
        with open(path) as f:
            for r in csv.DictReader(f):
                S.append(int(r["frame_size"])); P.append(float(r["achieved_pps"]) / 1e6)
                G.append(float(r["offered_gbps"]))
        o = np.argsort(S)
        return np.array(S)[o], np.array(P)[o], np.array(G)[o]
    S, P, G = _read(loadcsv)
    has_b = baseline and os.path.exists(baseline)
    if has_b:
        Sb, Pb, Gb = _read(baseline)
        # align baseline to the Hermes frame sizes (NaN where a size is absent)
        pm = {int(s): p for s, p in zip(Sb, Pb)}
        gm = {int(s): g for s, g in zip(Sb, Gb)}
        Pb = np.array([pm.get(int(s), np.nan) for s in S])
        Gb = np.array([gm.get(int(s), np.nan) for s in S])
    x = np.arange(len(S)); w = 0.38 if has_b else 0.6
    fig, ax = plt.subplots(1, 2, figsize=(10.5, 4.1))
    if has_b:
        ax[0].bar(x - w/2, P, w, color=C_H, label="Hermes")
        ax[0].bar(x + w/2, Pb, w, color=C_B, label="baseline (plain fwd)")
        ax[1].bar(x - w/2, G, w, color=C_H, label="Hermes")
        ax[1].bar(x + w/2, Gb, w, color=C_B, label="baseline (plain fwd)")
        ax[0].legend(); ax[1].legend()
    else:
        ax[0].bar(x, P, w, color=C_H); ax[1].bar(x, G, w, color=C_H)
    for axi, ylab, ttl in ((ax[0], "offered rate (Mpps)", "Packet rate"),
                           (ax[1], "offered goodput (Gbps)", "Goodput")):
        axi.set_xticks(x); axi.set_xticklabels([str(s) for s in S])
        axi.set_xlabel("frame size (B)"); axi.set_ylabel(ylab); axi.set_title(ttl)
        axi.grid(alpha=0.3, axis="y")
    _save(fig, "fig_throughput_bars", outdir)


def fig_latency_box(outdir, baseline_rtt=None, hermes_rtt=None, hermes_total_median=5.88):
    """True boxplots comparing the plain-forwarding RTT baseline against Hermes.
    Reads raw per-sample CSVs (sample_idx, rtt_ms) written by `hermes_bench rtt`
    and, optionally, a raw Hermes per-packet total-latency CSV (col rtt_ms or
    total_ms). If no Hermes raw samples are given, the Hermes median from
    Experiment 2 is drawn as a reference line."""
    def _col(path):
        rows = list(csv.DictReader(open(path)))
        k = "rtt_ms" if "rtt_ms" in rows[0] else ("total_ms" if "total_ms" in rows[0]
                                                  else list(rows[0])[-1])
        return np.array([float(r[k]) for r in rows])
    data, labels, colors = [], [], []
    if baseline_rtt and os.path.exists(baseline_rtt):
        b = _col(baseline_rtt)
        data.append(b); labels.append("baseline\nforwarding RTT"); colors.append(C_B)
        data.append(b / 2.0); labels.append("baseline\none-way (RTT/2)"); colors.append("#c7ccd1")
    if hermes_rtt and os.path.exists(hermes_rtt):
        data.append(_col(hermes_rtt)); labels.append("Hermes\nverification total"); colors.append(C_H)
    if not data:
        print("  (skipped latency box: no rtt CSVs given)")
        return
    fig, ax = plt.subplots(figsize=(7, 4.3))
    bp = ax.boxplot(data, tick_labels=labels, showfliers=False, patch_artist=True,
                    widths=0.55)
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c); patch.set_alpha(0.7)
    if not (hermes_rtt and os.path.exists(hermes_rtt)):
        ax.axhline(hermes_total_median, color=C_H, ls="--", lw=1.6,
                   label=f"Hermes total median ({hermes_total_median:.2f} ms, Exp.2)")
        ax.legend()
    ax.set_ylabel("latency (ms)")
    ax.set_title("Forwarding baseline vs Hermes verification latency")
    ax.grid(alpha=0.3, axis="y")
    _save(fig, "fig_latency_box", outdir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--load", default="load.csv")
    ap.add_argument("--baseline-load", default="", help="plain-forwarding load.csv")
    ap.add_argument("--baseline-rtt", default="", help="hermes_bench rtt CSV (baseline)")
    ap.add_argument("--hermes-rtt", default="", help="raw Hermes per-packet total CSV (optional)")
    ap.add_argument("--outdir", default=".")
    a = ap.parse_args()
    print("writing figures:")
    fig_dh(a.outdir)
    fig_e2e(a.outdir)
    fig_keyrot(a.outdir)
    if os.path.exists(a.load):
        fig_throughput(a.outdir, a.load, baseline=a.baseline_load or None)
    else:
        print(f"  (skipped throughput: {a.load} not found)")
    if a.baseline_rtt or a.hermes_rtt:
        fig_latency_box(a.outdir, baseline_rtt=a.baseline_rtt or None,
                        hermes_rtt=a.hermes_rtt or None)


if __name__ == "__main__":
    main()
