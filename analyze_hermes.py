#!/usr/bin/env python3
"""
analyze_hermes.py  --  turn hermes_bench CSVs into results-section figures+tables
================================================================================
Subcommands:
  throughput  --load load.csv --counters counters.csv [--linkrate 10]
  fct         --tx fct_tx.csv --rx rx.csv [--linkrate 10] [--base-rtt-us 50]
  latency     --in latency.csv          (cols: total_ms,digest_ms,verify_ms)
  demo        fabricate SYNTHETIC inputs + run everything (watermarked output)

All figures are written as PNG + PDF; summary numbers as a LaTeX table.
Demo output is watermarked "SYNTHETIC" and must NOT be used as real results.
"""

import argparse, csv, math, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SYNTH = False   # set by demo


def _wm(ax):
    if SYNTH:
        ax.text(0.5, 0.5, "SYNTHETIC", transform=ax.transAxes, fontsize=46,
                color="0.85", rotation=30, ha="center", va="center", zorder=0)


def _save(fig, stem):
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(f"{stem}.{ext}", dpi=130)
    plt.close(fig)
    print(f"  saved {stem}.png / .pdf")


def _read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


# ───────────────────────────── throughput ───────────────────────────────────
def do_throughput(a):
    rows = _read(a.load)
    sizes = np.array([float(r["frame_size"]) for r in rows])
    pps = np.array([float(r["achieved_pps"]) for r in rows])
    gbps = np.array([float(r["offered_gbps"]) for r in rows])
    order = np.argsort(sizes)
    sizes, pps, gbps = sizes[order], pps[order], gbps[order]

    deliv = None
    if a.counters and os.path.exists(a.counters):
        cr = _read(a.counters)
        # pair before/after by dev_port; delivered pps = d(tx_frames)/d(wall_time)
        byp = {}
        for r in cr:
            byp.setdefault(r["dev_port"], {})[r["phase"]] = r
        d = []
        for port, ph in byp.items():
            if "before" in ph and "after" in ph:
                dt = float(ph["after"]["wall_time"]) - float(ph["before"]["wall_time"])
                df = int(ph["after"]["tx_frames"]) - int(ph["before"]["tx_frames"])
                if dt > 0:
                    d.append(df / dt)
        deliv = np.mean(d) if d else None

    fig, ax = plt.subplots(figsize=(7, 4.4))
    ax.plot(sizes, pps / 1e6, "o-", color="#2e86c1", label="offered at h1 (generator)")
    # line-rate reference (Gbps -> pps for given frame size incl 20B IFG+preamble)
    lr = a.linkrate * 1e9
    line_pps = lr / ((sizes + 20) * 8)
    ax.plot(sizes, line_pps / 1e6, "--", color="0.5", label=f"{a.linkrate:g}G line rate")
    if deliv:
        ax.axhline(deliv / 1e6, color="#27ae60", ls=":", label="delivered at h2 (Tofino counters)")
    _wm(ax)
    ax.set_xlabel("frame size (bytes)")
    ax.set_ylabel("throughput (Mpps)")
    ax.set_title("Forwarding throughput vs frame size")
    ax.legend(); ax.grid(alpha=0.3)
    _save(fig, f"{a.outdir}/fig_throughput_pps")

    # Gbps view
    fig, ax = plt.subplots(figsize=(7, 4.4))
    ax.plot(sizes, gbps, "o-", color="#2e86c1", label="offered goodput at h1")
    ax.axhline(a.linkrate, color="0.5", ls="--", label=f"{a.linkrate:g} Gbps line rate")
    _wm(ax)
    ax.set_xlabel("frame size (bytes)"); ax.set_ylabel("throughput (Gbps)")
    ax.set_title("Forwarding throughput (Gbps) vs frame size")
    ax.legend(); ax.grid(alpha=0.3)
    _save(fig, f"{a.outdir}/fig_throughput_gbps")
    print(f"[throughput] peak offered = {pps.max()/1e6:.3f} Mpps, "
          f"{gbps.max():.3f} Gbps" + (f"; delivered ~{deliv/1e6:.3f} Mpps" if deliv else ""))


# ───────────────────────────── FCT ──────────────────────────────────────────
def do_fct(a):
    tx = _read(a.tx)
    rx = _read(a.rx)
    # last rx time per logical flow
    last_rx = {}
    for r in rx:
        lf = int(r["logical_flow"])
        if lf < 0:
            continue
        t = float(r["rx_time_s"])
        if lf not in last_rx or t > last_rx[lf]:
            last_rx[lf] = t
    recs = []
    for r in tx:
        lf = int(r["logical_flow"])
        if lf in last_rx:
            sz = float(r["size_bytes"])
            fct = last_rx[lf] - float(r["tx_first_s"])
            if fct > 0:
                ideal = sz * 8 / (a.linkrate * 1e9) + a.base_rtt_us * 1e-6
                recs.append((sz, fct, fct / ideal if ideal else float("nan")))
    if not recs:
        print("[fct] no flows matched between tx and rx (check logical_flow tags)")
        return
    recs.sort()
    sz = np.array([r[0] for r in recs])
    fct = np.array([r[1] for r in recs]) * 1e3      # ms
    slow = np.array([r[2] for r in recs])
    print(f"[fct] matched {len(recs)} flows; FCT p50={np.percentile(fct,50):.2f}ms "
          f"p99={np.percentile(fct,99):.2f}ms; slowdown p50={np.percentile(slow,50):.2f}")

    # CDF
    fig, ax = plt.subplots(figsize=(7, 4.4))
    xs = np.sort(fct); ys = np.arange(1, len(xs) + 1) / len(xs)
    ax.plot(xs, ys, color="#c0392b")
    _wm(ax)
    ax.set_xscale("log"); ax.set_xlabel("flow completion time (ms)")
    ax.set_ylabel("CDF"); ax.set_title("Flow completion time (CDF)")
    ax.grid(alpha=0.3, which="both")
    _save(fig, f"{a.outdir}/fig_fct_cdf")

    # FCT vs size (binned p50/p99)
    fig, ax = plt.subplots(figsize=(7, 4.4))

    if len(sz) < 3 or sz.min() == sz.max():
        # Not enough matched flows for binned percentiles.
        ax.scatter(sz, fct, label="matched flow")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("flow size (bytes)")
        ax.set_ylabel("FCT (ms)")
        ax.set_title("FCT vs flow size")
        ax.legend()
        ax.grid(alpha=0.3, which="both")
    else:
        bins = np.logspace(np.log10(sz.min()), np.log10(sz.max()), 12)
        idx = np.digitize(sz, bins)
        cx, p50, p99 = [], [], []

        for b in range(1, len(bins)):
            m = idx == b
            if m.sum() >= 3:
                cx.append(np.median(sz[m]))
                p50.append(np.percentile(fct[m], 50))
                p99.append(np.percentile(fct[m], 99))

        if cx:
            ax.plot(cx, p50, "o-", color="#2e86c1", label="p50")
            ax.plot(cx, p99, "s--", color="#c0392b", label="p99")
            ax.set_yscale("log")
            ax.legend()
        else:
            ax.scatter(sz, fct, label="matched flows")
            ax.set_yscale("log")
            ax.legend()

        ax.set_xscale("log")
        ax.set_xlabel("flow size (bytes)")
        ax.set_ylabel("FCT (ms)")
        ax.set_title("FCT vs flow size")
        ax.grid(alpha=0.3, which="both")

    _wm(ax)
    _save(fig, f"{a.outdir}/fig_fct_vs_size")

    # slowdown vs size
    fig, ax = plt.subplots(figsize=(7, 4.4))

    if len(sz) < 3 or sz.min() == sz.max():
        ax.scatter(sz, slow, label="matched flow")
    else:
        scx, sp50, sp99 = [], [], []

        if "bins" not in locals():
            bins = np.logspace(np.log10(sz.min()), np.log10(sz.max()), 12)

        idx = np.digitize(sz, bins)
        for b in range(1, len(bins)):
            m = idx == b
            if m.sum() >= 3:
                scx.append(np.median(sz[m]))
                sp50.append(np.percentile(slow[m], 50))
                sp99.append(np.percentile(slow[m], 99))

        if scx:
            ax.plot(scx, sp50, "o-", color="#2e86c1", label="p50")
            ax.plot(scx, sp99, "s--", color="#c0392b", label="p99")
        else:
            ax.scatter(sz, slow, label="matched flows")

    ax.axhline(1.0, color="0.5", ls=":")
    _wm(ax)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("flow size (bytes)")
    ax.set_ylabel("slowdown (FCT / ideal)")
    ax.set_title("Normalised FCT (slowdown) vs flow size")
    ax.legend()
    ax.grid(alpha=0.3, which="both")
    _save(fig, f"{a.outdir}/fig_fct_slowdown")

    with open(f"{a.outdir}/table_fct.tex", "w") as f:
        f.write("% FCT summary (generated by analyze_hermes.py)\n")
        f.write("\\begin{tabular}{lrr}\n\\toprule\n")
        f.write("Metric & p50 & p99 \\\\\n\\midrule\n")
        f.write(f"FCT (ms) & {np.percentile(fct,50):.2f} & {np.percentile(fct,99):.2f} \\\\\n")
        f.write(f"Slowdown & {np.percentile(slow,50):.2f} & {np.percentile(slow,99):.2f} \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n")
    print(f"  saved {a.outdir}/table_fct.tex")


# ───────────────────────────── latency ──────────────────────────────────────
def do_latency(a):
    rows = _read(a.infile)
    tot = np.array([float(r["total_ms"]) for r in rows])
    dig = np.array([float(r["digest_ms"]) for r in rows])
    ver = np.array([float(r["verify_ms"]) for r in rows])
    fig, ax = plt.subplots(figsize=(7, 4.4))
    parts = ax.boxplot([dig, ver, tot], labels=["send→digest", "digest→verify", "total"],
                       showfliers=False, patch_artist=True)
    for p, c in zip(parts["boxes"], ["#2e86c1", "#e67e22", "#c0392b"]):
        p.set_facecolor(c); p.set_alpha(0.6)
    _wm(ax)
    ax.set_ylabel("latency (ms)")
    ax.set_title("Per-packet verification latency breakdown")
    ax.grid(alpha=0.3, axis="y")
    _save(fig, f"{a.outdir}/fig_latency_breakdown")
    print(f"[latency] total p50={np.percentile(tot,50):.2f}ms p99={np.percentile(tot,99):.2f}ms "
          f"(digest p50={np.percentile(dig,50):.2f}, verify p50={np.percentile(ver,50):.2f})")


# ───────────────────────────── demo (synthetic) ─────────────────────────────
def do_demo(a):
    global SYNTH
    SYNTH = True
    rng = np.random.default_rng(0)
    od = a.outdir

    # synthetic throughput: python generator caps ~250kpps small, line-limited large
    sizes = [64, 128, 256, 512, 1024, 1500]
    with open(f"{od}/load.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["frame_size", "target_pps", "sent",
                                       "duration_s", "achieved_pps", "offered_gbps"])
        for s in sizes:
            cap = min(260000, 10e9 / ((s + 20) * 8))      # python ceiling vs line
            cap *= rng.uniform(0.9, 1.0)
            w.writerow([s, 0, int(cap * 5), 5.0, f"{cap:.1f}", f"{cap*(s+20)*8/1e9:.4f}"])
    with open(f"{od}/counters.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["phase", "wall_time", "dev_port", "rx_frames",
                                       "tx_frames", "rx_bytes", "tx_bytes"])
        w.writerow(["before", 1000.0, 65, 0, 0, 0, 0])
        w.writerow(["after", 1005.0, 65, 1_200_000, 1_200_000, 9e7, 9e7])

    # synthetic FCT: web-search sizes, completion = serialization + per-pkt verify queueing
    ntx, nrx = [], []
    base = 1000.0
    for fid in range(3000):
        u = rng.random()
        sz = int(np.exp(rng.uniform(math.log(5e3), math.log(2e7))))
        npk = max(1, -(-sz // 1500))
        tx0 = base + fid * 0.003
        # verified completion: serialization + queueing proportional to npkts (per-pkt verify)
        serial = sz * 8 / 10e9
        verify_q = npk * rng.uniform(0.4e-3, 0.9e-3)       # ~0.5ms/pkt control-plane
        last_rx = tx0 + serial + verify_q + rng.uniform(0, 1e-3)
        ntx.append((fid, sz, npk, f"{tx0:.9f}", f"{tx0+serial:.9f}"))
        nrx.append((f"{last_rx:.9f}", npk, fid, npk - 1, 1500))
    with open(f"{od}/fct_tx.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["logical_flow", "size_bytes", "n_pkts",
                                       "tx_first_s", "tx_last_s"]); w.writerows(ntx)
    with open(f"{od}/rx.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["rx_time_s", "seq", "logical_flow",
                                       "pkt_idx", "frame_size"]); w.writerows(nrx)

    # synthetic latency
    with open(f"{od}/latency.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["total_ms", "digest_ms", "verify_ms"])
        for _ in range(500):
            dg = rng.normal(0.6, 0.15); vr = rng.normal(1.1, 0.4)
            w.writerow([f"{dg+vr:.3f}", f"{max(0.05,dg):.3f}", f"{max(0.05,vr):.3f}"])

    class NS:
        pass
    for fn, args in [
        (do_throughput, dict(load=f"{od}/load.csv", counters=f"{od}/counters.csv",
                             linkrate=10.0, outdir=od)),
        (do_fct, dict(tx=f"{od}/fct_tx.csv", rx=f"{od}/rx.csv", linkrate=10.0,
                      base_rtt_us=50.0, outdir=od)),
        (do_latency, dict(infile=f"{od}/latency.csv", outdir=od)),
    ]:
        ns = NS()
        for k, v in args.items():
            setattr(ns, k, v)
        fn(ns)
    print("\n[demo] SYNTHETIC example figures written. These are NOT measurements.")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("throughput"); t.add_argument("--load", required=True)
    t.add_argument("--counters", default=""); t.add_argument("--linkrate", type=float, default=10.0)
    t.add_argument("--outdir", default="."); t.set_defaults(func=do_throughput)

    fc = sub.add_parser("fct"); fc.add_argument("--tx", required=True)
    fc.add_argument("--rx", required=True); fc.add_argument("--linkrate", type=float, default=10.0)
    fc.add_argument("--base-rtt-us", type=float, default=50.0, dest="base_rtt_us")
    fc.add_argument("--outdir", default="."); fc.set_defaults(func=do_fct)

    la = sub.add_parser("latency"); la.add_argument("--in", dest="infile", required=True)
    la.add_argument("--outdir", default="."); la.set_defaults(func=do_latency)

    d = sub.add_parser("demo"); d.add_argument("--outdir", default="."); d.set_defaults(func=do_demo)

    a = p.parse_args(); a.func(a)


if __name__ == "__main__":
    main()
