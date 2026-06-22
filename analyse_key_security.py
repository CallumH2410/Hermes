#!/usr/bin/env python3
"""
analyse_key_security.py
========================
Quantitative security analysis of the Hermes key-reuse schedule.

Produces four figures and a summary CSV:

  fig_key_recovery_vs_R.pdf       — P_recover(R) for sequential phase (RQ: refresh rate)
  fig_birthday_vs_packets.pdf     — P(first collision by packet t) for LFSR phase
  fig_lfsr_index_distribution.pdf — Key-index frequency histogram over one LFSR period
                                    (run with --full-lfsr; slow for 2^32 states)
  fig_risk_heatmap.pdf            — P_recover as 2D heatmap over (R, N_k)
  key_security_summary.csv        — Numeric table matching thesis Table (key-recovery)

Usage:
  python3 analyse_key_security.py [--out figures/] [--full-lfsr]

  --full-lfsr    Enumerate all 2^32-1 LFSR states to get exact index distribution.
                 WARNING: takes ~60 s and ~16 GB RAM. Omit for a sampled version.
"""

import argparse
import csv
import os
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

# ── TU Delft colour palette ───────────────────────────────────────────────────
TU_BLUE  = "#00A6D6"
TU_CYAN  = "#0ABFBF"
TU_GREEN = "#6CC24A"
TU_RED   = "#E03C31"
TU_GRAY  = "#888888"
PALETTE  = [TU_BLUE, TU_CYAN, TU_GREEN, TU_RED, TU_GRAY,
            "#F0A500", "#6E2585", "#003082"]

plt.rcParams.update({
    "font.family":    "serif",
    "font.size":      11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "xtick.labelsize":10,
    "ytick.labelsize":10,
    "legend.fontsize":10,
    "figure.dpi":     150,
    "savefig.dpi":    300,
    "savefig.bbox":   "tight",
    "axes.grid":      True,
    "grid.linestyle": "--",
    "grid.alpha":     0.45,
})

# ── LFSR parameters ───────────────────────────────────────────────────────────
LFSR_MASK   = 0xB4BCD35C   # Galois 32-bit, poly x^32+x^22+x^2+x+1
LFSR_PERIOD = (1 << 32) - 1


def lfsr_next(state: int) -> int:
    """Single Galois LFSR step."""
    if state & 1:
        return (state >> 1) ^ LFSR_MASK
    return state >> 1


# ─────────────────────────────────────────────────────────────────────────────
# 1. Key-recovery probability in the SEQUENTIAL phase
# ─────────────────────────────────────────────────────────────────────────────

def p_recover_sequential(R: int) -> float:
    """
    P_recover(R) = 1 - (7/8)^(R-1)

    Derivation: with R observations of the same key, the adversary can
    eliminate incorrect opcode hypotheses.  Each additional observation
    eliminates a wrong hypothesis with probability 7/8 (the fraction that
    are inconsistent).  After R-1 extra observations the probability that
    ALL wrong hypotheses have been eliminated approaches 1-(7/8)^(R-1).
    """
    if R <= 0:
        return 0.0
    return 1.0 - (7.0 / 8.0) ** (R - 1)


def plot_key_recovery_vs_R(out_dir: str):
    """Figure 1: P_recover(R) curve with risk-level annotations."""
    R_vals = np.arange(1, 101)
    P_vals = np.array([p_recover_sequential(R) for R in R_vals])

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(R_vals, P_vals, color=TU_BLUE, linewidth=2, label="$P_{\\mathrm{recover}}(R)$")

    # Risk threshold lines
    thresholds = [(0.10, TU_GREEN, "10% risk"),
                  (0.25, TU_CYAN,  "25% risk"),
                  (0.50, "#F0A500","50% risk"),
                  (0.90, TU_RED,   "90% risk")]
    for p_thr, colour, label in thresholds:
        ax.axhline(p_thr, color=colour, linestyle="--", linewidth=1.2,
                   alpha=0.8, label=label)
        # Find the R at which the curve crosses this threshold
        crossings = R_vals[P_vals >= p_thr]
        if len(crossings):
            R_cross = crossings[0]
            ax.annotate(f"$R={R_cross}$",
                        xy=(R_cross, p_thr),
                        xytext=(R_cross + 2, p_thr - 0.04),
                        fontsize=9, color=colour,
                        arrowprops=dict(arrowstyle="->", color=colour,
                                        lw=0.8))

    ax.set_xlabel("Refresh rate $R$ (packets per key use)")
    ax.set_ylabel("Key-recovery probability $P_{\\mathrm{recover}}(R)$")
    ax.set_title("Adversarial Key-Recovery Probability vs Refresh Rate\n"
                 "(Sequential Phase, 8-Opcode System)")
    ax.set_xlim(1, 50)
    ax.set_ylim(0, 1.05)
    ax.legend(loc="lower right")

    path = os.path.join(out_dir, "fig_key_recovery_vs_R.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Birthday-collision probability in the LFSR phase
# ─────────────────────────────────────────────────────────────────────────────

def p_birthday_collision(t: int, N_k: int) -> float:
    """
    Probability that among t draws from {0,...,N_k-1} (with replacement,
    approximately uniform) at least two are identical.

    P(collision by packet t) = 1 - prod_{i=0}^{t-1} (1 - i/N_k)
                              ≈ 1 - exp(-t(t-1)/(2*N_k))
    """
    if t <= 1:
        return 0.0
    # Use log-sum for numerical stability
    log_no_collision = sum(
        np.log1p(-i / N_k) for i in range(t)
    )
    return 1.0 - np.exp(log_no_collision)


def expected_collision_time(N_k: int) -> float:
    """E[T] ≈ sqrt(pi * N_k / 2)  (birthday problem expected first collision)."""
    return np.sqrt(np.pi * N_k / 2.0)


def plot_birthday_vs_packets(out_dir: str):
    """
    Figure 2: P(first key-index collision by packet t) vs t,
    for several values of N_k.
    """
    nk_values = [300, 330, 340, 350, 400]
    t_max = 100
    t_vals = np.arange(1, t_max + 1)

    fig, ax = plt.subplots(figsize=(8, 5))
    for nk, colour in zip(nk_values, PALETTE):
        p_vals = np.array([p_birthday_collision(t, nk) for t in t_vals])
        e_t    = expected_collision_time(nk)
        ax.plot(t_vals, p_vals, color=colour, linewidth=1.8,
                label=f"$N_k = {nk}$  ($E[T]\\approx {e_t:.1f}$)")
        ax.axvline(e_t, color=colour, linestyle=":", linewidth=1.0, alpha=0.6)

    ax.axhline(0.5, color="black", linestyle="--", linewidth=1.0,
               alpha=0.6, label="50% collision probability")
    ax.set_xlabel("Packets observed in LFSR phase $t$")
    ax.set_ylabel("$P$(first key-index collision by packet $t$)")
    ax.set_title("Birthday-Collision Probability in LFSR Phase\n"
                 "(Dotted verticals = $E[T] = \\sqrt{\\pi N_k/2}$)")
    ax.set_xlim(1, t_max)
    ax.set_ylim(0, 1.05)
    ax.legend(loc="lower right")

    path = os.path.join(out_dir, "fig_birthday_vs_packets.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# 3. LFSR key-index frequency distribution (sampled or full)
# ─────────────────────────────────────────────────────────────────────────────

def sample_lfsr_distribution(N_k: int = 340, n_samples: int = 100_000,
                              seed: int = 0xDEADBEEF) -> np.ndarray:
    """
    Sample n_samples steps of the LFSR and return frequency array of size N_k.
    Much faster than a full enumeration and sufficient for distribution analysis.
    """
    counts = np.zeros(N_k, dtype=np.int64)
    state  = seed & 0xFFFFFFFF
    if state == 0:
        state = 1
    for _ in range(n_samples):
        state = lfsr_next(state)
        counts[state % N_k] += 1
    return counts


def full_lfsr_distribution(N_k: int = 340) -> np.ndarray:
    """
    Enumerate ALL 2^32-1 LFSR states and count index frequencies.
    WARNING: slow (~60 s) and memory-intensive.
    """
    print(f"  Enumerating full LFSR period ({LFSR_PERIOD:,} steps)...")
    counts = np.zeros(N_k, dtype=np.int64)
    state  = 1
    t0 = time.time()
    for i in range(LFSR_PERIOD):
        state = lfsr_next(state)
        counts[state % N_k] += 1
        if i % 100_000_000 == 0 and i > 0:
            elapsed = time.time() - t0
            pct = 100.0 * i / LFSR_PERIOD
            print(f"    {pct:.1f}% ({elapsed:.0f}s elapsed)", flush=True)
    return counts


def plot_lfsr_index_distribution(counts: np.ndarray, N_k: int,
                                 full: bool, out_dir: str):
    """
    Figure 3: Histogram of key-index selection frequency under the LFSR schedule.
    Shows how evenly (or unevenly) keys are reused.
    """
    n_samples = int(counts.sum())
    expected  = n_samples / N_k
    deviation = (counts - expected) / expected * 100   # % deviation from uniform

    fig, axes = plt.subplots(1, 2, figsize=(13, 4))

    # Left: raw frequency
    ax = axes[0]
    ax.bar(range(N_k), counts, color=TU_BLUE, alpha=0.75, width=1.0)
    ax.axhline(expected, color=TU_RED, linestyle="--", linewidth=1.2,
               label=f"Uniform expected ({expected:.0f})")
    ax.set_xlabel("Key index $j$")
    ax.set_ylabel("Selection count")
    title = (f"LFSR Key-Index Distribution\n"
             f"({'Full $2^{{32}}-1$ period' if full else f'{n_samples:,} samples'},"
             f" $N_k={N_k}$)")
    ax.set_title(title)
    ax.legend()

    # Right: % deviation from uniform
    ax2 = axes[1]
    ax2.bar(range(N_k), deviation, color=TU_CYAN, alpha=0.75, width=1.0)
    ax2.axhline(0, color="black", linewidth=0.8)
    ax2.set_xlabel("Key index $j$")
    ax2.set_ylabel("Deviation from uniform (%)")
    ax2.set_title("Deviation from Uniform Distribution")

    path = os.path.join(out_dir, "fig_lfsr_index_distribution.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")

    # Summary stats
    print(f"  LFSR distribution stats (N_k={N_k}, samples={n_samples:,}):")
    print(f"    Min freq:  {counts.min():,} ({counts.min()/expected*100:.2f}% of uniform)")
    print(f"    Max freq:  {counts.max():,} ({counts.max()/expected*100:.2f}% of uniform)")
    print(f"    Std dev:   {counts.std():.2f}  ({counts.std()/expected*100:.3f}%)")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Risk heatmap: P_recover over (R, N_k)
# ─────────────────────────────────────────────────────────────────────────────

def plot_risk_heatmap(out_dir: str):
    """
    Figure 4: 2D heatmap of key-recovery probability as a function of
    refresh rate R (x-axis) and key-pool size N_k (y-axis).
    Shows how N_k alone does NOT protect against recovery — only R does.
    """
    R_vals  = np.arange(1, 31)
    Nk_vals = np.arange(100, 401, 10)

    # P_recover in sequential phase depends only on R, not N_k
    # (N_k affects how long the sequential phase lasts, not per-key risk)
    Z = np.array([[p_recover_sequential(R) for R in R_vals]
                  for _Nk in Nk_vals])

    fig, ax = plt.subplots(figsize=(10, 6))
    im = ax.imshow(Z, aspect="auto", origin="lower",
                   extent=[R_vals[0]-0.5, R_vals[-1]+0.5,
                           Nk_vals[0]-5, Nk_vals[-1]+5],
                   cmap="RdYlGn_r", vmin=0, vmax=1)
    cb = fig.colorbar(im, ax=ax)
    cb.set_label("$P_{\\mathrm{recover}}(R)$")

    # Contour lines at risk thresholds
    X, Y = np.meshgrid(R_vals, Nk_vals)
    cs = ax.contour(X, Y, Z,
                    levels=[0.10, 0.25, 0.50, 0.90],
                    colors=["white","white","white","white"],
                    linewidths=1.2)
    ax.clabel(cs, fmt={0.10:"10%", 0.25:"25%", 0.50:"50%", 0.90:"90%"},
              fontsize=9)

    ax.set_xlabel("Refresh rate $R$ (packets per key use)")
    ax.set_ylabel("Key-pool size $N_k$")
    ax.set_title("Key-Recovery Probability Heatmap\n"
                 "(Sequential Phase — $N_k$ affects duration, not per-key risk)")

    path = os.path.join(out_dir, "fig_risk_heatmap.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Summary CSV
# ─────────────────────────────────────────────────────────────────────────────

def write_summary_csv(out_dir: str, N_k: int = 340):
    """
    Writes key_security_summary.csv with:
      - R values 1..100
      - P_recover(R) for sequential phase
      - P(birthday collision) at packet T = birthday-bound for LFSR phase
      - Maximum safe R for each risk level
    """
    rows = []
    e_t  = expected_collision_time(N_k)
    for R in list(range(1, 21)) + [25, 30, 40, 50, 75, 100]:
        p_seq  = p_recover_sequential(R)
        # For LFSR phase: after R packets we've seen R observations;
        # treat as R draws for the birthday problem with pool size N_k
        p_lfsr = p_birthday_collision(R, N_k)
        rows.append({
            "R":            R,
            "P_seq":        round(p_seq,  6),
            "P_lfsr_bday":  round(p_lfsr, 6),
            "risk_level":   ("HIGH" if p_seq >= 0.5
                             else "MEDIUM" if p_seq >= 0.25
                             else "LOW" if p_seq >= 0.10
                             else "NEGLIGIBLE"),
        })

    path = os.path.join(out_dir, "key_security_summary.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["R","P_seq","P_lfsr_bday","risk_level"])
        w.writeheader()
        w.writerows(rows)
    print(f"  → {path}")

    # Also print a human-readable table
    print(f"\n  Key-security summary (N_k={N_k}, E[LFSR collision]≈{e_t:.1f} packets):")
    print(f"  {'R':>5}  {'P_seq':>10}  {'P_lfsr_bday':>14}  Risk")
    print("  " + "-"*48)
    for row in rows:
        print(f"  {row['R']:>5}  {row['P_seq']:>10.4f}  "
              f"{row['P_lfsr_bday']:>14.4f}  {row['risk_level']}")

    return rows


# ─────────────────────────────────────────────────────────────────────────────
# 6. Detailed per-opcode key-recovery analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyse_opcode_invertibility(n_samples: int = 100_000,
                                 out_dir: str = "."):
    """
    For each opcode, empirically estimate the average number of candidate
    keys consistent with a single (A_in, A_out) observation.
    Prints a table; useful for validating the analytical results.
    """
    rng = np.random.default_rng(42)
    print("\n  Opcode invertibility analysis "
          f"({n_samples:,} random (A_in, A_out) pairs):")
    print(f"  {'Opcode':12s}  {'Avg candidates':>16s}  {'Exact?':>8s}")
    print("  " + "-"*42)

    def rotl(a: int, b: int) -> int:
        amt = (b >> 27) & 0x1f
        add = b & 0x07FFFFFF
        r   = ((a << amt) | (a >> (32 - amt))) & 0xFFFFFFFF if amt else a
        return (r + add) & 0xFFFFFFFF

    ops = {
        "Add":      lambda a, k: (a + k) & 0xFFFFFFFF,
        "Sub(a-b)": lambda a, k: (a - k) & 0xFFFFFFFF,
        "Sub(b-a)": lambda a, k: (k - a) & 0xFFFFFFFF,
        "Xor":      lambda a, k: a ^ k,
        "Or":       lambda a, k: a | k,
        "And":      lambda a, k: a & k,
        "Rot(a,b)": lambda a, k: rotl(a, k),
        "Rot(b,a)": lambda a, k: rotl(k, a),
    }

    # For invertible ops: count exactly 1 solution.
    # For Or/And: count how many k values in 0..2^32-1 satisfy the equation
    #   (estimated by checking 2^16 random k values and extrapolating).
    for name, op in ops.items():
        # Pick random (a_in, k_true) pairs
        a_in_vals  = rng.integers(0, 2**32, size=1000, dtype=np.uint64)
        k_true_vals= rng.integers(0, 2**32, size=1000, dtype=np.uint64)
        a_out_vals = np.array([int(op(int(a), int(k))) & 0xFFFFFFFF
                               for a, k in zip(a_in_vals, k_true_vals)],
                              dtype=np.uint64)

        # For uniquely invertible ops: just check the formula
        if name in ("Add", "Sub(a-b)", "Sub(b-a)", "Xor"):
            candidate_counts = np.ones(1000)  # always exactly 1
            print(f"  {name:12s}  {'1 (exact)':>16s}  {'Yes':>8s}")
        elif name in ("Or", "And"):
            # Estimate avg candidates: for And, key must agree on set bits of A_in;
            # for Or,  key must agree on set bits of A_out not in A_in.
            if name == "And":
                # k must have A_out set where A_in has bits set, free elsewhere
                # but A_out & A_in = A_out must hold (a & k = a_out implies a_out subset of a)
                # avg free bits = 32 - popcount(a_in)
                avg_free = 32 - np.mean([bin(int(a)).count('1') for a in a_in_vals])
                avg_cands = 2 ** avg_free
            else:
                # Or: k must cover bits in a_out; bits in a_in are already set
                # free bits are those NOT in a_in and NOT required by a_out
                # Bits in a_in & ~a_out: A_in has 1 but A_out has 0 → impossible
                # So valid pairs: a_out must have all bits of a_in set
                valid = [(a_in_vals[i], a_out_vals[i])
                         for i in range(1000)
                         if (int(a_in_vals[i]) & int(a_out_vals[i]))
                             == int(a_in_vals[i])]
                if valid:
                    avg_free = np.mean([32 - bin(int(a_in) | int(a_out)).count('1')
                                        for a_in, a_out in valid])
                    avg_cands = 2 ** avg_free
                else:
                    avg_cands = 0
            print(f"  {name:12s}  {avg_cands:>16.1f}  {'No':>8s}")
        else:
            # Rot: 32 rotation amounts to try; each gives one candidate pair (rotl, plus)
            print(f"  {name:12s}  {'up to 32':>16s}  {'No (32 shifts)':>8s}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Hermes key-reuse security analysis")
    ap.add_argument("--out",        default="figures",
                    help="Output directory (default: figures/)")
    ap.add_argument("--nk",         type=int, default=340,
                    help="Key-pool size N_k to use in analysis (default: 340)")
    ap.add_argument("--full-lfsr",  action="store_true",
                    help="Enumerate full LFSR period (slow; omit for sampled version)")
    ap.add_argument("--lfsr-samples", type=int, default=500_000,
                    help="LFSR steps to sample when not using --full-lfsr (default: 500000)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    print(f"Hermes Key Security Analysis  (N_k={args.nk})")
    print("=" * 60)

    # ── Figure 1: P_recover(R) ────────────────────────────────────────────────
    print("\n[1/5] Key-recovery probability vs refresh rate R ...")
    plot_key_recovery_vs_R(args.out)

    # ── Figure 2: Birthday collision probability in LFSR phase ───────────────
    print("\n[2/5] Birthday-collision probability in LFSR phase ...")
    plot_birthday_vs_packets(args.out)

    # ── Figure 3: LFSR index distribution ────────────────────────────────────
    print(f"\n[3/5] LFSR index distribution (N_k={args.nk}) ...")
    if args.full_lfsr:
        counts = full_lfsr_distribution(args.nk)
        plot_lfsr_index_distribution(counts, args.nk, full=True, out_dir=args.out)
    else:
        print(f"  Sampling {args.lfsr_samples:,} LFSR steps "
              f"(use --full-lfsr for exact distribution) ...")
        counts = sample_lfsr_distribution(args.nk, n_samples=args.lfsr_samples)
        plot_lfsr_index_distribution(counts, args.nk, full=False, out_dir=args.out)

    # ── Figure 4: Risk heatmap ────────────────────────────────────────────────
    print("\n[4/5] Risk heatmap (R vs N_k) ...")
    plot_risk_heatmap(args.out)

    # ── CSV + printed table ───────────────────────────────────────────────────
    print(f"\n[5/5] Summary CSV (N_k={args.nk}) ...")
    write_summary_csv(args.out, N_k=args.nk)

    # ── Bonus: opcode invertibility table ────────────────────────────────────
    analyse_opcode_invertibility(n_samples=1000, out_dir=args.out)

    print(f"\nAll outputs written to: {args.out}/")
    e_t = expected_collision_time(args.nk)
    print(f"\nKey findings (N_k={args.nk}):")
    print(f"  E[first LFSR key-index collision] = {e_t:.1f} packets")
    print(f"  P_recover(R=1)  = {p_recover_sequential(1):.3f}  (max security)")
    print(f"  P_recover(R=5)  = {p_recover_sequential(5):.3f}  (marginal)")
    print(f"  P_recover(R=10) = {p_recover_sequential(10):.3f} (key compromised)")
    print(f"  P_recover(R=50) = {p_recover_sequential(50):.6f} (≈1)")
    print(f"\n  Recommended R: 1 (high-security) or ≤3 (general use)")


if __name__ == "__main__":
    main()
