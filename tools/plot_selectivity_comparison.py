#!/usr/bin/env python3
"""
plot_selectivity_comparison.py - Direct Comparison of Selectivity Sweep: 256 KB vs 1024 KB Chunk
"""
import os
import sys
import csv
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def load_csv(csv_path):
    rows = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({k: float(v) for k, v in r.items()})
    return rows

def main():
    csv_256 = sys.argv[1] if len(sys.argv) > 1 else "/home/luigim/uni/eBPF_JIT/datinuovi/benchmark_selectivity_results_256.csv"
    csv_1024 = sys.argv[2] if len(sys.argv) > 2 else "/home/luigim/uni/eBPF_JIT/datinuovi/benchmark_selectivity_results.csv"
    out_dir = sys.argv[3] if len(sys.argv) > 3 else "/home/luigim/uni/eBPF_JIT/datinuovi"

    rows_256 = load_csv(csv_256)
    rows_1024 = load_csv(csv_1024)

    sel = [r["actual_sel_pct"] for r in rows_256]
    
    pipe_spd_256 = [r["true_csd_pipe_speedup_vs_pcie"] for r in rows_256]
    pipe_spd_1024 = [r["true_csd_pipe_speedup_vs_pcie"] for r in rows_1024]
    
    thru_256 = [r["csd_pipe_thru_mb_s"] for r in rows_256]
    thru_1024 = [r["csd_pipe_thru_mb_s"] for r in rows_1024]
    host_thru = [r["host_thru_mb_s"] for r in rows_256]

    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    plt.rcParams.update({
        'font.size': 11,
        'font.family': 'sans-serif',
        'axes.labelsize': 12,
        'axes.titlesize': 13,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 9.5,
    })

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.2), dpi=300)

    # Subplot 1: Speedup comparison
    c_256 = '#1f77b4'   # blue
    c_1024 = '#ff7f0e'  # orange

    ax1.plot(sel, pipe_spd_256, 'o-', color=c_256, linewidth=2.5, markersize=8, label='CSD Pipe (256 KB Chunk - Optimal)')
    ax1.plot(sel, pipe_spd_1024, 's--', color=c_1024, linewidth=2.0, markersize=7, label='CSD Pipe (1024 KB Chunk - Conservative)')
    ax1.axhline(1.0, color='gray', linestyle=':', alpha=0.7, label='Break-even (1.0x)')

    for x, y in zip(sel, pipe_spd_256):
        ax1.annotate(f"{y:.2f}x", (x, y), textcoords="offset points", xytext=(0, 8), ha='center', fontweight='bold', color=c_256, fontsize=9)
    for x, y in zip(sel, pipe_spd_1024):
        ax1.annotate(f"{y:.2f}x", (x, y), textcoords="offset points", xytext=(0, -14), ha='center', fontweight='bold', color=c_1024, fontsize=9)

    ax1.set_xlabel('Filter Selectivity (% of matched records)', fontweight='bold')
    ax1.set_ylabel('End-to-End Speedup (vs. Host Storage)', fontweight='bold')
    ax1.set_title('(a) Speedup Scaling: 256 KB vs 1024 KB Chunk', fontweight='bold')
    ax1.set_ylim(0.5, 10.5)
    ax1.legend(loc='upper right', frameon=True)

    # Subplot 2: Throughput comparison
    ax2.plot(sel, host_thru, 'D:', color='#d62728', linewidth=1.8, markersize=6, alpha=0.8, label='Host In-RAM (GCC -O2 Baseline)')
    ax2.plot(sel, thru_256, 'o-', color=c_256, linewidth=2.5, markersize=8, label='CSD Pipe Throughput (256 KB Chunk)')
    ax2.plot(sel, thru_1024, 's--', color=c_1024, linewidth=2.0, markersize=7, label='CSD Pipe Throughput (1024 KB Chunk)')

    for x, y in zip(sel, thru_256):
        ax2.annotate(f"{y:.0f}", (x, y), textcoords="offset points", xytext=(0, 8), ha='center', fontweight='bold', color=c_256, fontsize=9)
    for x, y in zip(sel, thru_1024):
        ax2.annotate(f"{y:.0f}", (x, y), textcoords="offset points", xytext=(0, -14), ha='center', fontweight='bold', color=c_1024, fontsize=9)

    ax2.set_xlabel('Filter Selectivity (% of matched records)', fontweight='bold')
    ax2.set_ylabel('Effective Throughput (MB/s)', fontweight='bold')
    ax2.set_title('(b) CSD Pipe Throughput: 256 KB vs 1024 KB', fontweight='bold')
    ax2.legend(loc='center right', frameon=True)
    ax2.set_ylim(0, 2700)

    plt.tight_layout()
    out_path = os.path.join(out_dir, "plot_selectivity_comparison.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
