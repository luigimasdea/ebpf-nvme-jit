#!/usr/bin/env python3
"""
plot_selectivity_benchmarks.py - Generate Publication-Quality Plots for Selectivity Sensitivity
"""
import os
import sys
import csv
import numpy as np
import matplotlib.pyplot as plt

def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "../benchmark_selectivity_results.csv"
    if not os.path.exists(csv_path):
        csv_path = "benchmark_selectivity_results.csv"
    if not os.path.exists(csv_path):
        csv_path = "/home/luigim/uni/eBPF_JIT/benchmark_selectivity_results.csv"

    out_dir = sys.argv[2] if len(sys.argv) > 2 else "../docs"
    if not os.path.exists(out_dir):
        out_dir = "/home/luigim/uni/eBPF_JIT/docs"

    os.makedirs(out_dir, exist_ok=True)

    print(f"Reading: {csv_path}")
    print(f"Output to: {out_dir}")

    rows = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({k: float(v) for k, v in r.items()})

    sel = [r["actual_sel_pct"] for r in rows]
    speedup_pcie = [r["true_csd_speedup_vs_pcie"] for r in rows]
    data_reduct = [r["data_reduction_pct"] for r in rows]
    host_thru = [r["host_thru_mb_s"] for r in rows]
    csd_thru = [r["csd_pipe_thru_mb_s"] for r in rows]

    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    plt.rcParams.update({
        'font.size': 11,
        'font.family': 'sans-serif',
        'axes.labelsize': 12,
        'axes.titlesize': 13,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
    })

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), dpi=300)

    # Subplot 1: Speedup and Data Reduction vs Selectivity
    color_spd = '#1f77b4' # blue
    color_red = '#2ca02c' # green

    ax1.plot(sel, speedup_pcie, 'o-', color=color_spd, linewidth=2.5, markersize=8, label='CSD Speedup vs. Storage PCIe')
    for x, y in zip(sel, speedup_pcie):
        ax1.annotate(f"{y:.2f}x", (x, y), textcoords="offset points", xytext=(0, 10), ha='center', fontweight='bold', color=color_spd)

    ax1.set_xlabel('Filter Selectivity (% of matched records)', fontweight='bold')
    ax1.set_ylabel('End-to-End Speedup (vs. Host Storage)', color=color_spd, fontweight='bold')
    ax1.tick_params(axis='y', labelcolor=color_spd)
    ax1.set_ylim(1.0, 8.0)
    ax1.set_title('(a) End-to-End Speedup & Bus Reduction Curve', fontweight='bold')

    # Twin axis for data reduction
    ax1_twin = ax1.twinx()
    ax1_twin.plot(sel, data_reduct, 's--', color=color_red, linewidth=2, markersize=7, label='Data Reduction % (Host Bus Saved)')
    ax1_twin.set_ylabel('Host Memory Bus Traffic Saved (%)', color=color_red, fontweight='bold')
    ax1_twin.tick_params(axis='y', labelcolor=color_red)
    ax1_twin.set_ylim(-5, 105)
    ax1_twin.grid(False)

    # Combine legends from ax1 and ax1_twin
    lines_1, labels_1 = ax1.get_legend_handles_labels()
    lines_2, labels_2 = ax1_twin.get_legend_handles_labels()
    ax1.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper right', frameon=True)

    # Subplot 2: Throughput degradation curve
    ax2.plot(sel, host_thru, 'D-', color='#d62728', linewidth=2.2, markersize=7, label='Host In-RAM (GCC -O2)')
    ax2.plot(sel, csd_thru, 'o-', color='#1f77b4', linewidth=2.5, markersize=8, label='CSD Pipelined (ONFI + JIT)')

    for x, y in zip(sel, host_thru):
        ax2.annotate(f"{y:.0f}", (x, y), textcoords="offset points", xytext=(0, 8), ha='center', fontsize=9, color='#d62728')
    for x, y in zip(sel, csd_thru):
        ax2.annotate(f"{y:.0f}", (x, y), textcoords="offset points", xytext=(0, -15), ha='center', fontsize=9, fontweight='bold', color='#1f77b4')

    ax2.set_xlabel('Filter Selectivity (% of matched records)', fontweight='bold')
    ax2.set_ylabel('Effective Throughput (MB/s)', fontweight='bold')
    ax2.set_title('(b) Compute Throughput vs. Output Compaction Load', fontweight='bold')
    ax2.legend(loc='upper right', frameon=True)
    ax2.set_ylim(150, 1600)

    plt.tight_layout()
    out_path = os.path.join(out_dir, "plot_selectivity_sensitivity.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
