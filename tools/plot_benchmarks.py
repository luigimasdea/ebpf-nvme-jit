#!/usr/bin/env python3
"""
plot_benchmarks.py - Scientific Plotting for eBPF NVMe Micro-Benchmarks

Reads benchmark_results.csv and generates publication-quality figures:
1. benchmark_latency.png: Execution latency (ms) with Mean ± StdDev error bars.
2. benchmark_throughput.png: Sustained compute throughput (MB/s) with error bars.
3. benchmark_efficiency_ratio.png: JIT efficiency relative to native GCC -O2.
"""

import os
import sys
import csv
import matplotlib.pyplot as plt

def generate_plots(csv_path="benchmark_results.csv", output_dir="../docs"):
    # Fallback search paths for CSV
    if not os.path.exists(csv_path):
        candidates = [
            "benchmark_results.csv",
            "host/benchmark_results.csv",
            "../host/benchmark_results.csv",
            "../benchmark_results.csv"
        ]
        for c in candidates:
            if os.path.exists(c):
                csv_path = c
                break

    records = []
    size_kb = []
    host_us = []
    host_std_us = []
    csd_us = []
    csd_std_us = []
    csd_cycles = []
    speedup = []
    throughput_mb_s = []
    throughput_std_mb_s = []

    if os.path.exists(csv_path):
        print(f"Reading benchmark data from {csv_path}...")
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(int(row["records"]))
                size_kb.append(float(row.get("data_kb", 0.0)))
                host_us.append(float(row.get("host_us", 0.0)))
                host_std_us.append(float(row.get("host_std_us", 0.0)))
                csd_us.append(float(row.get("csd_us", 0.0)))
                csd_std_us.append(float(row.get("csd_std_us", 0.0)))
                csd_cycles.append(float(row.get("csd_cycles", 0.0)))
                speedup.append(float(row.get("speedup", 0.0)))
                
                # Throughput
                thru = float(row.get("csd_throughput_mb_s", 0.0))
                thru_std = float(row.get("csd_throughput_std_mb_s", 0.0))
                throughput_mb_s.append(thru)
                throughput_std_mb_s.append(thru_std)
    else:
        print(f"[WARNING] CSV {csv_path} not found. Cannot generate plots.")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Scientific styling
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    plt.rcParams.update({
        'font.size': 11,
        'font.family': 'sans-serif',
        'axes.labelsize': 12,
        'axes.titlesize': 13,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
        'figure.titlesize': 14
    })

    # =========================================================================
    # PLOT 1: Execution Time Comparison (Host Native vs CSD JIT with Error Bars)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    host_ms = [t / 1000.0 for t in host_us]
    host_std_ms = [t / 1000.0 for t in host_std_us]
    csd_ms = [t / 1000.0 for t in csd_us]
    csd_std_ms = [t / 1000.0 for t in csd_std_us]

    # Plot lines with optional error bars
    if any(s > 0 for s in host_std_ms):
        ax.errorbar(records, host_ms, yerr=host_std_ms, fmt='o-', color='#1f77b4',
                    linewidth=2, markersize=6, capsize=3, label='Host Native (GCC -O2 on Linux Core 1)')
    else:
        ax.plot(records, host_ms, 'o-', color='#1f77b4', linewidth=2, markersize=6, label='Host Native (GCC -O2 on Linux Core 1)')

    if any(s > 0 for s in csd_std_ms):
        ax.errorbar(records, csd_ms, yerr=csd_std_ms, fmt='s--', color='#d62728',
                    linewidth=2, markersize=6, capsize=3, label='CSD Offload (Bare-Metal eBPF JIT on Core 3)')
    else:
        ax.plot(records, csd_ms, 's--', color='#d62728', linewidth=2, markersize=6, label='CSD Offload (Bare-Metal eBPF JIT on Core 3)')

    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.set_xlabel('Dataset Size (Number of 16-byte Records, Log Scale)')
    ax.set_ylabel('Execution Latency (ms, Log Scale)')
    ax.set_title('In-Memory Query Latency: Host Native vs. CSD eBPF JIT')
    ax.grid(True, which="both", ls="--", alpha=0.5)
    ax.legend(loc='upper left', frameon=True)

    plot1_path = os.path.join(output_dir, "benchmark_latency.png")
    plt.tight_layout()
    plt.savefig(plot1_path)
    plt.close()
    print(f"Generated: {plot1_path}")

    # =========================================================================
    # PLOT 2: CSD Processing Throughput (MB/s with Error Bars)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    x_labels = [str(r) for r in records]
    
    yerr_val = throughput_std_mb_s if any(s > 0 for s in throughput_std_mb_s) else None
    bars = ax.bar(x_labels, throughput_mb_s, yerr=yerr_val, color='#2ca02c', width=0.55,
                  edgecolor='black', alpha=0.85, capsize=4, error_kw={'elinewidth': 1.2, 'capthick': 1.2})

    for bar, thru in zip(bars, throughput_mb_s):
        height = bar.get_height()
        ax.annotate(f'{thru:.1f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 4),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax.set_xlabel('Dataset Size (Records)')
    ax.set_ylabel('Sustained Compute Throughput (MB/s)')
    ax.set_title('CSD eBPF JIT Sustained Compute Throughput in SLM')
    ax.set_ylim(0, max(throughput_mb_s) * 1.20)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plot2_path = os.path.join(output_dir, "benchmark_throughput.png")
    plt.tight_layout()
    plt.savefig(plot2_path)
    plt.close()
    print(f"Generated: {plot2_path}")

    # =========================================================================
    # PLOT 3: Relative Efficiency Ratio (JIT vs GCC -O2)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
    pct_ratio = [s * 100.0 for s in speedup]

    ax.plot(x_labels, pct_ratio, 'D-', color='#ff7f0e', linewidth=2.2, markersize=7, label='CSD JIT Speed relative to GCC -O2 (%)')
    ax.axhline(100, color='#1f77b4', linestyle=':', linewidth=1.8, label='Host Baseline (GCC -O2 = 100%)')
    ax.axhspan(60, 65, color='#2ca02c', alpha=0.15, label='Nominal Steady-State Zone (60% - 65%)')

    for x, y in zip(x_labels, pct_ratio):
        ax.annotate(f'{y:.1f}%', xy=(x, y), xytext=(0, 7), textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax.set_xlabel('Dataset Size (Records)')
    ax.set_ylabel('Relative Efficiency (% of GCC -O2)')
    ax.set_title('Compilatore JIT Bare-Metal: Efficienza Relativa vs GCC -O2')
    ax.set_ylim(40, 115)
    ax.grid(True, linestyle='--', alpha=0.5)
    ax.legend(loc='lower right', frameon=True)

    plot3_path = os.path.join(output_dir, "benchmark_efficiency_ratio.png")
    plt.tight_layout()
    plt.savefig(plot3_path)
    plt.close()
    print(f"Generated: {plot3_path}")

if __name__ == '__main__':
    csv_file = sys.argv[1] if len(sys.argv) > 1 else "benchmark_results.csv"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "../docs"
    generate_plots(csv_file, out_dir)
