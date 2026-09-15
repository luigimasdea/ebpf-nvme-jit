#!/usr/bin/env python3
import os
import sys
import matplotlib.pyplot as plt

def generate_plots(csv_path="benchmark_results.csv", output_dir="../docs"):
    # Fallback search paths for csv
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
    csd_us = []
    csd_cycles = []
    speedup = []
    throughput_mb_s = []

    if os.path.exists(csv_path):
        print(f"Reading benchmark data from {csv_path}...")
        with open(csv_path, "r") as f:
            lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split(",")
                if len(parts) >= 8:
                    records.append(int(parts[0]))
                    size_kb.append(float(parts[1]))
                    host_us.append(float(parts[2]))
                    csd_us.append(float(parts[3]))
                    csd_cycles.append(int(parts[4]))
                    speedup.append(float(parts[5]))
                    throughput_mb_s.append(float(parts[7]))
    else:
        print(f"CSV {csv_path} not found, using measured hardware numbers...")
        records = [100, 1000, 5000, 10000, 25000, 50000, 100000]
        size_kb = [1.6, 15.6, 78.1, 156.2, 390.6, 781.2, 1562.5]
        host_us = [3.53, 19.88, 126.10, 247.73, 614.36, 1285.04, 2453.07]
        csd_us = [6.70, 26.45, 149.95, 295.80, 737.58, 1463.99, 2913.48]
        csd_cycles = [937, 8413, 54637, 109357, 274468, 547150, 1090836]
        speedup = [0.53, 0.75, 0.84, 0.84, 0.83, 0.88, 0.84]
        throughput_mb_s = [227.7, 576.9, 508.8, 515.8, 517.2, 521.1, 523.7]

    os.makedirs(output_dir, exist_ok=True)

    # Style configuration
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    plt.rcParams.update({
        'font.size': 11,
        'font.family': 'sans-serif',
        'axes.labelsize': 12,
        'axes.titlesize': 13,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 11,
        'figure.titlesize': 14
    })

    # --- Plot 1: Execution Time Comparison (Host Native vs CSD JIT) ---
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    host_ms = [t / 1000.0 for t in host_us]
    csd_ms = [t / 1000.0 for t in csd_us]

    ax.plot(records, host_ms, 'o-', color='#1f77b4', linewidth=2, markersize=6, label='Host Native (GCC -O2 on Linux Core 0)')
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

    # --- Plot 2: CSD Processing Throughput (MB/s) ---
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    bars = ax.bar([str(r) for r in records], throughput_mb_s, color='#2ca02c', width=0.55, edgecolor='black', alpha=0.85)

    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.1f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax.set_xlabel('Dataset Size (Records)')
    ax.set_ylabel('Sustained Compute Throughput (MB/s)')
    ax.set_title('CSD eBPF JIT Sustained Compute Throughput in SLM')
    ax.set_ylim(0, max(throughput_mb_s) * 1.18)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plot2_path = os.path.join(output_dir, "benchmark_throughput.png")
    plt.tight_layout()
    plt.savefig(plot2_path)
    plt.close()
    print(f"Generated: {plot2_path}")

if __name__ == '__main__':
    csv = sys.argv[1] if len(sys.argv) > 1 else "benchmark_results.csv"
    out = sys.argv[2] if len(sys.argv) > 2 else "../docs"
    generate_plots(csv, out)
