#!/usr/bin/env python3
import os
import sys
import csv
import numpy as np
import matplotlib.pyplot as plt

def load_csv(path):
    data = []
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parsed = {}
            for k, v in row.items():
                try:
                    parsed[k] = float(v)
                except ValueError:
                    parsed[k] = v
            data.append(parsed)
    return data

def main():
    ssd_csv = sys.argv[1] if len(sys.argv) > 1 else "../benchmark_matrix_results.csv"
    ram_csv = sys.argv[2] if len(sys.argv) > 2 else "../benchmark_ram_matrix_results.csv"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "../docs"

    if not os.path.exists(ssd_csv):
        ssd_csv = "benchmark_matrix_results.csv"
    if not os.path.exists(ram_csv):
        ram_csv = "benchmark_ram_matrix_results.csv"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    print(f"Loading SSD benchmark from: {ssd_csv}")
    print(f"Loading RAM benchmark from: {ram_csv}")
    print(f"Saving plots to: {output_dir}")

    ssd_data = load_csv(ssd_csv)
    ram_data = load_csv(ram_csv)

    # Styling for scientific papers
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    plt.rcParams.update({
        'font.size': 11,
        'font.family': 'sans-serif',
        'axes.labelsize': 12,
        'axes.titlesize': 13,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'legend.fontsize': 10,
        'figure.titlesize': 14
    })

    # =========================================================================
    # PLOT 1: Physical SSD PCIe Matrix (Throughput with Error Bars)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8.5, 5), dpi=300)
    chunks = [256, 512, 1024]
    x = np.arange(len(chunks))
    width = 0.25

    # Extract values
    host_thru = [d['thru_mean_mbs'] for d in ssd_data if d['mode'] == 'Host Traditional']
    host_std = [d['thru_std_mbs'] for d in ssd_data if d['mode'] == 'Host Traditional']

    seq_thru = [d['thru_mean_mbs'] for d in ssd_data if d['mode'] == 'CSD Sequential']
    seq_std = [d['thru_std_mbs'] for d in ssd_data if d['mode'] == 'CSD Sequential']

    pipe_thru = [d['thru_mean_mbs'] for d in ssd_data if d['mode'] == 'CSD Pipelined']
    pipe_std = [d['thru_std_mbs'] for d in ssd_data if d['mode'] == 'CSD Pipelined']

    rects1 = ax.bar(x - width, host_thru, width, yerr=host_std, capsize=4,
                    label='Host Traditional (CPU GCC -O2)', color='#4A90E2', edgecolor='black', alpha=0.9)
    rects2 = ax.bar(x, seq_thru, width, yerr=seq_std, capsize=4,
                    label='CSD Sequential (Core 3 JIT)', color='#F5A623', edgecolor='black', alpha=0.9)
    rects3 = ax.bar(x + width, pipe_thru, width, yerr=pipe_std, capsize=4,
                    label='CSD Pipelined (Double-Buffered)', color='#7ED321', edgecolor='black', alpha=0.9)

    ax.set_ylabel('Effective Throughput (MB/s)')
    ax.set_xlabel('Streaming Chunk Size (KB)')
    ax.set_title('Physical NVMe SSD Streaming Benchmark (PCIe 2.0 x1 Bottleneck)')
    ax.set_xticks(x)
    ax.set_xticklabels([f'{c} KB' for c in chunks])
    ax.legend(loc='upper right', frameon=True)
    ax.set_ylim(0, 190)

    # Annotate winner
    max_pipe_idx = np.argmax(pipe_thru)
    ax.annotate(f'Peak: {pipe_thru[max_pipe_idx]:.1f} MB/s\n(+15.9% vs Host)',
                xy=(x[max_pipe_idx] + width, pipe_thru[max_pipe_idx] + pipe_std[max_pipe_idx]),
                xytext=(0, 10), textcoords="offset points",
                ha='center', va='bottom', fontsize=9.5, fontweight='bold', color='#2E7D32')

    plt.tight_layout()
    p1 = os.path.join(output_dir, "plot_ssd_matrix.png")
    plt.savefig(p1)
    plt.close()
    print(f"Generated: {p1}")

    # =========================================================================
    # PLOT 2: Architectural In-RAM / ONFI Bus Matrix (Throughput with Error Bars)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8.5, 5), dpi=300)

    host_ram_thru = [d['thru_mean_mbs'] for d in ram_data if d['mode'] == 'Host In-RAM']
    host_ram_std = [d['thru_std_mbs'] for d in ram_data if d['mode'] == 'Host In-RAM']

    seq_ram_thru = [d['thru_mean_mbs'] for d in ram_data if d['mode'] == 'CSD Seq (ONFI)']
    seq_ram_std = [d['thru_std_mbs'] for d in ram_data if d['mode'] == 'CSD Seq (ONFI)']

    pipe_ram_thru = [d['thru_mean_mbs'] for d in ram_data if d['mode'] == 'CSD Pipe (ONFI)']
    pipe_ram_std = [d['thru_std_mbs'] for d in ram_data if d['mode'] == 'CSD Pipe (ONFI)']

    rects1 = ax.bar(x - width, host_ram_thru, width, yerr=host_ram_std, capsize=4,
                    label='Host In-RAM (Core 0 Direct Memory)', color='#4A90E2', edgecolor='black', alpha=0.9)
    rects2 = ax.bar(x, seq_ram_thru, width, yerr=seq_ram_std, capsize=4,
                    label='CSD Sequential (Simulated ONFI DMA)', color='#F5A623', edgecolor='black', alpha=0.9)
    rects3 = ax.bar(x + width, pipe_ram_thru, width, yerr=pipe_ram_std, capsize=4,
                    label='CSD Pipelined (Simulated ONFI DMA)', color='#7ED321', edgecolor='black', alpha=0.9)

    ax.set_ylabel('Effective Throughput (MB/s)')
    ax.set_xlabel('Streaming Chunk Size (KB)')
    ax.set_title('Architectural In-RAM Benchmark (Internal ONFI 5.0 Bus Model)')
    ax.set_xticks(x)
    ax.set_xticklabels([f'{c} KB' for c in chunks])
    ax.legend(loc='upper left', frameon=True)
    ax.set_ylim(0, 800)

    # Annotate peak
    max_ram_idx = np.argmax(pipe_ram_thru)
    ax.annotate(f'Peak: {pipe_ram_thru[max_ram_idx]:.1f} MB/s\n(4.56x vs Storage)',
                xy=(x[max_ram_idx] + width, pipe_ram_thru[max_ram_idx] + pipe_ram_std[max_ram_idx]),
                xytext=(0, 10), textcoords="offset points",
                ha='center', va='bottom', fontsize=9.5, fontweight='bold', color='#2E7D32')

    plt.tight_layout()
    p2 = os.path.join(output_dir, "plot_ram_matrix.png")
    plt.savefig(p2)
    plt.close()
    print(f"Generated: {p2}")

    # =========================================================================
    # PLOT 3: The Chunking Dichotomy (I/O-Bound vs Dispatch-Bound)
    # =========================================================================
    fig, ax1 = plt.subplots(figsize=(8.5, 5), dpi=300)

    color1 = '#D0021B'
    ax1.set_xlabel('Chunk Size (KB)')
    ax1.set_ylabel('PCIe SSD Pipelined Throughput (MB/s)', color=color1)
    line1 = ax1.errorbar(chunks, pipe_thru, yerr=pipe_std, fmt='o-', color=color1,
                         linewidth=2.5, markersize=8, capsize=5, label='Physical PCIe SSD (I/O-Bound)')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_ylim(120, 180)
    ax1.set_xticks(chunks)
    ax1.set_xticklabels([f'{c} KB' for c in chunks])

    ax2 = ax1.twinx()
    color2 = '#00838F'
    ax2.set_ylabel('In-RAM ONFI Pipelined Throughput (MB/s)', color=color2)
    line2 = ax2.errorbar(chunks, pipe_ram_thru, yerr=pipe_ram_std, fmt='s--', color=color2,
                         linewidth=2.5, markersize=8, capsize=5, label='In-RAM ONFI Bus (Dispatch-Bound)')
    ax2.tick_params(axis='y', labelcolor=color2)
    ax2.set_ylim(300, 560)
    ax2.grid(False)

    lines = [line1, line2]
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc='center right', frameon=True)
    plt.title('Architectural Dichotomy: Optimal Chunk Size Inversion (I/O vs. Dispatch)')

    plt.tight_layout()
    p3 = os.path.join(output_dir, "plot_chunk_dichotomy.png")
    plt.savefig(p3)
    plt.close()
    print(f"Generated: {p3}")

    # =========================================================================
    # PLOT 4: End-to-End Latency & True CSD Speedup
    # =========================================================================
    fig, (ax_lat, ax_sp) = plt.subplots(1, 2, figsize=(11, 4.8), dpi=300)

    # Subplot A: Latency Comparison across Modes (at optimal chunk sizes)
    # Host Storage: ~132-143ms, CSD PCIe: 96.79ms, CSD ONFI: 29.98ms
    categories = ['Host Storage\n(PCIe + CPU)', 'CSD PCIe\n(256KB Chunk)', 'CSD ONFI Reale\n(1024KB Chunk)']
    latencies = [132.37, 96.79, 29.98]
    colors = ['#E74C3C', '#F39C12', '#2ECC71']

    bars = ax_lat.bar(categories, latencies, color=colors, edgecolor='black', width=0.55, alpha=0.9)
    for b in bars:
        h = b.get_height()
        ax_lat.annotate(f'{h:.1f} ms',
                        xy=(b.get_x() + b.get_width() / 2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax_lat.set_ylabel('Total Execution Time (ms)')
    ax_lat.set_title('Total End-to-End Latency (1M Records)')
    ax_lat.set_ylim(0, 160)

    # Subplot B: True CSD Speedup vs Chunk Size
    speedup_vals = [d['true_csd_speedup_vs_pcie'] for d in ram_data if d['mode'] == 'CSD Pipe (ONFI)']
    sp_bars = ax_sp.bar([f'{c} KB' for c in chunks], speedup_vals, color='#9B59B6', edgecolor='black', width=0.45, alpha=0.9)
    for b in sp_bars:
        h = b.get_height()
        ax_sp.annotate(f'{h:.2f}x',
                        xy=(b.get_x() + b.get_width() / 2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax_sp.set_ylabel('Speedup Factor vs. Host Storage')
    ax_sp.set_xlabel('Streaming Chunk Size')
    ax_sp.set_title('Integrated CSD Architectural Speedup')
    ax_sp.axhline(1.0, color='gray', linestyle='--', label='Baseline (1.0x)')
    ax_sp.set_ylim(0, 5.5)
    ax_sp.legend(loc='upper left', frameon=True)

    plt.tight_layout()
    p4 = os.path.join(output_dir, "plot_speedup_scaling.png")
    plt.savefig(p4)
    plt.close()
    print(f"Generated: {p4}")

if __name__ == '__main__':
    main()
