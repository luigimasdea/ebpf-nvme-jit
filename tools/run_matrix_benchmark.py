#!/usr/bin/env python3
"""
run_matrix_benchmark.py - Unified Chunk Matrix Benchmark Suite

Evaluates chunking dichotomy across physical SSD storage and in-RAM ONFI simulation:
1. Physical NVMe SSD (ext4 pread):
   Tests sustained throughput across chunk sizes [256, 512, 1024 KB] on /mnt/nvme/dataset_1m.bin.
2. In-RAM Architectural Model (ONFI 5.0 simulation):
   Tests flash-to-SLM pipelined streaming across chunk sizes [256, 512, 1024 KB].

Produces publication-ready statistics (Mean ± StdDev) and automatically generates figures:
- plot_ssd_matrix.png
- plot_chunk_dichotomy.png
"""

import subprocess
import re
import statistics
import sys
import os
import csv
import argparse
from collections import defaultdict

def run_single_benchmark(mode, chunk_size, disk_file=None):
    if mode == "disk":
        cmd = ["sudo", "./host/host_loader", "--disk", disk_file, str(chunk_size)]
    else:
        cmd = ["sudo", "./host/host_loader", "--stream", "15", str(chunk_size)]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Command failed with exit code {e.returncode}:\n{e.output}")
        sys.exit(1)

    metrics = {
        "host_time": 0.0, "csd_seq_time": 0.0, "csd_pipe_time": 0.0,
        "host_thru": 0.0, "csd_seq_thru": 0.0, "csd_pipe_thru": 0.0,
        "data_reduction": 0.0, "true_csd_speedup": 0.0, "true_csd_speedup_pipe": 0.0
    }

    for line in output.split('\n'):
        if "Total Time" in line:
            match = re.findall(r'(\d+\.\d+) ms', line)
            if len(match) >= 3:
                metrics["host_time"] = float(match[0])
                metrics["csd_seq_time"] = float(match[1])
                metrics["csd_pipe_time"] = float(match[2])

        elif "Effective Throughput" in line:
            match = re.findall(r'(\d+\.\d+) MB/s', line)
            if len(match) >= 3:
                metrics["host_thru"] = float(match[0])
                metrics["csd_seq_thru"] = float(match[1])
                metrics["csd_pipe_thru"] = float(match[2])

        elif "Host Data Reduction" in line:
            match = re.findall(r'(\d+\.\d+)%', line)
            if len(match) >= 3:
                metrics["data_reduction"] = float(match[1])

        elif "TRUE CSD vs Host-PCIe" in line:
            match = re.search(r':\s*(\d+\.\d+)x', line)
            if match:
                metrics["true_csd_speedup"] = float(match.group(1))

        elif "TRUE CSD (Pipelined Ret)" in line:
            match = re.search(r':\s*(\d+\.\d+)x', line)
            if match:
                metrics["true_csd_speedup_pipe"] = float(match.group(1))

    return metrics

def run_suite(mode, chunk_sizes, runs, disk_file):
    print(f"\n==============================================================================================")
    if mode == "disk":
        print(f"       CHUNKING MATRIX BENCHMARK: PHYSICAL NVMe SSD (ext4 pread) - {runs} RUNS               ")
        print(f"       Dataset File: {disk_file}")
    else:
        print(f"       CHUNKING MATRIX BENCHMARK: IN-RAM ONFI 5.0 SIMULATION - {runs} RUNS                   ")
        print(f"==============================================================================================")

    try:
        from benchmark_env import setup_performance_governor
        setup_performance_governor()
    except Exception:
        pass

    # Warmup
    print(f"[Warmup] Running initial warmup chunk {chunk_sizes[0]} KB...")
    run_single_benchmark(mode, chunk_sizes[0], disk_file)
    print("[Warmup] Complete.\n")

    results = defaultdict(lambda: defaultdict(list))
    for chunk in chunk_sizes:
        print(f">>> Testing Chunk Size: {chunk} KB ({runs} repetitions)...", flush=True)
        for r in range(runs):
            m = run_single_benchmark(mode, chunk, disk_file)
            for k, v in m.items():
                results[chunk][k].append(v)

    # Standardized Output Table
    print("\n----------------------------------------------------------------------------------------------")
    print(f"{'Chunk':<8} | {'Mode':<18} | {'Total Time (ms)':<25} | {'Throughput (MB/s)':<25}")
    print("-" * 88)

    csv_data = []
    modes = [
        ("Host Traditional" if mode == "disk" else "Host In-RAM", "host_time", "host_thru"),
        ("CSD Sequential", "csd_seq_time", "csd_seq_thru"),
        ("CSD Pipelined", "csd_pipe_time", "csd_pipe_thru")
    ]

    for chunk in chunk_sizes:
        for idx, (mode_name, time_key, thru_key) in enumerate(modes):
            t_mean = statistics.mean(results[chunk][time_key])
            t_std = statistics.stdev(results[chunk][time_key]) if runs > 1 else 0.0
            th_mean = statistics.mean(results[chunk][thru_key])
            th_std = statistics.stdev(results[chunk][thru_key]) if runs > 1 else 0.0

            chunk_str = f"{chunk} KB" if idx == 0 else ""
            t_str = f"{t_mean:8.2f} ± {t_std:5.2f}"
            th_str = f"{th_mean:8.2f} ± {th_std:5.2f}"
            print(f"{chunk_str:<8} | {mode_name:<18} | {t_str:<25} | {th_str:<25}")

            row = {
                "chunk_kb": chunk,
                "mode": mode_name,
                "time_mean_ms": round(t_mean, 2),
                "time_std_ms": round(t_std, 2),
                "thru_mean_mbs": round(th_mean, 2),
                "thru_std_mbs": round(th_std, 2),
                "data_reduction_pct": round(statistics.mean(results[chunk]["data_reduction"]), 1)
            }
            if mode == "ram":
                row["true_csd_speedup_vs_pcie"] = round(statistics.mean(results[chunk]["true_csd_speedup"]), 2)
            csv_data.append(row)

        if mode == "ram" and results[chunk]["true_csd_speedup"]:
            true_spd = statistics.mean(results[chunk]["true_csd_speedup"])
            pipe_spd = statistics.mean(results[chunk]["true_csd_speedup_pipe"]) if results[chunk]["true_csd_speedup_pipe"] else 0.0
            print(f"         * True CSD Speedup vs Storage: {true_spd:.2f}x (Pipelined Return: {pipe_spd:.2f}x)")
        print("-" * 88)

    # Save CSV
    csv_file = "benchmark_matrix_results.csv" if mode == "disk" else "benchmark_ram_matrix_results.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
        writer.writeheader()
        writer.writerows(csv_data)
    print(f"[INFO] Results saved to '{csv_file}'.")
    return csv_file

def main():
    parser = argparse.ArgumentParser(description="Unified Chunk Matrix Benchmark Suite")
    parser.add_argument("--mode", choices=["all", "disk", "ram"], default="all",
                        help="Benchmark mode: 'disk' (NVMe SSD), 'ram' (ONFI simulation), or 'all' (default)")
    parser.add_argument("--file", type=str, default="/mnt/nvme/dataset_1m.bin",
                        help="Dataset file path for disk mode (default: /mnt/nvme/dataset_1m.bin)")
    parser.add_argument("--runs", type=int, default=5, help="Number of repetitions per chunk size (default: 5)")
    parser.add_argument("--chunks", nargs="+", type=int, default=[256, 512, 1024],
                        help="Chunk sizes in KB to evaluate (default: 256 512 1024)")
    parser.add_argument("--no-plot", action="store_true", help="Skip automatic plot generation")
    parser.add_argument("--shutdown", action="store_true", help="Park Core 3 via SBI HSM when benchmark completes")

    args = parser.parse_args()

    if not os.path.exists("./host/host_loader"):
        print("[ERROR] ./host/host_loader not found. Please run 'make host' first.")
        sys.exit(1)

    selected_mode = args.mode
    if selected_mode in ("all", "disk") and not os.path.exists(args.file):
        if selected_mode == "disk":
            print(f"[ERROR] Disk dataset file '{args.file}' not found. Please generate it or specify --file.")
            sys.exit(1)
        else:
            print(f"[WARNING] Disk dataset file '{args.file}' not found. Skipping disk mode, running RAM mode only.")
            selected_mode = "ram"

    if selected_mode in ("all", "disk"):
        run_suite("disk", args.chunks, args.runs, args.file)

    if selected_mode in ("all", "ram"):
        run_suite("ram", args.chunks, args.runs, args.file)

    # Plot generation
    if not args.no_plot:
        plot_script = os.path.join(os.path.dirname(__file__), "plot_matrix_benchmarks.py")
        if os.path.exists(plot_script):
            print("\n[PLOTTING] Generating updated figures (plot_ssd_matrix.png, plot_chunk_dichotomy.png)...")
            subprocess.run([sys.executable, plot_script])

    # Shutdown Core 3 if requested
    if args.shutdown:
        print("\n[SHUTDOWN] Parking Core 3...")
        subprocess.run(["sudo", "./host/host_loader", "--stream", "1", "256", "3", "--shutdown"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[SHUTDOWN] Core 3 parked cleanly.")

    print("\n[SUCCESS] Matrix benchmark suite complete!")

if __name__ == "__main__":
    main()
