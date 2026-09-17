#!/usr/bin/env python3
"""
run_heavy_streaming_benchmark.py - High-Volume In-RAM Benchmark Suite

Automates multiple runs for high-volume streaming benchmarks (1 GB and 2 GB),
collecting latency, throughput, and speedup statistics with Mean ± StdDev.
"""

import subprocess
import re
import statistics
import sys
import os
import time
import csv
from collections import defaultdict

DEFAULT_SIZES_MB = [1024, 2048]
DEFAULT_CHUNK_KB = 1024
DEFAULT_RUNS = 5

def set_performance_governor():
    """Attempt to set CPU governor to 'performance' on Linux to prevent DVFS jitter."""
    try:
        cmd = "echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1"
        subprocess.run(cmd, shell=True, check=False)
    except Exception:
        pass

def run_benchmark(size_mb, chunk_kb):
    cmd = ["sudo", "./host/host_ram_loader", "--stream", str(size_mb), str(chunk_kb)]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Command failed with exit code {e.returncode}:\n{e.output}")
        sys.exit(1)

    metrics = {
        "host_time": 0.0, "csd_seq_time": 0.0, "csd_pipe_time": 0.0,
        "host_thru": 0.0, "csd_seq_thru": 0.0, "csd_pipe_thru": 0.0,
        "data_reduction": 0.0, "speedup_vs_host": 0.0, "true_csd_speedup": 0.0
    }

    # Parse output table
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

        elif "In-RAM Speedup vs Host" in line:
            match = re.search(r'(\d+\.\d+)x faster', line)
            if match:
                metrics["speedup_vs_host"] = float(match.group(1))

        elif "TRUE CSD vs Host-PCIe" in line:
            match = re.search(r'(\d+\.\d+)x faster', line)
            if match:
                metrics["true_csd_speedup"] = float(match.group(1))

    return metrics

def main():
    if not os.path.exists("./host/host_ram_loader"):
        print("Error: ./host/host_ram_loader not found. Please run 'make host' first.")
        sys.exit(1)

    sizes_mb = DEFAULT_SIZES_MB
    chunk_kb = DEFAULT_CHUNK_KB
    runs = DEFAULT_RUNS

    if len(sys.argv) > 1:
        try:
            runs = int(sys.argv[1])
        except ValueError:
            pass

    print("==============================================================================================")
    print("         HIGH-VOLUME IN-RAM STREAMING BENCHMARK SUITE (1 GB & 2 GB STEADY STATE)             ")
    print("==============================================================================================")
    print(f"  Target Volumes : {sizes_mb} MB")
    print(f"  Streaming Chunk: {chunk_kb} KB")
    print(f"  Repetitions    : {runs} runs per target")
    print("----------------------------------------------------------------------------------------------")

    # Set governor to reduce frequency ramping variance
    set_performance_governor()

    # Warmup run to stabilize caches and bus
    print("[Warmup] Executing 512 MB warmup run...")
    run_benchmark(512, chunk_kb)
    time.sleep(1)
    print("[Warmup] Complete. Commencing measured benchmark suite.\n")

    results = defaultdict(lambda: defaultdict(list))

    for sz in sizes_mb:
        gb_label = f"{sz / 1024.0:.1f} GB ({sz} MB)"
        print(f"\n>>> Benchmarking Volume: {gb_label} across {runs} runs...")
        for r in range(runs):
            print(f"  [Run {r + 1}/{runs}] Target: {sz} MB... ", end="", flush=True)
            t0 = time.time()
            m = run_benchmark(sz, chunk_kb)
            elapsed = time.time() - t0
            print(f"Done in {elapsed:.2f}s | Pipe Throughput: {m['csd_pipe_thru']:.2f} MB/s (Speedup: {m['speedup_vs_host']:.2f}x)")
            for k, v in m.items():
                results[sz][k].append(v)
            # 1 second cooldown to avoid thermal accumulation
            time.sleep(1)

    # Print statistical summary
    print("\n\n==============================================================================================")
    print("               HIGH-VOLUME STREAMING BENCHMARK RESULTS (Mean ± StdDev)                         ")
    print("==============================================================================================")
    print(f"{'Target Size':<14} | {'Mode':<18} | {'Total Time (ms)':<25} | {'Throughput (MB/s)':<25}")
    print("-" * 90)

    csv_data = []

    for sz in sizes_mb:
        gb_label = f"{sz / 1024.0:.1f} GB"
        modes = [
            ("Host In-RAM", "host_time", "host_thru"),
            ("CSD Seq (ONFI)", "csd_seq_time", "csd_seq_thru"),
            ("CSD Pipe (ONFI)", "csd_pipe_time", "csd_pipe_thru")
        ]

        for idx, (mode_name, time_key, thru_key) in enumerate(modes):
            time_mean = statistics.mean(results[sz][time_key])
            time_std = statistics.stdev(results[sz][time_key]) if runs > 1 else 0.0

            thru_mean = statistics.mean(results[sz][thru_key])
            thru_std = statistics.stdev(results[sz][thru_key]) if runs > 1 else 0.0

            time_str = f"{time_mean:8.2f} ± {time_std:6.2f}"
            thru_str = f"{thru_mean:8.2f} ± {thru_std:6.2f}"

            size_col = gb_label if idx == 0 else ""
            print(f"{size_col:<14} | {mode_name:<18} | {time_str:<25} | {thru_str:<25}")

            csv_data.append({
                "target_mb": sz,
                "target_gb": sz / 1024.0,
                "mode": mode_name,
                "time_mean_ms": round(time_mean, 2),
                "time_std_ms": round(time_std, 2),
                "thru_mean_mb_s": round(thru_mean, 2),
                "thru_std_mb_s": round(thru_std, 2)
            })
        print("-" * 90)

    # Summary speedups
    print("\nSpeedup Summary (CSD Pipelined vs Host):")
    for sz in sizes_mb:
        pipe_thru_mean = statistics.mean(results[sz]["csd_pipe_thru"])
        host_thru_mean = statistics.mean(results[sz]["host_thru"])
        speedup_mean = statistics.mean(results[sz]["speedup_vs_host"])
        true_speedup_mean = statistics.mean(results[sz]["true_csd_speedup"])
        print(f"  {sz / 1024.0:.1f} GB ({sz} MB): In-RAM Speedup = {speedup_mean:.2f}x | TRUE CSD vs Host-PCIe = {true_speedup_mean:.2f}x (Pipe Throughput: {pipe_thru_mean:.2f} MB/s vs Host: {host_thru_mean:.2f} MB/s)")

    # Write to CSV
    csv_file = "benchmark_heavy_results.csv"
    with open(csv_file, mode="w", newline="") as f:
        fieldnames = ["target_mb", "target_gb", "mode", "time_mean_ms", "time_std_ms", "thru_mean_mb_s", "thru_std_mb_s"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv_data:
            writer.writerow(row)

    print(f"\n[INFO] Detailed statistics saved to: {csv_file}")

if __name__ == "__main__":
    main()
