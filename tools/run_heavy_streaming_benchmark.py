#!/usr/bin/env python3
"""
run_heavy_streaming_benchmark.py - In-RAM Benchmark Suite with Statistical Sampling

Automates multiple repeated runs for in-RAM streaming benchmarks,
collecting latency, throughput, and speedup statistics with Mean ± StdDev.
"""

import subprocess
import re
import statistics
import sys
import os
import time
import csv
import argparse
from collections import defaultdict

try:
    from benchmark_env import setup_performance_governor
except ImportError:
    def setup_performance_governor():
        pass

def run_benchmark(size_mb, chunk_kb, sel_pct):
    cmd = ["sudo", "./host/host_loader", "--stream", str(size_mb), str(chunk_kb), str(sel_pct)]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Command failed with exit code {e.returncode}:\n{e.output}")
        sys.exit(1)

    metrics = {
        "host_time": 0.0, "csd_seq_time": 0.0, "csd_pipe_time": 0.0,
        "host_thru": 0.0, "csd_seq_thru": 0.0, "csd_pipe_thru": 0.0,
        "data_reduction": 0.0, "speedup_vs_host": 0.0, "true_csd_speedup": 0.0,
        "true_csd_speedup_pipe": 0.0
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
            if match:
                metrics["data_reduction"] = float(match[0])

        elif "In-RAM Speedup vs Host" in line:
            match = re.search(r':\s*(\d+\.\d+)x', line)
            if match:
                metrics["speedup_vs_host"] = float(match.group(1))

        elif "TRUE CSD vs Host-PCIe" in line:
            match = re.search(r':\s*(\d+\.\d+)x', line)
            if match:
                metrics["true_csd_speedup"] = float(match.group(1))

        elif "TRUE CSD (Pipelined Ret)" in line:
            match = re.search(r':\s*(\d+\.\d+)x', line)
            if match:
                metrics["true_csd_speedup_pipe"] = float(match.group(1))

    return metrics

def main():
    parser = argparse.ArgumentParser(description="In-RAM CSD Benchmark Suite with Statistical Sampling")
    parser.add_argument("--size", type=int, default=100, help="Target data size in MB (default: 100)")
    parser.add_argument("--chunk", type=int, default=256, help="Chunk size in KB (default: 256)")
    parser.add_argument("--sel", type=int, default=100, help="Selectivity percentage: 3, 10, 25, 50, 75, 100 (default: 100)")
    parser.add_argument("--runs", type=int, default=5, help="Number of repetitions for statistical sampling (default: 5)")
    parser.add_argument("--csv", type=str, default="benchmark_results_repeated.csv", help="Output CSV filename")
    parser.add_argument("--shutdown", action="store_true", help="Park Core 3 via SBI HSM when benchmark completes")

    args = parser.parse_args()

    if not os.path.exists("./host/host_loader"):
        print("Error: ./host/host_loader not found. Please run 'make -C host' first.")
        sys.exit(1)

    sz = args.size
    chunk_kb = args.chunk
    sel_pct = args.sel
    runs = args.runs

    print("==============================================================================================")
    print("         CSD REPEATED MICRO-BENCHMARK SUITE (STATISTICAL SAMPLING)                            ")
    print("==============================================================================================")
    print(f"  Target Volume  : {sz} MB ({sz / 1024.0:.2f} GB)")
    print(f"  Streaming Chunk: {chunk_kb} KB")
    print(f"  Selectivity    : {sel_pct}%")
    print(f"  Repetitions    : {runs} runs")
    print("----------------------------------------------------------------------------------------------")

    # Set governor to reduce frequency ramping variance
    setup_performance_governor()

    # Warmup run
    print("[Warmup] Executing warmup run...")
    run_benchmark(sz, chunk_kb, sel_pct)
    time.sleep(1)
    print("[Warmup] Complete. Commencing measured benchmark suite.\n")

    results = defaultdict(list)

    for r in range(runs):
        print(f"  [Run {r + 1}/{runs}] Benchmarking {sz} MB @ {sel_pct}% selectivity... ", end="", flush=True)
        t0 = time.time()
        m = run_benchmark(sz, chunk_kb, sel_pct)
        elapsed = time.time() - t0
        print(f"Done in {elapsed:.2f}s | Pipe Thru: {m['csd_pipe_thru']:.2f} MB/s | Host Thru: {m['host_thru']:.2f} MB/s")
        for k, v in m.items():
            results[k].append(v)
        time.sleep(1)

    # Print statistical summary
    print("\n\n==============================================================================================")
    print(f"               BENCHMARK RESULTS: {sz} MB @ {sel_pct}% SELECTIVITY (Mean ± StdDev)            ")
    print("==============================================================================================")
    print(f"{'Mode':<22} | {'Total Time (ms)':<25} | {'Throughput (MB/s)':<25}")
    print("-" * 80)

    modes = [
        ("Host In-RAM", "host_time", "host_thru"),
        ("CSD Sequential", "csd_seq_time", "csd_seq_thru"),
        ("CSD Pipelined", "csd_pipe_time", "csd_pipe_thru")
    ]

    for mode_name, time_key, thru_key in modes:
        t_mean = statistics.mean(results[time_key])
        t_std = statistics.stdev(results[time_key]) if runs > 1 else 0.0
        th_mean = statistics.mean(results[thru_key])
        th_std = statistics.stdev(results[thru_key]) if runs > 1 else 0.0

        t_str = f"{t_mean:8.2f} ± {t_std:6.2f}"
        th_str = f"{th_mean:8.2f} ± {th_std:6.2f}"
        print(f"{mode_name:<22} | {t_str:<25} | {th_str:<25}")

    print("-" * 80)

    pipe_thru_mean = statistics.mean(results["csd_pipe_thru"])
    host_thru_mean = statistics.mean(results["host_thru"])
    speedup_mean = statistics.mean(results["speedup_vs_host"])
    print(f"\nSpeedup Summary:")
    print(f"  In-RAM Compute Ratio (CSD Pipe / Host): {speedup_mean:.2f}x ({pipe_thru_mean:.2f} MB/s vs {host_thru_mean:.2f} MB/s)")
    if "true_csd_speedup" in results and results["true_csd_speedup"]:
        true_csd_mean = statistics.mean(results["true_csd_speedup"])
        pipe_ret_mean = statistics.mean(results["true_csd_speedup_pipe"]) if "true_csd_speedup_pipe" in results and results["true_csd_speedup_pipe"] else 0.0
        print(f"  True CSD vs Host-PCIe (Sequential Ret): {true_csd_mean:.2f}x")
        print(f"  True CSD vs Host-PCIe (Pipelined Ret) : {pipe_ret_mean:.2f}x")

    # CSV export
    with open(args.csv, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["size_mb", "sel_pct", "runs", "mode", "time_mean_ms", "time_std_ms", "thru_mean_mb_s", "thru_std_mb_s"])
        for mode_name, time_key, thru_key in modes:
            t_mean = statistics.mean(results[time_key])
            t_std = statistics.stdev(results[time_key]) if runs > 1 else 0.0
            th_mean = statistics.mean(results[thru_key])
            th_std = statistics.stdev(results[thru_key]) if runs > 1 else 0.0
            writer.writerow([sz, sel_pct, runs, mode_name, round(t_mean, 2), round(t_std, 2), round(th_mean, 2), round(th_std, 2)])

    print(f"[INFO] Statistics saved to '{args.csv}'.")

    # Shutdown Core 3 if requested
    if args.shutdown:
        print("\n[SHUTDOWN] Parking Core 3...")
        subprocess.run(["sudo", "./host/host_loader", "--stream", "1", "256", "3", "--shutdown"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[SHUTDOWN] Core 3 parked cleanly.")

if __name__ == "__main__":
    main()
