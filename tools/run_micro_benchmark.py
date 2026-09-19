#!/usr/bin/env python3
"""
run_micro_benchmark.py - Automated Micro-Benchmark Suite for eBPF NVMe CSD

Executes the in-memory micro-benchmarks on StarFive VisionFive 2:
- NVMe TP4091 Control Plane latency (LOAD command round-trip, sampled over 20 runs)
- JIT Compilation time (ACTIVATE command latency & hardware cycles via rdcycle)
- Scaling of In-Memory execution (Host GCC -O2 vs CSD JIT from 100 to 100,000 records)

Outputs Mean ± StdDev for all metrics and generates publication-grade plots.
"""

import subprocess
import sys
import os
import csv
import re

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Automated Micro-Benchmark Suite for eBPF NVMe CSD")
    parser.add_argument("--app", type=str, default="apps/analytics_simple.bin", help="Target eBPF application binary")
    parser.add_argument("--csv", type=str, default="benchmark_results.csv", help="Output CSV filename")
    parser.add_argument("--no-plot", action="store_true", help="Skip automatic plot generation")
    parser.add_argument("--shutdown", action="store_true", help="Park Core 3 via SBI HSM when benchmark completes")

    args = parser.parse_args()

    app_bin = args.app
    output_csv = args.csv

    if not os.path.exists("./host/host_benchmark"):
        print("[ERROR] ./host/host_benchmark not found. Please run 'make -C host host_benchmark' first.")
        sys.exit(1)

    if not os.path.exists(app_bin):
        print(f"[ERROR] eBPF application binary '{app_bin}' not found.")
        sys.exit(1)

    print("==========================================================================")
    print("      Starting Automated eBPF-NVMe Micro-Benchmarking Suite              ")
    print(f"      Target Application: {app_bin}                                      ")
    print(f"      Output CSV:         {output_csv}                                   ")
    print("==========================================================================")

    cmd = ["sudo", "./host/host_benchmark", app_bin]
    if args.shutdown:
        cmd.append("--shutdown")

    print(f"Executing: {' '.join(cmd)}\n")

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        print(proc.stdout)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Benchmark process failed with exit code {e.returncode}:\n{e.output}")
        sys.exit(1)

    # Ensure CSV is placed in current directory and synced if needed
    if os.path.exists("benchmark_results.csv") and output_csv != "benchmark_results.csv":
        import shutil
        shutil.copy("benchmark_results.csv", output_csv)
        print(f"[INFO] Copied results to {output_csv}")

    # Generate updated plots
    if not args.no_plot:
        plot_script = os.path.join(os.path.dirname(__file__), "plot_benchmarks.py")
        if os.path.exists(plot_script):
            print("\nGenerating updated plots...")
            plot_cmd = [sys.executable, plot_script, output_csv]
            subprocess.run(plot_cmd)

    print("\n[SUCCESS] Micro-benchmark complete!")

if __name__ == "__main__":
    main()
