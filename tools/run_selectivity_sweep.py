#!/usr/bin/env python3
"""
run_selectivity_sweep.py - Selectivity Sensitivity Benchmark Suite

Automates a sweep across filter selectivities (3%, 10%, 25%, 50%, 75%, 100%)
to quantify data reduction, return bus saturation, and break-even behavior.
"""

import subprocess
import re
import sys
import os
import time
import csv

DEFAULT_SIZE_MB = 1024
DEFAULT_CHUNK_KB = 1024
SELECTIVITIES = [3, 10, 25, 50, 75, 100]

def run_benchmark(size_mb, chunk_kb, sel_pct):
    cmd = ["sudo", "./host/host_ram_loader", "--stream", str(size_mb), str(chunk_kb), str(sel_pct)]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Command failed with exit code {e.returncode}:\n{e.output}")
        sys.exit(1)

    metrics = {
        "sel_pct": sel_pct,
        "actual_sel": 0.0,
        "matches": 0,
        "host_time": 0.0, "csd_pipe_time": 0.0,
        "host_thru": 0.0, "csd_pipe_thru": 0.0,
        "data_reduction": 0.0, "host_mem_recv_mb": 0.0,
        "speedup_vs_host": 0.0, "true_csd_speedup": 0.0,
        "true_csd_speedup_pipe": 0.0
    }

    for line in output.split('\n'):
        if "Matches / Sum" in line and metrics["matches"] == 0:
            match = re.search(r'(\d+) matches \((\d+\.\d+)% selectivity\)', line)
            if match:
                metrics["matches"] = int(match.group(1))
                metrics["actual_sel"] = float(match.group(2))

        elif "Total Time" in line:
            match = re.findall(r'(\d+\.\d+) ms', line)
            if len(match) >= 3:
                metrics["host_time"] = float(match[0])
                metrics["csd_pipe_time"] = float(match[2])

        elif "Effective Throughput" in line:
            match = re.findall(r'(\d+\.\d+) MB/s', line)
            if len(match) >= 3:
                metrics["host_thru"] = float(match[0])
                metrics["csd_pipe_thru"] = float(match[2])

        elif "Host Data Reduction" in line:
            match = re.findall(r'(\d+\.\d+)%', line)
            if len(match) >= 3:
                metrics["data_reduction"] = float(match[1])

        elif "Host Memory Recv" in line and "Pipe" in output:
            match = re.search(r'(\d+\.\d+) MB', line)
            if match:
                metrics["host_mem_recv_mb"] = float(match.group(1))

        elif "In-RAM Speedup vs Host" in line:
            match = re.search(r'(\d+\.\d+)x', line)
            if match:
                metrics["speedup_vs_host"] = float(match.group(1))

        elif "TRUE CSD vs Host-PCIe" in line:
            match = re.search(r'(\d+\.\d+)x', line)
            if match:
                metrics["true_csd_speedup"] = float(match.group(1))

        elif "TRUE CSD (Pipelined Ret)" in line:
            match = re.search(r'(\d+\.\d+)x', line)
            if match:
                metrics["true_csd_speedup_pipe"] = float(match.group(1))

    return metrics

def main():
    if not os.path.exists("./host/host_ram_loader"):
        print("Error: ./host/host_ram_loader not found. Please run 'make host' first.")
        sys.exit(1)

    size_mb = DEFAULT_SIZE_MB
    chunk_kb = DEFAULT_CHUNK_KB

    if len(sys.argv) > 1:
        try:
            size_mb = int(sys.argv[1])
        except ValueError:
            pass

    print("==============================================================================================")
    print("                CSD FILTER SELECTIVITY SENSITIVITY SWEEP (BREAK-EVEN STUDY)                   ")
    print("==============================================================================================")
    print(f"  Target Volume  : {size_mb} MB ({size_mb / 1024.0:.2f} GB)")
    print(f"  Streaming Chunk: {chunk_kb} KB")
    print(f"  Selectivities  : {SELECTIVITIES}%")
    print("----------------------------------------------------------------------------------------------")

    # Warmup
    print("[Warmup] Running initial warmup...")
    run_benchmark(size_mb, chunk_kb, 3)
    time.sleep(1)
    print("[Warmup] Complete. Commencing selectivity sweep.\n")

    results = []

    for sel in SELECTIVITIES:
        print(f">>> Testing Selectivity: ~{sel}%... ", end="", flush=True)
        t0 = time.time()
        m = run_benchmark(size_mb, chunk_kb, sel)
        elapsed = time.time() - t0
        print(f"Done in {elapsed:.2f}s | Actual: {m['actual_sel']:.2f}% | Reduction: {m['data_reduction']:.1f}% | CSD vs PCIe: {m['true_csd_speedup']:.2f}x (Pipe: {m['true_csd_speedup_pipe']:.2f}x)")
        results.append(m)
        time.sleep(1)

    # Print publication summary table
    print("\n\n==========================================================================================================")
    print("                              SELECTIVITY SENSITIVITY & BREAK-EVEN RESULTS                                ")
    print("==========================================================================================================")
    print(f"{'Selectivity':<12} | {'Data Reduct':<12} | {'Host Ret MB':<12} | {'Host Thru':<12} | {'CSD Thru':<12} | {'CSD vs PCIe':<12} | {'Pipe Ret Spd':<12}")
    print("-" * 106)

    for r in results:
        sel_str = f"{r['actual_sel']:.2f}%"
        red_str = f"{r['data_reduction']:.1f}%"
        ret_str = f"{r['host_mem_recv_mb']:.1f} MB"
        host_str = f"{r['host_thru']:.1f} MB/s"
        csd_str = f"{r['csd_pipe_thru']:.1f} MB/s"
        spd_str = f"{r['true_csd_speedup']:.2f}x"
        pipe_str = f"{r['true_csd_speedup_pipe']:.2f}x"
        print(f"{sel_str:<12} | {red_str:<12} | {ret_str:<12} | {host_str:<12} | {csd_str:<12} | {spd_str:<12} | {pipe_str:<12}")

    print("-" * 106)

    # CSV export
    csv_file = "benchmark_selectivity_results.csv"
    with open(csv_file, mode="w", newline="") as f:
        fieldnames = ["target_mb", "sel_target_pct", "actual_sel_pct", "data_reduction_pct", "host_recv_mb",
                      "host_time_ms", "csd_pipe_time_ms", "host_thru_mb_s", "csd_pipe_thru_mb_s",
                      "speedup_vs_host_ram", "true_csd_speedup_vs_pcie", "true_csd_pipe_speedup_vs_pcie"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "target_mb": size_mb,
                "sel_target_pct": r["sel_pct"],
                "actual_sel_pct": round(r["actual_sel"], 2),
                "data_reduction_pct": round(r["data_reduction"], 1),
                "host_recv_mb": round(r["host_mem_recv_mb"], 2),
                "host_time_ms": round(r["host_time"], 2),
                "csd_pipe_time_ms": round(r["csd_pipe_time"], 2),
                "host_thru_mb_s": round(r["host_thru"], 1),
                "csd_pipe_thru_mb_s": round(r["csd_pipe_thru"], 1),
                "speedup_vs_host_ram": round(r["speedup_vs_host"], 2),
                "true_csd_speedup_vs_pcie": round(r["true_csd_speedup"], 2),
                "true_csd_pipe_speedup_vs_pcie": round(r["true_csd_speedup_pipe"], 2)
            })

    print(f"\n[INFO] Selectivity sweep data saved to: {csv_file}")

if __name__ == "__main__":
    main()
