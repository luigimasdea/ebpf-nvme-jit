#!/usr/bin/env python3
import subprocess
import re
import statistics
import sys
import os
import csv
from collections import defaultdict

def run_benchmark(chunk_size):
    cmd = ["sudo", "./host/host_loader", "--stream", "15", str(chunk_size)]
    print(f"  Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running benchmark with chunk size {chunk_size}: {e.output}")
        sys.exit(1)
        
    metrics = {
        "host_time": 0.0, "csd_seq_time": 0.0, "csd_pipe_time": 0.0,
        "host_thru": 0.0, "csd_seq_thru": 0.0, "csd_pipe_thru": 0.0,
        "data_reduction": 0.0, "true_csd_speedup": 0.0
    }
    
    # Parse the output table
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
            match = re.search(r'(\d+\.\d+)x faster', line)
            if match:
                metrics["true_csd_speedup"] = float(match.group(1))
                
    return metrics

def main():
    if not os.path.exists("./host/host_loader"):
        print("Error: ./host/host_loader not found. Please run 'make host' first.")
        sys.exit(1)
        
    chunk_sizes = [256, 512, 1024]
    runs = 5
    
    print("Starting automated in-RAM architectural matrix benchmarking...")
    
    # Warmup
    print("\n[Warmup Run - 256 KB]")
    run_benchmark(256)
    print("Warmup complete.\n")
    
    results = defaultdict(lambda: defaultdict(list))
    
    for chunk in chunk_sizes:
        print(f"=== Benchmarking Chunk Size: {chunk} KB ({runs} runs) ===")
        for r in range(runs):
            m = run_benchmark(chunk)
            for k, v in m.items():
                results[chunk][k].append(v)
    
    # Calculate statistics and print
    print("\n\n==============================================================================================")
    print("                       ARCHITECTURAL IN-RAM RESULTS (Mean ± StdDev)                           ")
    print("==============================================================================================")
    print(f"{'Chunk':<8} | {'Mode':<18} | {'Total Time (ms)':<25} | {'Throughput (MB/s)':<25}")
    print("-" * 88)
    
    csv_data = []
    
    for chunk in chunk_sizes:
        modes = [
            ("Host In-RAM", "host_time", "host_thru"),
            ("CSD Seq (ONFI)", "csd_seq_time", "csd_seq_thru"),
            ("CSD Pipe (ONFI)", "csd_pipe_time", "csd_pipe_thru")
        ]
        
        for idx, (mode_name, time_key, thru_key) in enumerate(modes):
            time_mean = statistics.mean(results[chunk][time_key])
            time_std = statistics.stdev(results[chunk][time_key]) if runs > 1 else 0.0
            
            thru_mean = statistics.mean(results[chunk][thru_key])
            thru_std = statistics.stdev(results[chunk][thru_key]) if runs > 1 else 0.0
            
            chunk_str = f"{chunk} KB" if idx == 0 else ""
            
            print(f"{chunk_str:<8} | {mode_name:<18} | {time_mean:>8.2f} ± {time_std:<8.2f} ms      | {thru_mean:>8.2f} ± {thru_std:<8.2f} MB/s")
            
            csv_data.append({
                "chunk_kb": chunk,
                "mode": mode_name,
                "time_mean_ms": time_mean,
                "time_std_ms": time_std,
                "thru_mean_mbs": thru_mean,
                "thru_std_mbs": thru_std,
                "data_reduction_pct": statistics.mean(results[chunk]["data_reduction"]),
                "true_csd_speedup_vs_pcie": statistics.mean(results[chunk]["true_csd_speedup"])
            })
            
        true_speedup = statistics.mean(results[chunk]["true_csd_speedup"])
        print(f"         * TRUE CSD Speedup vs Host-PCIe Storage: {true_speedup:.2f}x faster!")
        print("-" * 88)
        
    # Write to CSV
    csv_file = "benchmark_ram_matrix_results.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
        writer.writeheader()
        writer.writerows(csv_data)
        
    print(f"\nResults saved to {csv_file}")

if __name__ == "__main__":
    main()
