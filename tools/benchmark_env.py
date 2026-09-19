import subprocess
import glob
import os

def setup_performance_governor():
    """
    Sets CPU scaling governor to 'performance' on all available CPUs,
    and prints the active governor and frequencies.
    """
    try:
        cmd = "echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1"
        subprocess.run(cmd, shell=True, check=False)
    except Exception:
        pass

    # Inspect current governor and frequency
    freqs = []
    cpu_dirs = sorted(glob.glob("/sys/devices/system/cpu/cpu[0-9]*"))
    for cpu in cpu_dirs:
        cpu_name = os.path.basename(cpu)
        gov_path = os.path.join(cpu, "cpufreq", "scaling_governor")
        freq_path = os.path.join(cpu, "cpufreq", "scaling_cur_freq")
        if not os.path.exists(freq_path):
            freq_path = os.path.join(cpu, "cpufreq", "cpuinfo_cur_freq")
        
        gov = "unknown"
        freq_mhz = "unknown"
        if os.path.exists(gov_path):
            try:
                with open(gov_path, "r") as f:
                    gov = f.read().strip()
            except Exception:
                pass
        if os.path.exists(freq_path):
            try:
                with open(freq_path, "r") as f:
                    khz = int(f.read().strip())
                    freq_mhz = f"{khz / 1000.0:.0f} MHz"
            except Exception:
                pass
        if gov != "unknown" or freq_mhz != "unknown":
            freqs.append(f"{cpu_name}: {freq_mhz} ({gov})")

    if freqs:
        print("[SYSTEM] CPU Governor & Frequency Status:")
        print(f"         {', '.join(freqs)}")
