import os
import re
import subprocess as sub
import ipaddress

def validate_ip(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def _run_nmap_cmd(cmd):
    return sub.run(cmd, capture_output=True, text=True)

def run_nmap(ip):
    """
    Try privileged scan with -O when running as root. If libpcap complains
    (\"can't open ...\") or we're not privileged, fall back to a non-raw
    TCP connect scan (-sT) which does not require root.
    """
    base = ["nmap", "-sV", "--script", "vulners", ip]
    privileged = (os.geteuid() == 0)

    if privileged:
        cmd = ["nmap", "-O"] + base[1:]  # keep -sV and scripts
    else:
        cmd = ["nmap", "-sT"] + base[1:]

    proc = _run_nmap_cmd(cmd)

    # Detect libpcap/interface open errors and try fallback if needed
    stderr = (proc.stderr or "").lower()
    if "can't open" in stderr or "failed to open device" in stderr:
        # If we attempted privileged scan and got interface error, try -sT fallback
        fallback_cmd = ["nmap", "-sT", "-sV", "--script", "vulners", ip]
        fallback = _run_nmap_cmd(fallback_cmd)
        # attach a short note in stderr to explain fallback
        fallback.stderr = (fallback.stderr or "") + "\n[info] fell back to -sT due to libpcap/interface error"
        return fallback

    return proc

def pretty_print_nmap_output(output):
    lines = output.splitlines()
    os_details = None
    running = None
    agg_guesses = None

    for line in lines:
        if line.startswith("OS details:"):
            os_details = line.strip()
            break
        if line.startswith("Running:") and running is None:
            running = line.strip()
            continue
        if line.startswith("Aggressive OS guesses:") and agg_guesses is None:
            agg_guesses = line.strip()
            continue

    chosen = os_details or running or agg_guesses or "OS not found"
    return chosen

def main():
    ip = input("enter ip address: ").strip()
    if not ip or not validate_ip(ip):
        print("ip address is invalid")
        return

    proc = run_nmap(ip)
    if proc.returncode != 0:
        # show stderr with short hint about interface/capability issues
        err = proc.stderr.strip() or "unknown error"
        print("nmap error:", err)
        return

    print(pretty_print_nmap_output(proc.stdout))

if __name__ == "__main__":
    main()
