#!/usr/bin/env python3
"""
Vulnerability Tool - TCP port scanner, service/version detection, and
banner-grabbing risk report, built on python-nmap.

For use on Kali Linux against hosts you own or are authorized to test.

Setup on Kali:
    sudo apt update && sudo apt install nmap -y
    pip install python-nmap --break-system-packages
    sudo python3 vulnerability_tool.py        # root/sudo needed for SYN scans (-sS)
"""

import argparse
import json
import socket
import sys
from datetime import datetime

try:
    import nmap
except ImportError:
    sys.exit("Missing dependency: pip install python-nmap --break-system-packages")

# Ports/services worth flagging on sight — not a vulnerability database,
# just a quick heuristic so a human reviewer knows where to look first.
RISK_NOTES = {
    21: "FTP — check for anonymous login / outdated vsftpd versions",
    23: "Telnet — unencrypted remote access, avoid on production hosts",
    25: "SMTP — check for open relay",
    445: "SMB — check patch level, historically a common RCE target",
    3389: "RDP — ensure NLA enabled and exposed only where required",
    5900: "VNC — often weak/no auth by default",
    6379: "Redis — frequently misconfigured with no auth",
    9200: "Elasticsearch — frequently exposed with no auth",
    27017: "MongoDB — frequently exposed with no auth",
}


def banner_grab(host, port, timeout=2):
    """Try to read a service banner directly over a raw TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
                return data.decode(errors="replace").strip()
            except socket.timeout:
                return ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_target(target, port_range, scan_args):
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target} (ports {port_range})...")
    scanner.scan(target, port_range, arguments=scan_args)

    results = []
    for host in scanner.all_hosts():
        host_info = {
            "host": host,
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "ports": [],
        }

        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                info = scanner[host][proto][port]
                if info["state"] != "open":
                    continue

                entry = {
                    "port": port,
                    "protocol": proto,
                    "state": info["state"],
                    "service": info.get("name", ""),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "note": RISK_NOTES.get(port),
                }

                banner = banner_grab(host, port)
                if banner:
                    entry["banner"] = banner

                host_info["ports"].append(entry)

        results.append(host_info)

    return results


def print_report(results):
    for host_info in results:
        print(f"\nHost: {host_info['host']} ({host_info['hostname'] or 'no PTR'}) — {host_info['state']}")
        if not host_info["ports"]:
            print("  No open ports found in range.")
            continue

        for p in host_info["ports"]:
            svc = f"{p['product']} {p['version']}".strip() or p["service"]
            print(f"  [{p['port']}/{p['protocol']}] {p['state']:<6} {svc}")
            if p.get("banner"):
                print(f"      banner: {p['banner']}")
            if p.get("note"):
                print(f"      ! {p['note']}")


def save_report(results, path):
    report = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "hosts": results,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] JSON report saved to {path}")


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Tool — port scan, service detection, banner grab")
    parser.add_argument("target", nargs="?", help="Target IP, hostname, or CIDR range (e.g. 192.168.1.10 or 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-o", "--output", default="scan_report.json", help="JSON report output path")
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Fast scan (no version detection; use when not root or for a quick sweep)",
    )
    args = parser.parse_args()

    target = args.target or input("Enter target IP/hostname/CIDR: ").strip()
    if not target:
        sys.exit("No target provided.")

    scan_args = "-T4" if args.fast else "-sV -T4"

    results = scan_target(target, args.ports, scan_args)
    print_report(results)
    save_report(results, args.output)


if __name__ == "__main__":
    main()