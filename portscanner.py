#!/usr/bin/env python3
"""
ULTIMATE RED TEAM PORT SCANNER v2
Interactive Menu | History | Custom Ports | Export | Zero deps
Ethical use only — your lab, your rules.
"""

import socket
import threading
import sys
import os
from urllib.parse import urlparse
from datetime import datetime

# === CONFIG ===
THREADS = 150
TIMEOUT = 1.2
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443
]
BANNERS = {
    22: "SSH", 21: "FTP", 80: "HTTP", 443: "HTTPS", 25: "SMTP",
    3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Alt"
}

# === GLOBALS ===
lock = threading.Lock()
history = []
custom_ports = []
last_results = []

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print("="*70)
    print(" " * 20 + "RED TEAM PORT SCANNER v2")
    print(" " * 15 + "Interactive | Ethical | Educational")
    print("="*70)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
    print()

def resolve(target):
    if target.startswith(("http://", "https://")):
        target = urlparse(target).hostname
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except:
        print(f"  [✗] Cannot resolve: {target}")
        return None, None

def scan_port(port, host, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((host, port)) == 0:
            banner = ""
            service = BANNERS.get(port, "unknown")
            if port in [21,22,25,80,443,110,143,8080]:
                try:
                    banner = s.recv(1024).decode('utf-8', errors='ignore')
                    banner = banner.splitlines()[0].strip()[:60]
                except:
                    banner = "[no banner]"
            with lock:
                results.append((port, service, banner))
                print(f"  [OPEN] {port:5}/tcp → {service:12} {banner}")
        s.close()
    except:
        pass

def do_scan(target, ports):
    name, ip = resolve(target)
    if not ip:
        return
    print(f"\n  Scanning → {name} ({ip}) | {len(ports)} ports...")
    results = []
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(port, ip, results))
        threads.append(t)
        t.start()
        if len(threads) >= THREADS:
            for t in threads: t.join()
            threads = []
    for t in threads: t.join()

    global last_results
    last_results = (name, ip, results)
    history.append(f"{name} ({ip}) → {len(results)} open")
    print(f"\n  [✓] Scan complete! {len(results)} open ports.\n")
    input("  Press Enter to continue...")

def show_history():
    banner()
    print("  SCAN HISTORY")
    print("  " + "-"*50)
    if not history:
        print("  No scans yet.")
    else:
        for i, entry in enumerate(history[-10:], 1):
            print(f"  {i:2}. {entry}")
    print()
    input("  Press Enter to return...")

def export_results():
    if not last_results:
        print("  [✗] No results to export!")
        input("  Press Enter...")
        return
    name, ip, results = last_results
    filename = f"scan_{name}_{datetime.now().strftime('%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"Port Scan Report - {datetime.now()}\n")
        f.write(f"Target: {name} ({ip})\n")
        f.write("-"*50 + "\n")
        for p, s, b in sorted(results):
            f.write(f"{p:5}/tcp  {s:12}  {b}\n")
    print(f"  [✓] Exported to {filename}")
    input("  Press Enter...")

def add_custom_ports():
    global custom_ports
    print("  Enter ports (space/comma separated, e.g. 22 8080 3390):")
    inp = input("  > ").strip()
    if not inp:
        return
    new = []
    for p in inp.replace(',', ' ').split():
        try:
            port = int(p)
            if 1 <= port <= 65535 and port not in custom_ports:
                new.append(port)
        except:
            pass
    custom_ports.extend(new)
    custom_ports = sorted(set(custom_ports))
    print(f"  [✓] Added {len(new)} custom ports.")
    input("  Press Enter...")

def menu():
    while True:
        banner()
        print("  [1] Quick Scan (Common Ports)")
        print("  [2] Full Scan (Common + Custom)")
        print("  [3] Add Custom Ports")
        print("  [4] View Scan History")
        print("  [5] Export Last Results")
        print("  [6] Exit")
        print()
        choice = input("  Choose [1-6]: ").strip()

        if choice == '1':
            target = input("\n  Target (IP or URL): ").strip()
            if target:
                do_scan(target, DEFAULT_PORTS)
        elif choice == '2':
            ports = DEFAULT_PORTS + custom_ports
            target = input(f"\n  Target ({len(ports)} ports): ").strip()
            if target:
                do_scan(target, ports)
        elif choice == '3':
            add_custom_ports()
        elif choice == '4':
            show_history()
        elif choice == '5':
            export_results()
        elif choice == '6':
            print("\n  Happy hacking! Stay ethical. 🛡️\n")
            sys.exit(0)
        else:
            print("  [✗] Invalid option!")
            input("  Press Enter...")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\n  [!] Scanner stopped by user.")
        sys.exit(0)
