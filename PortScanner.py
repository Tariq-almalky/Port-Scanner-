#!/usr/bin/env python3
"""
╔═══════════════════════════════════════╗
║         PORT SCANNER  v1.0.0          ║
║     TCP Connect Scan · Python 3       ║
║   Developed by Tariq H. Almlaki       ║
╚═══════════════════════════════════════╝
"""

import socket
import threading
import sys
import time
import argparse
from datetime import datetime
from queue import Queue

# ─── ANSI Colors ───────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    GRAY    = "\033[90m"
    WHITE   = "\033[97m"
    MAGENTA = "\033[95m"

# ─── Common Services ───────────────────────────────────────
SERVICES = {
    21: "FTP",        22: "SSH",         23: "Telnet",
    25: "SMTP",       53: "DNS",         80: "HTTP",
    110: "POP3",      143: "IMAP",       443: "HTTPS",
    445: "SMB",       3306: "MySQL",     3389: "RDP",
    5432: "PostgreSQL",6379: "Redis",    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",27017: "MongoDB",  5900: "VNC",
    3000: "Dev",      8888: "Jupyter",   9200: "Elasticsearch",
    11211: "Memcached",1433: "MSSQL",    5672: "RabbitMQ",
}

# ─── Globals ───────────────────────────────────────────────
open_ports   = []
closed_count = 0
lock         = threading.Lock()
stop_event   = threading.Event()

# ─── Banner ────────────────────────────────────────────────
def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.GRAY}  TCP Connect Scanner · Python 3{C.RESET}
{C.GRAY}  Developed by {C.RESET}{C.BOLD}{C.WHITE}Tariq H. Almlaki{C.RESET}
""")

# ─── Progress Bar ──────────────────────────────────────────
def progress_bar(done, total, width=40):
    pct     = done / total if total else 0
    filled  = int(width * pct)
    bar     = f"{C.GREEN}{'█' * filled}{C.GRAY}{'░' * (width - filled)}{C.RESET}"
    return f"[{bar}] {C.WHITE}{pct*100:5.1f}%{C.RESET} ({done}/{total})"

# ─── Port Scanner Worker ───────────────────────────────────
def scan_port(host, port, timeout):
    global closed_count
    if stop_event.is_set():
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = SERVICES.get(port, "unknown")
            with lock:
                open_ports.append((port, service))
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"\r{' ' * 80}\r", end="")  # clear progress line
                print(
                    f"  {C.GRAY}{ts}{C.RESET}  "
                    f"{C.GREEN}{C.BOLD}OPEN{C.RESET}   "
                    f"{C.WHITE}{port:<6}{C.RESET}  "
                    f"{C.CYAN}{service}{C.RESET}"
                )
        else:
            with lock:
                closed_count += 1
    except Exception:
        with lock:
            closed_count += 1

# ─── Thread Pool Runner ────────────────────────────────────
def run_scan(host, ports, threads, timeout):
    global open_ports, closed_count
    open_ports   = []
    closed_count = 0

    queue    = Queue()
    total    = len(ports)
    done     = [0]
    start_ts = time.time()

    for p in ports:
        queue.put(p)

    def worker():
        while not queue.empty() and not stop_event.is_set():
            try:
                port = queue.get_nowait()
            except Exception:
                break
            scan_port(host, port, timeout)
            with lock:
                done[0] += 1
            queue.task_done()

    thread_list = []
    for _ in range(min(threads, total)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    # Live progress display
    while any(t.is_alive() for t in thread_list):
        elapsed = time.time() - start_ts
        with lock:
            d = done[0]
        bar = progress_bar(d, total)
        rate = d / elapsed if elapsed > 0 else 0
        eta  = (total - d) / rate if rate > 0 else 0
        status_line = (
            f"  {C.GRAY}Scanning...{C.RESET}  {bar}  "
            f"{C.YELLOW}{rate:.0f} ports/s{C.RESET}  "
            f"ETA {C.MAGENTA}{eta:.0f}s{C.RESET}"
        )
        print(f"\r{status_line}", end="", flush=True)
        time.sleep(0.1)

    print(f"\r{' ' * 120}\r", end="")  # clear last progress line

    for t in thread_list:
        t.join()

    return time.time() - start_ts

# ─── Parse Port Range ──────────────────────────────────────
def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-")
                ports.update(range(int(start), int(end) + 1))
            except ValueError:
                print(f"{C.RED}Invalid range: {part}{C.RESET}")
                sys.exit(1)
        else:
            try:
                ports.add(int(part))
            except ValueError:
                print(f"{C.RED}Invalid port: {part}{C.RESET}")
                sys.exit(1)
    return sorted(p for p in ports if 1 <= p <= 65535)

# ─── Resolve Host ──────────────────────────────────────────
def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"\n{C.RED}  ✗ Cannot resolve host: {host}{C.RESET}\n")
        sys.exit(1)

# ─── Print Results Summary ─────────────────────────────────
def print_summary(host, ip, ports, elapsed):
    total = len(ports)
    print(f"\n  {C.GRAY}{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}SCAN SUMMARY{C.RESET}")
    print(f"  {C.GRAY}{'─' * 60}{C.RESET}")
    print(f"  Host       : {C.CYAN}{host}{C.RESET}  {C.GRAY}({ip}){C.RESET}")
    print(f"  Ports      : {C.WHITE}{total:,}{C.RESET} scanned")
    print(f"  Open       : {C.GREEN}{C.BOLD}{len(open_ports)}{C.RESET}")
    print(f"  Closed     : {C.GRAY}{closed_count}{C.RESET}")
    print(f"  Time       : {C.YELLOW}{elapsed:.2f}s{C.RESET}")
    print(f"  Finished   : {C.GRAY}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")

    if open_ports:
        sorted_open = sorted(open_ports, key=lambda x: x[0])
        print(f"\n  {C.BOLD}{C.GREEN}OPEN PORTS{C.RESET}")
        print(f"  {C.GRAY}{'─' * 40}{C.RESET}")
        print(f"  {C.GRAY}{'PORT':<8} {'STATE':<8} {'SERVICE'}{C.RESET}")
        print(f"  {C.GRAY}{'─' * 40}{C.RESET}")
        for port, service in sorted_open:
            print(
                f"  {C.WHITE}{port:<8}{C.RESET}"
                f"{C.GREEN}{'open':<8}{C.RESET}"
                f"{C.CYAN}{service}{C.RESET}"
            )
    else:
        print(f"\n  {C.YELLOW}No open ports found.{C.RESET}")

    print(f"\n  {C.GRAY}{'─' * 60}{C.RESET}\n")

# ─── Interactive Mode ──────────────────────────────────────
def interactive_mode():
    print_banner()
    print(f"  {C.BOLD}Interactive Mode{C.RESET}  {C.GRAY}(press Ctrl+C to cancel scan){C.RESET}\n")

    host = input(f"  {C.CYAN}Target host{C.RESET} (e.g. localhost, 192.168.1.1): ").strip()
    if not host:
        print(f"  {C.RED}No host provided.{C.RESET}")
        sys.exit(1)

    port_input = input(f"  {C.CYAN}Port range{C.RESET}  (e.g. 1-1024, 22,80,443) [{C.GRAY}1-1024{C.RESET}]: ").strip()
    if not port_input:
        port_input = "1-1024"

    thread_input = input(f"  {C.CYAN}Threads{C.RESET}     (e.g. 100-500)             [{C.GRAY}200{C.RESET}]: ").strip()
    threads = int(thread_input) if thread_input.isdigit() else 200

    timeout_input = input(f"  {C.CYAN}Timeout{C.RESET}     seconds per port            [{C.GRAY}0.5{C.RESET}]: ").strip()
    try:
        timeout = float(timeout_input) if timeout_input else 0.5
    except ValueError:
        timeout = 0.5

    return host, port_input, threads, timeout

# ─── Main ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner — TCP Connect Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py                          # interactive mode
  python port_scanner.py -H localhost             # scan localhost 1-1024
  python port_scanner.py -H 192.168.1.1 -p 1-500
  python port_scanner.py -H scanme.nmap.org -p 22,80,443 -t 300
        """
    )
    parser.add_argument("-H", "--host",    help="Target host / IP")
    parser.add_argument("-p", "--ports",   default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Number of threads (default: 200)")
    parser.add_argument("--timeout",       type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    args = parser.parse_args()

    if not args.host:
        # Interactive
        host, port_input, threads, timeout = interactive_mode()
    else:
        print_banner()
        host       = args.host
        port_input = args.ports
        threads    = args.threads
        timeout    = args.timeout

    ip    = resolve(host)
    ports = parse_ports(port_input)

    print(f"\n  {C.GRAY}{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}Starting scan{C.RESET} on {C.CYAN}{host}{C.RESET} {C.GRAY}({ip}){C.RESET}")
    print(f"  Ports: {C.WHITE}{len(ports):,}{C.RESET}  ·  Threads: {C.WHITE}{threads}{C.RESET}  ·  Timeout: {C.WHITE}{timeout}s{C.RESET}")
    print(f"  {C.GRAY}{'─' * 60}{C.RESET}\n")
    print(f"  {C.GRAY}{'TIME':<10} {'STATE':<8} {'PORT':<8} {'SERVICE'}{C.RESET}")
    print(f"  {C.GRAY}{'─' * 40}{C.RESET}")

    try:
        elapsed = run_scan(host, ports, threads, timeout)
    except KeyboardInterrupt:
        stop_event.set()
        print(f"\n\n  {C.YELLOW}Scan interrupted by user.{C.RESET}")
        elapsed = 0

    print_summary(host, ip, ports, elapsed)

if __name__ == "__main__":
    main()