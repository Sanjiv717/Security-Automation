#!/usr/bin/env python3
"""
port_scanner.py - Educational TCP port scanner with ethical safeguards.

Authorized targets for your assignment:
  - localhost (127.0.0.1)
  - scanme.nmap.org  (allowed by nmap for testing)

Examples:
  python port_scanner.py --host 127.0.0.1 --ports 20-25,80,443
  python port_scanner.py --host scanme.nmap.org --ports 20-100 --timeout 0.5 --delay-ms 50

Notes:
  * Sequential scanning with optional delay helps avoid aggressive behavior.
  * This tool reports OPEN/CLOSED for TCP connect() attempts.
"""
import argparse
import socket
import sys
import time
from typing import List, Tuple

def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = a.strip(), b.strip()
            if not a.isdigit() or not b.isdigit():
                raise ValueError(f"Invalid range '{part}'")
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                ports.add(p)
        else:
            if not part.isdigit():
                raise ValueError(f"Invalid port '{part}'")
            ports.add(int(part))
    cleaned = [p for p in sorted(ports) if 0 < p <= 65535]
    if not cleaned:
        raise ValueError("No valid ports parsed.")
    return cleaned

def resolve_host(host: str) -> str:
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        raise ValueError(f"Invalid host: {host}")

def is_authorized_target(host: str) -> bool:
    authorized = {"127.0.0.1", "localhost", "scanme.nmap.org"}
    return host in authorized

def scan_port(ip: str, port: int, timeout: float) -> Tuple[int, bool]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            return port, result == 0
        except Exception:
            return port, False

def main():
    parser = argparse.ArgumentParser(description="Educational TCP port scanner")
    parser.add_argument("--host", required=True, help="Target hostname (authorized: localhost or scanme.nmap.org)")
    parser.add_argument("--ports", required=True, help="Port list/ranges, e.g., 22,80,443 or 20-25,80")
    parser.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout in seconds (default: 0.5)")
    parser.add_argument("--delay-ms", type=int, default=25, help="Delay between ports in milliseconds (default: 25)")
    args = parser.parse_args()

    if not is_authorized_target(args.host):
        print("[scanner] ERROR: This scanner is restricted to localhost or scanme.nmap.org for coursework.", file=sys.stderr)
        sys.exit(10)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[scanner] Port parse error: {e}", file=sys.stderr)
        sys.exit(11)

    try:
        ip = resolve_host(args.host)
    except ValueError as e:
        print(f"[scanner] Host resolution error: {e}", file=sys.stderr)
        sys.exit(12)

    print(f"[scanner] Scanning {args.host} ({ip}) on {len(ports)} port(s) ...")
    open_ports = []
    closed_ports = 0
    delay = max(0, args.delay_ms) / 1000.0

    for p in ports:
        port, is_open = scan_port(ip, p, args.timeout)
        status = "OPEN" if is_open else "closed"
        print(f"{port:>5}  {status}")
        if is_open:
            open_ports.append(port)
        else:
            closed_ports += 1
        time.sleep(delay)

    print("\n[scanner] Summary")
    print(f"  Host: {args.host} ({ip})")
    print(f"  Ports scanned: {len(ports)}")
    print(f"  Open: {len(open_ports)}")
    print(f"  Closed: {closed_ports}")
    if open_ports:
        print(f"  Open ports: {', '.join(map(str, open_ports))}")

if __name__ == "__main__":
    main()
