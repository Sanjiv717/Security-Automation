#!/usr/bin/env python3
"""
client.py - Simple TCP client for the server in server.py

Usage:
  python client.py --host 127.0.0.1 --port 5000 --message "Hello server"
"""
import argparse
import socket
import sys

def run_client(host: str, port: int, message: str, timeout: float = 5.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            print(f"[client] Connected to {host}:{port}")
            sock.sendall((message.strip() + "\n").encode())
            data = sock.recv(1024)
            if data:
                print(f"[client] Received: {data.decode(errors='replace').strip()}")
            print("[client] Disconnecting cleanly.")
    except ConnectionRefusedError:
        print(f"[client] ERROR: Connection refused by {host}:{port}", file=sys.stderr)
        sys.exit(2)
    except socket.gaierror:
        print(f"[client] ERROR: Invalid hostname: {host}", file=sys.stderr)
        sys.exit(3)
    except socket.timeout:
        print(f"[client] ERROR: Connection timed out to {host}:{port}", file=sys.stderr)
        sys.exit(4)
    except Exception as e:
        print(f"[client] ERROR: {e}", file=sys.stderr)
        sys.exit(5)

def main():
    parser = argparse.ArgumentParser(description="Simple TCP client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Server port (default: 5000)")
    parser.add_argument("--message", default="Hello from client", help="Message to send")
    args = parser.parse_args()
    run_client(args.host, args.port, args.message)

if __name__ == "__main__":
    main()
