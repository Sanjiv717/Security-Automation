#!/usr/bin/env python3
"""
server.py - Simple TCP echo server for a basic client/server demo.

Usage:
  python server.py --host 127.0.0.1 --port 5000
Stop:
  Press Ctrl+C to shut down gracefully.
"""
import argparse
import socket
import sys
import threading
import signal

STOP = False

def handle_sigint(signum, frame):
    global STOP
    STOP = True
    print("\n[server] Interrupt received, shutting down...")

def serve(host: str, port: int):
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow immediate reuse after restart
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        s.settimeout(1.0)  # so we can periodically check STOP
        print(f"[server] Listening on {host}:{port} (Ctrl+C to stop)")
        while not STOP:
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except OSError as e:
                print(f"[server] Socket error while accepting: {e}", file=sys.stderr)
                continue

            print(f"[server] Connected by {addr}")
            # Per-connection handling
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

        print("[server] Server loop exited. Goodbye.")

def handle_client(conn: socket.socket, addr):
    with conn:
        # Set a recv timeout to avoid hanging forever
        conn.settimeout(10.0)
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    print(f"[server] Client {addr} disconnected.")
                    break
                message = data.decode(errors="replace").strip()
                print(f"[server] Received from {addr}: {message}")
                # Echo back with a small prefix
                response = f"ACK: {message}\n".encode()
                conn.sendall(response)
        except socket.timeout:
            print(f"[server] Connection with {addr} timed out.")
        except Exception as e:
            print(f"[server] Error with {addr}: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Simple TCP echo server")
    parser.add_argument("--host", default="127.0.0.1", help="Host/IP to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_sigint)
    serve(args.host, args.port)

if __name__ == "__main__":
    main()
