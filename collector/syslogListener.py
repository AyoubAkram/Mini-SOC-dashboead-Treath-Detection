"""
UDP Syslog listener
Receives syslog messages (RFC 5424 or RFC 3164) over UDP and ingests them.

The standard syslog port 514 needs root, so the default is 5514:
    python collector/syslogListener.py --port 5514
Test it with:
    logger -n 127.0.0.1 -P 5514 -d --rfc5424 "hello from logger"
"""

import argparse
import socket
import sys
from pathlib import Path

# Add backend to path to import ingestion module
sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.ingestion import LogBatcher

MAX_DATAGRAM = 65535


def decode(datagram: bytes):
    """A datagram normally holds one message; split defensively on newlines."""
    text = datagram.decode("utf-8", errors="replace")
    return [line for line in text.splitlines() if line.strip()]


def serve(host: str = "0.0.0.0", port: int = 5514, batcher=None, stop_event=None):
    """Listen until stop_event is set (forever when it is None)."""
    batcher = batcher or LogBatcher("syslog")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    print(f"✓ Syslog listener on udp://{host}:{sock.getsockname()[1]}")
    try:
        while stop_event is None or not stop_event.is_set():
            try:
                datagram, _ = sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            for line in decode(datagram):
                batcher.add(line)
    finally:
        sock.close()
        batcher.close()


def main():
    parser = argparse.ArgumentParser(description="ARGUS UDP syslog listener")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5514, help="UDP port (514 requires root)")
    args = parser.parse_args()
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
