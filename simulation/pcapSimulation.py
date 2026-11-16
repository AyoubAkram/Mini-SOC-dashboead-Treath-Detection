"""
Simulated packet capture
Builds a pcap file with Scapy: normal web and DNS traffic plus four attacks
(SYN port scan, DNS tunneling, beaconing, data exfiltration). Nothing is sent
on the network: packets are only written to a file.

    python simulation/pcapSimulation.py --out data/generated/capture.pcap --seed 42
    python collector/pcapReader.py data/generated/capture.pcap --ingest
"""

import argparse
import random
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESOLVER = "10.0.0.2"
WEB_SERVER = "10.0.1.10"
DOMAINS = ["example.com", "shop.example.com", "cdn.example.net", "mail.example.org", "api.example.io"]


class PcapSimulator:
    def __init__(self, seed: Optional[int] = None, start: Optional[float] = None,
                 duration_seconds: float = 600):
        self.rng = random.Random(seed)
        self.duration = duration_seconds
        self.start = start if start is not None else time.time() - duration_seconds
        self.packets: List = []
        self.workstations = [f"10.0.2.{self.rng.randint(10, 250)}" for _ in range(12)]

    # -- helpers ---------------------------------------------------------------

    def _when(self) -> float:
        return self.start + self.rng.uniform(0, self.duration * 0.95)

    def _port(self) -> int:
        return self.rng.randint(32768, 60999)

    def attacker_ip(self) -> str:
        return f"{self.rng.choice(['203.0.113', '198.51.100', '192.0.2'])}.{self.rng.randint(2, 254)}"

    def add(self, ts: float, packet) -> None:
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet
        packet.time = ts
        self.packets.append(packet)

    def tcp_session(self, ts: float, src: str, dst: str, dport: int, sent: int = 400,
                    received: int = 1500, duration: float = 0.3) -> None:
        """A complete TCP connection: handshake, data both ways, clean close."""
        sport, mss = self._port(), 1400
        seq, ack = self.rng.randint(1000, 2 ** 31), self.rng.randint(1000, 2 ** 31)
        client = lambda **kw: IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, **kw)
        server = lambda **kw: IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, **kw)
        self.add(ts, client(flags="S", seq=seq))
        self.add(ts + 0.001, server(flags="SA", seq=ack, ack=seq + 1))
        self.add(ts + 0.002, client(flags="A", seq=seq + 1, ack=ack + 1))
        chunks = [(client, sent), (server, received)]
        steps = sum(-(-size // mss) for _, size in chunks) or 1
        step, at = duration / (steps + 1), ts + 0.003
        for maker, size in chunks:
            while size > 0:
                chunk = min(size, mss)
                at += step
                self.add(at, maker(flags="PA") / Raw(b"\x00" * chunk))
                size -= chunk
        self.add(ts + duration, client(flags="FA"))
        self.add(ts + duration + 0.001, server(flags="FA"))
        self.add(ts + duration + 0.002, client(flags="A"))

    def dns_query(self, ts: float, src: str, name: str, qtype: str = "A", answer: bool = True) -> None:
        sport, query_id = self._port(), self.rng.randint(1, 65535)
        question = DNSQR(qname=name, qtype=qtype)
        self.add(ts, IP(src=src, dst=RESOLVER) / UDP(sport=sport, dport=53)
                 / DNS(id=query_id, rd=1, qd=question))
        if answer:
            record = (DNSRR(rrname=name, type="A", rdata="93.184.216.34") if qtype == "A"
                      else DNSRR(rrname=name, type="TXT", rdata="ok"))
            self.add(ts + 0.02, IP(src=RESOLVER, dst=src) / UDP(sport=53, dport=sport)
                     / DNS(id=query_id, qr=1, rd=1, ra=1, qd=question, an=record))

    # -- traffic ---------------------------------------------------------------

    def normal_traffic(self, sessions: int = 120) -> None:
        for _ in range(sessions):
            ts, src = self._when(), self.rng.choice(self.workstations)
            if self.rng.random() < 0.4:
                self.dns_query(ts, src, self.rng.choice(DOMAINS))
            else:
                dst = f"{self.rng.randint(11, 220)}.{self.rng.randint(1, 250)}.{self.rng.randint(1, 250)}.{self.rng.randint(1, 250)}"
                self.tcp_session(ts, src, dst, self.rng.choice([80, 443, 443]),
                                 sent=self.rng.randint(200, 1500),
                                 received=self.rng.randint(500, 9000),
                                 duration=self.rng.uniform(0.05, 2))

    def port_scan(self) -> Dict:
        """SYN scan: one SYN per port, answered by RST (closed) or SYN-ACK then RST (open)."""
        src, ts = self.attacker_ip(), self.start + self.duration * self.rng.uniform(0.2, 0.7)
        ports = self.rng.sample(range(1, 5000), 150)
        for port in ports:
            ts += self.rng.uniform(0.005, 0.05)
            sport = self._port()
            self.add(ts, IP(src=src, dst=WEB_SERVER) / TCP(sport=sport, dport=port, flags="S"))
            if port in (22, 80, 443):
                self.add(ts + 0.001, IP(src=WEB_SERVER, dst=src) / TCP(sport=port, dport=sport, flags="SA"))
                self.add(ts + 0.002, IP(src=src, dst=WEB_SERVER) / TCP(sport=sport, dport=port, flags="R"))
            else:
                self.add(ts + 0.001, IP(src=WEB_SERVER, dst=src) / TCP(sport=port, dport=sport, flags="RA"))
        return {"scenario": "port_scan", "source_ip": src, "ports": len(ports)}

    def dns_tunneling(self) -> Dict:
        src, domain = "10.0.3.40", "cdn-update.example.net"
        ts, count = self.start + self.duration * self.rng.uniform(0.2, 0.7), 80
        for _ in range(count):
            ts += self.rng.uniform(0.1, 0.5)
            label = "".join(self.rng.choices("0123456789abcdef", k=50))
            self.dns_query(ts, src, f"{label}.{domain}", qtype="TXT")
        return {"scenario": "dns_tunneling", "source_ip": src, "domain": domain, "queries": count}

    def beaconing(self) -> Dict:
        src, c2, interval = "10.0.2.77", self.attacker_ip(), 30
        ts, count = self.start + 5, int(self.duration * 0.9 // interval)
        for _ in range(count):
            self.tcp_session(ts, src, c2, 443, sent=200, received=110, duration=0.2)
            ts += interval + self.rng.uniform(-1, 1)
        return {"scenario": "beaconing", "source_ip": src, "dest_ip": c2, "connections": count}

    def data_exfiltration(self) -> Dict:
        src, dst, size = "10.0.3.40", self.attacker_ip(), 600_000
        self.tcp_session(self.start + self.duration * 0.8, src, dst, 443, sent=size, received=800,
                         duration=20)
        return {"scenario": "data_exfiltration", "source_ip": src, "dest_ip": dst, "bytes": size}

    def generate(self, sessions: int = 120, attacks: bool = True) -> List[Dict]:
        self.normal_traffic(sessions)
        truth = []
        if attacks:
            truth = [self.port_scan(), self.dns_tunneling(), self.beaconing(), self.data_exfiltration()]
        self.packets.sort(key=lambda packet: float(packet.time))
        return truth

    def write(self, path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(path), self.packets)
        return path


def main():
    parser = argparse.ArgumentParser(description="ARGUS simulated packet capture (Scapy)")
    parser.add_argument("--out", default=str(ROOT / "data" / "generated" / "capture.pcap"))
    parser.add_argument("--sessions", type=int, default=120, help="number of normal sessions")
    parser.add_argument("--seconds", type=float, default=600, help="time covered by the capture")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--no-attacks", action="store_true")
    args = parser.parse_args()

    simulator = PcapSimulator(args.seed, duration_seconds=args.seconds)
    truth = simulator.generate(args.sessions, attacks=not args.no_attacks)
    path = simulator.write(args.out)
    print(f"✓ {len(simulator.packets)} packets written to {path}")
    for item in truth:
        print(f"  ⚠ {item}")


if __name__ == "__main__":
    main()
