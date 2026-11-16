"""
Pcap reader
Turns a packet capture into Zeek-style connection and DNS records (one JSON
line each), so captured traffic goes through the same Zeek parser and the same
unified schema as every other source.

    python collector/pcapReader.py data/generated/capture.pcap            # print the records
    python collector/pcapReader.py data/generated/capture.pcap --ingest   # store them
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import PcapReader

# Add backend to path to import ingestion module
sys.path.insert(0, str(Path(__file__).parent.parent))

SERVICES = {22: "ssh", 53: "dns", 80: "http", 443: "ssl", 3389: "rdp"}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
SYN, FIN, RST, ACK = 0x02, 0x01, 0x04, 0x10


def _conn_state(flow: Dict) -> str:
    """Zeek-like summary of how a TCP connection went."""
    if flow["proto"] != "tcp":
        return "SF" if flow["resp_pkts"] else "S0"
    orig, resp = flow["orig_flags"], flow["resp_flags"]
    if orig & SYN and not flow["resp_pkts"]:
        return "S0"                      # SYN, no answer
    if orig & SYN and resp & RST and not resp & SYN:
        return "REJ"                     # SYN answered by RST: closed port
    if orig & SYN and resp & SYN:
        if orig & FIN and resp & FIN:
            return "SF"                  # established, closed normally
        if orig & RST:
            return "RSTO"                # established, reset by the originator
        if resp & RST:
            return "RSTR"
        return "S1"                      # established, never closed
    return "OTH"


def read_pcap(path) -> List[Dict]:
    """Read a capture and return Zeek-style records (conn and dns), oldest first."""
    flows: Dict[Tuple, Dict] = {}
    dns: Dict[Tuple, Dict] = {}

    with PcapReader(str(path)) as reader:
        for packet in reader:
            if IP not in packet:
                continue
            ip, ts = packet[IP], float(packet.time)

            if UDP in packet and DNS in packet and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                message = packet[DNS]
                if message.qd is None:
                    continue
                question = message.qd[0] if hasattr(message.qd, "__getitem__") else message.qd
                name = question.qname.decode(errors="replace").rstrip(".")
                if message.qr == 0:
                    dns[(ip.src, message.id, name)] = {
                        "ts": round(ts, 6), "uid": f"D{len(dns) + 1:06d}", "id.orig_h": ip.src,
                        "id.orig_p": packet[UDP].sport, "id.resp_h": ip.dst, "id.resp_p": 53,
                        "proto": "udp", "query": name,
                        "qtype_name": QTYPES.get(question.qtype, str(question.qtype))}
                elif (ip.dst, message.id, name) in dns:
                    dns[(ip.dst, message.id, name)]["rcode_name"] = RCODES.get(message.rcode, str(message.rcode))
                continue

            if TCP in packet:
                proto, layer = "tcp", packet[TCP]
            elif UDP in packet:
                proto, layer = "udp", packet[UDP]
            elif ICMP in packet:
                proto, layer = "icmp", None
            else:
                continue
            sport, dport = (layer.sport, layer.dport) if layer is not None else (0, 0)
            payload = len(layer.payload) if layer is not None else len(packet[ICMP].payload)
            flags = int(layer.flags) if proto == "tcp" else 0

            key, reverse = (proto, ip.src, sport, ip.dst, dport), (proto, ip.dst, dport, ip.src, sport)
            if key in flows:
                flow = flows[key]
                flow["orig_bytes"] += payload
                flow["orig_flags"] |= flags
            elif reverse in flows:
                flow = flows[reverse]
                flow["resp_bytes"] += payload
                flow["resp_flags"] |= flags
                flow["resp_pkts"] += 1
            else:  # the first packet decides who the originator is
                flow = flows[key] = {
                    "ts": ts, "last": ts, "proto": proto, "orig_h": ip.src, "orig_p": sport,
                    "resp_h": ip.dst, "resp_p": dport, "orig_bytes": payload, "resp_bytes": 0,
                    "orig_flags": flags, "resp_flags": 0, "resp_pkts": 0}
            flow["last"] = max(flow["last"], ts)

    records = list(dns.values())
    for index, flow in enumerate(flows.values(), 1):
        record = {"ts": round(flow["ts"], 6), "uid": f"C{index:06d}", "id.orig_h": flow["orig_h"],
                  "id.orig_p": flow["orig_p"], "id.resp_h": flow["resp_h"], "id.resp_p": flow["resp_p"],
                  "proto": flow["proto"], "duration": round(flow["last"] - flow["ts"], 6),
                  "orig_bytes": flow["orig_bytes"], "resp_bytes": flow["resp_bytes"],
                  "conn_state": _conn_state(flow)}
        if flow["resp_p"] in SERVICES:
            record["service"] = SERVICES[flow["resp_p"]]
        records.append(record)
    records.sort(key=lambda record: record["ts"])
    return records


def to_lines(records: List[Dict]) -> List[str]:
    return [json.dumps(record, separators=(",", ":")) for record in records]


def main():
    parser = argparse.ArgumentParser(description="ARGUS pcap reader")
    parser.add_argument("pcap")
    parser.add_argument("--ingest", action="store_true", help="store the records in MongoDB")
    args = parser.parse_args()

    lines = to_lines(read_pcap(args.pcap))
    if not args.ingest:
        print("\n".join(lines))
        return
    from backend.ingestion import ingest_batch
    stored = 0
    for i in range(0, len(lines), 500):
        result = ingest_batch(lines[i:i + 500], "zeek")
        stored += result["count"] if result["stored"] else 0
    print(f"✓ {len(lines)} records read, {stored} stored")


if __name__ == "__main__":
    main()
