"""Scapy pcap simulation, and reading a capture back into the unified schema."""

import statistics
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "simulation"))
sys.path.insert(0, str(ROOT / "collector"))
import pcapReader  # noqa: E402
from pcapSimulation import PcapSimulator  # noqa: E402

from backend import ingestion, ml  # noqa: E402


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    simulator = PcapSimulator(seed=5, duration_seconds=600)
    truth = {item["scenario"]: item for item in simulator.generate(sessions=80)}
    path = simulator.write(tmp_path_factory.mktemp("pcap") / "capture.pcap")
    return simulator, truth, path, pcapReader.read_pcap(path)


def test_pcap_file_is_written_and_sorted(capture):
    simulator, _, path, _ = capture
    assert path.stat().st_size > 50_000 and path.read_bytes()[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
    times = [float(p.time) for p in simulator.packets]
    assert times == sorted(times) and len(times) > 1000


def test_normal_sessions_become_complete_connections(capture):
    _, truth, _, records = capture
    attackers = {truth["port_scan"]["source_ip"]}
    web = [r for r in records if "query" not in r and r["id.orig_h"].startswith("10.0.2.")
           and r["id.orig_h"] not in attackers and r["id.resp_p"] in (80, 443)
           and r["id.resp_h"] != truth["beaconing"]["dest_ip"]]
    assert len(web) > 20
    assert all(r["conn_state"] == "SF" and r["orig_bytes"] >= 200 and r["resp_bytes"] >= 500 for r in web)
    assert all(r["service"] in ("http", "ssl") and r["proto"] == "tcp" and r["duration"] > 0 for r in web)
    lookups = [r for r in records if r.get("query") in ("example.com", "shop.example.com")]
    assert lookups and all(r["qtype_name"] == "A" and r["rcode_name"] == "NOERROR" for r in lookups)


def test_port_scan_in_capture(capture):
    _, truth, _, records = capture
    scan = [r for r in records if r["id.orig_h"] == truth["port_scan"]["source_ip"]]
    assert len({r["id.resp_p"] for r in scan}) == truth["port_scan"]["ports"] == 150
    states = Counter(r["conn_state"] for r in scan)
    assert states["REJ"] >= 147 and states["REJ"] + states["RSTO"] == 150   # closed ports, and the few open ones
    assert all(r["orig_bytes"] == 0 for r in scan)


def test_tunneling_beaconing_and_exfiltration_in_capture(capture):
    _, truth, _, records = capture
    tunnel = [r for r in records if r.get("query", "").endswith(truth["dns_tunneling"]["domain"])]
    assert len(tunnel) == truth["dns_tunneling"]["queries"] and all(r["qtype_name"] == "TXT" for r in tunnel)
    assert min(len(r["query"]) for r in tunnel) > 60

    beacons = sorted(r["ts"] for r in records if r["id.resp_h"] == truth["beaconing"]["dest_ip"])
    gaps = [b - a for a, b in zip(beacons, beacons[1:])]
    assert len(beacons) == truth["beaconing"]["connections"]
    assert 28 < statistics.mean(gaps) < 32 and statistics.pstdev(gaps) < 2

    (upload,) = [r for r in records if r["id.resp_h"] == truth["data_exfiltration"]["dest_ip"]]
    assert upload["orig_bytes"] == truth["data_exfiltration"]["bytes"] and upload["resp_bytes"] == 800
    assert upload["conn_state"] == "SF" and 19 < upload["duration"] < 21


def test_capture_goes_through_the_zeek_parser_and_ml_features(capture, db):
    _, truth, _, records = capture
    lines = pcapReader.to_lines(records)
    result = ingestion.ingest_batch(lines, "zeek")
    assert result["stored"] and result["parse_errors"] == 0 and result["count"] == len(records)
    assert ingestion.verify_batch(result["batch_id"])["valid"]
    kinds = {row["value"]: row["count"] for row in ingestion.count_by_event_type()}
    assert set(kinds) == {"network_connection", "dns_query"}

    entries, _ = ingestion.normalize(lines, "zeek")
    rows = ml.extract_features([e.to_document() for e in entries], "ip")
    best = lambda ip, feature: max(r["features"][feature] for r in rows if r["entity"] == ip)
    assert best(truth["port_scan"]["source_ip"], "distinct_dest_ports") == 150
    assert best(truth["dns_tunneling"]["source_ip"], "avg_dns_length") > 60
    assert best(truth["beaconing"]["source_ip"], "conn_regularity") > 0.9
    assert best(truth["data_exfiltration"]["source_ip"], "bytes_out") == 600_000


def test_capture_without_attacks_and_empty_capture(tmp_path):
    simulator = PcapSimulator(seed=1, duration_seconds=60)
    assert simulator.generate(sessions=10, attacks=False) == []
    records = pcapReader.read_pcap(simulator.write(tmp_path / "quiet.pcap"))
    assert 0 < len(records) <= 10
    empty = PcapSimulator(seed=1)
    empty.packets = []
    from scapy.utils import wrpcap
    wrpcap(str(tmp_path / "empty.pcap"), [])
    assert pcapReader.read_pcap(tmp_path / "empty.pcap") == []
