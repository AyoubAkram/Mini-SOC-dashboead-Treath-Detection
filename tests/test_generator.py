"""The generator must produce lines every parser understands, with the attacks visible in the data."""

import json
import statistics
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "simulation"))
from logGenerator import SOURCES, LogGenerator  # noqa: E402

from backend import ingestion  # noqa: E402
from backend.models import LogSource  # noqa: E402


@pytest.fixture(scope="module")
def generated():
    generator = LogGenerator(seed=7)
    truth = generator.generate(normal=400)
    parsed = {source: ingestion.normalize(lines, source) for source, lines in generator.by_source().items()}
    return generator, {t["scenario"]: t for t in truth}, parsed


def test_all_sources_generated_and_parsed_without_errors(generated):
    _, _, parsed = generated
    assert set(parsed) == set(SOURCES) == {s.value for s in LogSource}
    for source, (entries, errors) in parsed.items():
        assert errors == 0, source
        assert len(entries) >= 50, source
        assert all(e.event_type.value != "unknown" for e in entries), source


def test_seed_makes_output_reproducible():
    a, b = LogGenerator(seed=3), LogGenerator(seed=3)
    start = a.start
    b.start = start
    a.generate(normal=80), b.generate(normal=80)
    assert [line for _, _, line in a.events] == [line for _, _, line in b.events]
    c = LogGenerator(seed=4, start=start)
    c.generate(normal=80)
    assert [line for _, _, line in c.events] != [line for _, _, line in a.events]


def test_events_are_sorted_and_inside_the_time_window(generated):
    generator, _, _ = generated
    times = [ts for ts, _, _ in generator.events]
    assert times == sorted(times)
    assert times[0] >= generator.start
    assert times[-1] <= generator.start + generator.duration * 1.5


def test_scenario_and_source_selection():
    generator = LogGenerator(seed=1)
    truth = generator.generate(normal=40, scenarios=["port_scan"], sources=["firewall"])
    assert [t["scenario"] for t in truth] == ["port_scan"]
    assert set(generator.by_source()) == {"firewall"}
    quiet = LogGenerator(seed=1)
    assert quiet.generate(normal=40, scenarios=[]) == [] and len(quiet.events) >= 40


def test_brute_force_is_visible(generated):
    _, truth, parsed = generated
    ip = truth["brute_force"]["source_ip"]
    events = Counter(e.event_type.value for e in parsed["linux_auth"][0] if e.source_ip == ip)
    assert events["login_failed"] == truth["brute_force"]["attempts"]
    assert events["login_success"] == 1


def test_port_scan_is_visible(generated):
    _, truth, parsed = generated
    ip = truth["port_scan"]["source_ip"]
    ports = {e.dest_port for e in parsed["firewall"][0] if e.source_ip == ip and e.event_type.value == "firewall_drop"}
    assert len(ports) == truth["port_scan"]["ports"] >= 100


def test_sql_injection_is_visible(generated):
    _, truth, parsed = generated
    ip = truth["sql_injection"]["source_ip"]
    hits = [e for e in parsed["web"][0] if e.source_ip == ip]
    assert len(hits) == truth["sql_injection"]["requests"]
    assert all("sqlmap" in e.extra["user_agent"] for e in hits)
    assert any("UNION" in e.extra["path"] for e in hits)


def test_privilege_escalation_and_account_creation_are_visible(generated):
    _, truth, parsed = generated
    auth = parsed["linux_auth"][0]
    user = truth["privilege_escalation"]["username"]
    kinds = [e.event_type.value for e in auth if e.username == user]
    assert kinds.count("sudo_failed") == 4 and kinds[-1] == "sudo_command"
    created = [e for e in auth if e.event_type.value == "account_created"]
    assert [e.username for e in created] == [truth["privilege_escalation"]["created_account"]]


def test_windows_account_takeover_is_visible(generated):
    _, truth, parsed = generated
    ip = truth["account_takeover"]["source_ip"]
    windows = parsed["windows_event"][0]
    from_attacker = Counter(e.event_type.value for e in windows if e.source_ip == ip)
    assert from_attacker["login_failed"] >= 15 and from_attacker["login_success"] == 1
    kinds = {e.event_type.value for e in windows}
    assert {"privilege_assigned", "account_created", "account_locked", "explicit_credential_logon"} <= kinds


def test_beaconing_has_regular_intervals(generated):
    _, truth, parsed = generated
    t = truth["beaconing"]
    times = sorted(e.timestamp for e in parsed["zeek"][0] if e.dest_ip == t["dest_ip"])
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    assert len(times) == t["connections"]
    assert 55 < statistics.mean(gaps) < 65 and statistics.pstdev(gaps) < 5


def test_exfiltration_and_dns_tunneling_are_visible(generated):
    _, truth, parsed = generated
    zeek = parsed["zeek"][0]
    exfil = truth["data_exfiltration"]
    sent = sum(e.extra["orig_bytes"] for e in zeek if e.dest_ip == exfil["dest_ip"])
    assert sent == exfil["bytes"] > 1_000_000_000
    tunnel = truth["dns_tunneling"]
    queries = [e.extra["query"] for e in zeek if e.event_type.value == "dns_query" and e.extra["query"].endswith(tunnel["domain"])]
    assert len(queries) == tunnel["queries"] and min(len(q) for q in queries) > 50


def test_cloud_takeover_and_lateral_movement_are_visible(generated):
    _, truth, parsed = generated
    ip = truth["cloud_takeover"]["source_ip"]
    kinds = [e.event_type.value for e in parsed["cloudtrail"][0] if e.source_ip == ip]
    assert kinds.count("login_failed") >= 8
    assert kinds[-4:] == ["login_success", "account_created", "privilege_assigned", "privilege_assigned"]
    src = truth["lateral_movement"]["source_ip"]
    hosts = {e.host for e in parsed["linux_auth"][0] if e.source_ip == src and e.event_type.value == "login_success"}
    assert len(hosts) == 4


def test_attackers_use_documentation_ranges_only(generated):
    _, truth, _ = generated
    nets = ("203.0.113.", "198.51.100.", "192.0.2.")
    for name in ("brute_force", "port_scan", "sql_injection", "account_takeover", "cloud_takeover"):
        assert truth[name]["source_ip"].startswith(nets), name


def test_write_files_and_ingest_end_to_end(generated, db, tmp_path):
    generator, _, _ = generated
    paths = generator.write_files(tmp_path)
    assert {p.name for p in paths.values()} == {f"{s}.log" for s in SOURCES}
    total = 0
    for source, path in paths.items():
        for result in ingestion.ingest_file(path, source):
            assert result["stored"] and result["parse_errors"] == 0
            assert ingestion.verify_batch(result["batch_id"])["valid"]
            total += result["count"]
    assert total == len(generator.events) == ingestion.get_log_count()
    assert {row["value"] for row in ingestion.count_by_log_source()} == set(SOURCES)


def test_sample_logs_file_parses():
    sample = json.loads((Path(__file__).resolve().parent.parent / "data" / "sample_logs.json").read_text())
    assert {item["log_source"] for item in sample} == set(SOURCES)
    for source in SOURCES:
        lines = [item["raw"] for item in sample if item["log_source"] == source]
        entries, errors = ingestion.normalize(lines, source)
        assert errors == 0 and len(entries) == len(lines), source
