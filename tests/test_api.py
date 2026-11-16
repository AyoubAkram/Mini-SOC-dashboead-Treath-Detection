"""API endpoints. main.py imports the backend modules by their plain names, so the
mock database is injected into that copy of the database module."""

import os
import sys
from pathlib import Path

import mongomock
import pytest
from fastapi.testclient import TestClient

os.environ["SOC_COLLECTOR"] = "off"  # never start the journalctl collector in tests
os.environ["ML_DETECT_INTERVAL"] = "0"  # no background detection in tests
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import dataBase as database  # noqa: E402
import ingestion  # noqa: E402
import main  # noqa: E402
import ml  # noqa: E402

from datetime import datetime, timedelta, timezone  # noqa: E402


def stamp(minutes_ago: float) -> str:
    """BSD syslog timestamp a few minutes in the past (the API filters by time range)."""
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')}"


def auth_lines(minutes_ago: float = 10):
    t = lambda offset: stamp(minutes_ago - offset)
    return [
        f"{t(0)} bastion sshd[1]: Failed password for root from 203.0.113.7 port 1001 ssh2",
        f"{t(0.1)} bastion sshd[1]: Failed password for root from 203.0.113.7 port 1002 ssh2",
        f"{t(0.2)} bastion sshd[1]: Accepted password for alice from 10.0.0.8 port 1003 ssh2",
        f"{t(0.3)} bastion useradd[9]: new user: name=backdoor, UID=1001",
        f"{t(0.4)} bastion sshd[1]: Connection closed by 10.0.0.8 port 1003",
    ]


def web_lines(minutes_ago: float = 10):
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return [f'198.51.100.9 - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8"']


def ids_lines(minutes_ago: float = 5):
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    head = ts.strftime("%m/%d/%y-%H:%M:%S.000001")
    return [
        f"{head} [**] [1:2006446:1] ET WEB_SERVER SQL Injection [**] [Classification: Web Application Attack] [Priority: 1] {{TCP}} 203.0.113.7:4000 -> 10.0.1.10:80",
        f"{head} [**] [1:2001219:1] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {{TCP}} 203.0.113.7:4001 -> 10.0.1.5:22",
        f"{head} [**] [1:366:1] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {{ICMP}} 10.0.0.9 -> 10.0.0.1",
    ]


@pytest.fixture
def client():
    database.set_db(mongomock.MongoClient().soc_api_test)
    with TestClient(main.app) as test_client:
        yield test_client
    database.set_db(None)
    database.reset_connection()


@pytest.fixture
def seeded(client):
    batch = ingestion.ingest_batch(auth_lines(), "linux_auth")
    ingestion.ingest_batch(web_lines(), "web")
    return client, batch


def test_health_and_root(client):
    assert client.get("/api/health").json() == {"status": "healthy"}
    assert client.get("/").json()["status"] == "operational"


def test_logs_contract_fields_and_pagination(seeded):
    client, _ = seeded
    body = client.get("/api/logs").json()
    assert body["total"] == 6 and len(body["logs"]) == 6 and body["limit"] == 50 and body["offset"] == 0
    contract = {"id", "timestamp", "source_ip", "username", "event_type", "log_source", "message", "raw"}
    assert all(contract <= set(log) for log in body["logs"])
    page = client.get("/api/logs", params={"limit": 2, "offset": 4}).json()
    assert len(page["logs"]) == 2 and page["total"] == 6
    assert client.get("/api/logs", params={"limit": 99999}).json()["limit"] == 500
    assert client.get("/api/logs", params={"limit": -5, "offset": -1}).json()["limit"] == 1


def test_logs_filters(seeded):
    client, _ = seeded
    get = lambda **params: client.get("/api/logs", params=params).json()
    assert get(log_source="web")["total"] == 1
    assert get(event_type="login_failed")["total"] == 2
    assert get(source_ip="203.0.113.7", username="root")["total"] == 2
    assert get(search="new user")["logs"][0]["username"] == "backdoor"
    assert get(username="nobody") == {"logs": [], "total": 0, "limit": 50, "offset": 0}
    assert client.get("/api/logs", params={"log_source": "bogus"}).status_code == 422


def test_stats_event_types_and_source_ips(seeded):
    client, _ = seeded
    stats = client.get("/api/stats").json()
    assert stats["total_events"] == 6 and stats["database_connected"] is True
    assert stats["active_alerts"] == 3 and stats["failed_logins"] == 2 and stats["unique_source_ips"] == 3
    assert stats["severity_counts"] == {"critical": 0, "high": 1, "medium": 2, "low": 0}
    assert stats["total_events_trend"] is None  # nothing in the previous period
    assert stats["threat_score"] == round(10 * 6 / (6 + 3), 1) and stats["threat_level"] == "high"
    body = client.get("/api/event-types").json()
    assert body["event_types"][0] == {"name": "login_failed", "count": 2, "percentage": 100}
    assert {row["name"]: row["count"] for row in body["log_sources"]} == {"linux_auth": 5, "web": 1}
    ips = client.get("/api/source-ips").json()["source_ips"]
    assert {"ip": "203.0.113.7", "location": "External", "event_count": 2, "threat_level": "unknown"} in ips
    assert [row["event_count"] for row in ips] == [2, 2, 1]
    assert {"ip": "10.0.0.8", "location": "Internal Network", "event_count": 2, "threat_level": "unknown"} in ips
    assert len(client.get("/api/source-ips", params={"limit": 1}).json()["source_ips"]) == 1


def test_time_range_and_trend(client):
    ingestion.ingest_batch(auth_lines(minutes_ago=10), "linux_auth")       # this hour
    ingestion.ingest_batch(auth_lines(minutes_ago=90)[:2], "linux_auth")   # previous hour
    ingestion.ingest_batch(web_lines(minutes_ago=60 * 30), "web")          # 30 hours ago
    get = lambda path, r: client.get(path, params={"time_range": r}).json()
    hour = get("/api/stats", "1h")
    assert hour["total_events"] == 5 and hour["total_events_trend"] == 150.0
    assert hour["failed_logins_trend"] == 0.0 and hour["time_range"] == "1h"
    assert get("/api/stats", "24h")["total_events"] == 7
    assert get("/api/stats", "7d")["total_events"] == 8
    assert get("/api/stats", "bogus")["time_range"] == "24h"
    assert get("/api/alerts", "1h")["total"] == 3 and get("/api/alerts", "24h")["total"] == 5
    assert len(get("/api/source-ips", "1h")["source_ips"]) == 2
    assert len(get("/api/source-ips", "7d")["source_ips"]) == 3
    assert get("/api/event-types", "7d")["log_sources"][1] == {"name": "web", "count": 1}


def test_alerts_filters_and_status_workflow(seeded):
    client, _ = seeded
    ingestion.ingest_batch(ids_lines(), "ids")
    get = lambda **params: client.get("/api/alerts", params=params).json()
    body = get()
    # 2 failed logins, 1 account created, 3 IDS alerts; not the successful login, web hit or disconnect
    assert body["total"] == 6 and body["alerts"][0]["type"] == "Ids Alert"
    assert {a["severity"] for a in body["alerts"]} == {"critical", "high", "medium"}
    assert [get(severity=s)["total"] for s in ("critical", "high", "medium", "low")] == [1, 2, 3, 0]
    assert get(search="203.0.113.7")["total"] == 4 and get(search="BACKDOOR")["total"] == 1
    assert get(search="(")["total"] == 0  # not treated as a regex
    assert len(get(limit=2, offset=4)["alerts"]) == 2
    critical = get(severity="critical")["alerts"][0]
    assert critical["destination"] == "10.0.1.10:80" and critical["status"] == "open"
    failed = get(search="Failed password")["alerts"][0]
    assert (failed["source"], failed["destination"], failed["username"]) == ("203.0.113.7", "bastion", "root")

    alert_id = critical["id"]
    acknowledged = client.post(f"/api/alerts/{alert_id}/acknowledge").json()
    assert (acknowledged["alert_id"], acknowledged["status"]) == (alert_id, "investigating")
    assert get(status="investigating")["total"] == 1 and get(status="open")["total"] == 5
    assert client.patch(f"/api/alerts/{alert_id}/resolve").json()["status"] == "resolved"
    assert get(status="resolved")["alerts"][0]["id"] == alert_id
    assert get(status="unresolved")["total"] == 5 and get()["total"] == 6
    assert client.get("/api/stats").json()["severity_counts"]["critical"] == 0  # resolved alerts leave the stats
    assert client.post(f"/api/alerts/{alert_id}/reopen").json()["status"] == "open"
    assert get(status="unresolved")["total"] == 6
    assert client.post("/api/alerts/does-not-exist/resolve").status_code == 404
    # triage does not break the integrity hash
    batch_id = database.get_db().logs.find_one({"_id": alert_id})["batch_id"]
    assert client.get(f"/api/batches/{batch_id}/verify").json()["valid"] is True


def test_threats_and_timeline(seeded):
    client, _ = seeded
    ingestion.ingest_batch(ids_lines(), "ids")
    body = client.get("/api/threats").json()
    assert body["total"] == 3 and {t["severity"] for t in body["threats"]} == {"critical", "high", "medium"}
    top = client.get("/api/threats", params={"severity": "critical"}).json()["threats"]
    assert len(top) == 1 and top[0]["title"] == "ET WEB_SERVER SQL Injection"
    assert top[0]["description"] == "Web Application Attack" and top[0]["target"] == "10.0.1.10:80"
    assert client.post(f"/api/threats/{top[0]['id']}/investigate").json()["status"] == "investigating"
    assert client.get("/api/threats", params={"severity": "critical"}).json()["threats"][0]["status"] == "investigating"
    client.post(f"/api/alerts/{top[0]['id']}/resolve")
    assert client.get("/api/threats").json()["total"] == 2  # resolved threats are no longer active

    timeline = client.get("/api/timeline").json()["timeline"]
    assert [e["severity"] for e in timeline] == ["critical", "high", "high"]  # newest first, no medium
    assert timeline[-1]["title"] == "Account Created"
    assert len(client.get("/api/timeline", params={"limit": 1}).json()["timeline"]) == 1


def test_batch_verify_endpoint(seeded):
    client, batch = seeded
    assert client.get(f"/api/batches/{batch['batch_id']}/verify").json()["valid"] is True
    database.get_db().logs.delete_one({"batch_id": batch["batch_id"], "batch_seq": 0})
    assert client.get(f"/api/batches/{batch['batch_id']}/verify").json()["valid"] is False
    assert client.get("/api/batches/nope/verify").json()["reason"] == "batch not found"


def test_endpoints_survive_without_database(client, monkeypatch):
    monkeypatch.setattr(database, "get_db", lambda: None)
    assert client.get("/api/logs").json() == {"logs": [], "total": 0, "limit": 50, "offset": 0}
    stats = client.get("/api/stats").json()
    assert stats["total_events"] == 0 and stats["database_connected"] is False and stats["threat_score"] == 0.0
    assert client.get("/api/alerts").json()["alerts"] == []
    assert client.get("/api/threats").json() == {"threats": [], "total": 0}
    assert client.get("/api/timeline").json() == {"timeline": [], "total": 0}
    assert client.post("/api/alerts/x/resolve").status_code == 404
    assert client.get("/api/event-types").json() == {"event_types": [], "log_sources": []}
    assert client.get("/api/source-ips").json() == {"source_ips": []}


def test_alert_volume_and_attack_types(seeded):
    client, _ = seeded
    ingestion.ingest_batch(ids_lines(), "ids")
    body = client.get("/api/alert-volume", params={"time_range": "1h"}).json()
    assert body["bucket_minutes"] == 5 and 12 <= len(body["buckets"]) <= 13
    assert set(body["buckets"][0]) == {"time", "critical", "high", "medium", "low", "ml"}
    assert [b["time"] for b in body["buckets"]] == sorted(b["time"] for b in body["buckets"])
    totals = {k: sum(b[k] for b in body["buckets"]) for k in ("critical", "high", "medium", "low", "ml")}
    assert totals == {"critical": 1, "high": 2, "medium": 3, "low": 0, "ml": 0}
    assert client.get("/api/alert-volume").json()["bucket_minutes"] == 60
    assert client.get("/api/alert-volume", params={"time_range": "x"}).json()["bucket_minutes"] == 60
    types = client.get("/api/attack-types").json()["attack_types"]
    assert types[0] == {"name": "ids_alert", "count": 3} and {"name": "account_created", "count": 1} in types
    stats = client.get("/api/stats").json()
    assert stats["rule_alerts"] == 6 and stats["ml_alerts"] == 0


def test_ml_endpoints(client, tmp_path, monkeypatch):
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "simulation"))
    from logGenerator import LogGenerator
    monkeypatch.setattr(ml, "MODEL_DIR", tmp_path / "models")

    assert client.get("/api/ml/models").json() == {"active": None, "versions": []}
    assert client.post("/api/ml/train").status_code == 409            # no data yet
    assert client.post("/api/ml/train", params={"contamination": 0.9}).status_code == 422
    assert client.post("/api/ml/detect").json()["reason"] == "no trained model"
    assert client.get("/api/ml/anomalies").json() == {"anomalies": [], "total": 0}
    assert client.get("/api/ml/entities").json() == {"entities": []}

    start = datetime.now(timezone.utc) - timedelta(hours=3, minutes=5)
    normal = LogGenerator(seed=31, start=start, duration_minutes=120)
    normal.generate(normal=1600, scenarios=[])
    for source, lines in normal.by_source().items():
        ingestion.ingest_batch(lines, source)
    assert client.post("/api/ml/train").json()["version"] == "v1"
    attack = LogGenerator(seed=32, start=start + timedelta(hours=2), duration_minutes=60)
    attack.workstations, attack.visitors = normal.workstations, normal.visitors
    truth = attack.generate(normal=600, scenarios=["port_scan"])
    for source, lines in attack.by_source().items():
        ingestion.ingest_batch(lines, source)
    scanner = truth[0]["source_ip"]

    summary = client.post("/api/ml/detect", params={"hours": 1.2}).json()
    assert summary["ran"] and summary["anomalies"] >= 1
    body = client.get("/api/ml/anomalies").json()
    assert body["total"] == summary["anomalies"]
    top = next(a for a in body["anomalies"] if a["entity"] == scanner)
    assert top["anomaly_score"] > 0.9 and top["detection_type"] == "ml-detected" and top["explanation"]
    assert (top["mitre_technique"], top["mitre_tactic"]) == ("T1595", "Reconnaissance")
    seen = {t["id"]: t["ml_alerts"] for tactic in client.get("/api/mitre").json()["tactics"] for t in tactic["techniques"]}
    assert seen["T1595"] >= 1
    assert client.get("/api/stats").json()["ml_alerts"] == summary["anomalies"]
    volume = client.get("/api/alert-volume", params={"time_range": "24h"}).json()["buckets"]
    assert sum(b["ml"] for b in volume) == summary["anomalies"]

    assert client.patch(f"/api/ml/anomalies/{top['id']}/resolve").json() == {"alert_id": top["id"], "resolved": True}
    assert client.get("/api/ml/anomalies", params={"resolved": False}).json()["total"] == summary["anomalies"] - 1
    assert client.post("/api/ml/anomalies/nope/resolve").status_code == 404

    entities = client.get("/api/ml/entities", params={"entity_type": "ip", "limit": 100}).json()["entities"]
    assert len(client.get("/api/ml/entities", params={"limit": 3}).json()["entities"]) == 3
    ranked = {e["entity"]: e["risk_score"] for e in entities}
    assert scanner in ranked and ranked[scanner] > 40
    profile = client.get(f"/api/entities/ip/{scanner}").json()
    assert profile["risk"]["risk_score"] == ranked[scanner] and profile["total_logs"] > 100
    assert all(type(c["weight"]) is float for c in top["explanation"])
    assert len(profile["recent_logs"]) == 25 and profile["anomalies"]
    assert client.get("/api/entities/ip/8.8.8.8").status_code == 404
    assert client.get("/api/entities/host/x").status_code == 404
    visitor = client.get(f"/api/entities/ip/{normal.visitors[0]}")
    assert visitor.status_code == 200 and visitor.json()["total_logs"] > 0

    assert client.post("/api/ml/train").json()["version"] == "v2"
    assert client.post("/api/ml/models/v1/activate").json()["active"] == "v1"
    assert client.post("/api/ml/models/v7/activate").status_code == 404


def test_mitre_matrix_story_and_report(seeded):
    client, _ = seeded
    ingestion.ingest_batch(ids_lines(), "ids")
    alerts = client.get("/api/alerts").json()["alerts"]
    tags = {a["event_type"]: (a["mitre_technique"], a["mitre_tactic"]) for a in alerts if a["event_type"] != "ids_alert"}
    assert tags == {"login_failed": ("T1110", "Credential Access"), "account_created": ("T1136", "Persistence")}
    sqli = next(a for a in alerts if "SQL" in a["description"])
    assert (sqli["mitre_technique"], sqli["mitre_name"]) == ("T1190", "Exploit Public-Facing Application")
    assert next(a for a in alerts if "PING" in a["description"])["mitre_technique"] is None

    body = client.get("/api/mitre").json()
    assert len(body["tactics"]) == 14 and body["techniques_covered"] == 11 and body["techniques_seen"] == 3
    counts = {t["id"]: t["rule_alerts"] for tactic in body["tactics"] for t in tactic["techniques"]}
    # 2 failed logins + the "SSH Scan" signature, 1 created account, 1 SQL injection signature
    assert (counts["T1110"], counts["T1136"], counts["T1190"], counts["T1041"]) == (3, 1, 1, 0)
    assert client.get("/api/mitre", params={"time_range": "1h"}).json()["techniques_seen"] == 3

    story = client.get("/api/entities/ip/203.0.113.7/story").json()
    assert [s["technique"] for s in story["stages"]] == ["T1110", "T1190", "T1110"]
    assert story["tactics"] == ["Initial Access", "Credential Access"] and story["alerts"] == 4
    assert story["stages"][0]["count"] == 2 and story["first_seen"] < story["last_seen"]
    assert client.get("/api/entities/ip/8.8.8.8/story").json()["stages"] == []
    assert client.get("/api/entities/host/x/story").status_code == 404

    response = client.get("/api/entities/ip/203.0.113.7/report.pdf")
    assert response.status_code == 200 and response.headers["content-type"] == "application/pdf"
    assert response.content[:5] == b"%PDF-"
    assert response.headers["content-disposition"] == 'attachment; filename="argus-report-203.0.113.7.pdf"'
    assert client.get("/api/entities/ip/8.8.8.8/report.pdf").status_code == 404
    user = client.get("/api/entities/user/root/report.pdf")
    assert user.status_code == 200 and user.content[:5] == b"%PDF-"
