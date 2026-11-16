"""ML / UEBA engine: features, Isolation Forest + novelty, baselines, DBSCAN, risk, versioning."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "simulation"))
import mlEvaluation  # noqa: E402
from logGenerator import LogGenerator  # noqa: E402

from backend import ingestion, ml  # noqa: E402

T0 = datetime(2026, 6, 14, 15, 0, tzinfo=timezone.utc)


def log(minute, event_type, ip="10.0.0.5", user=None, second=0, **fields):
    return {"timestamp": T0 + timedelta(minutes=minute, seconds=second), "event_type": event_type,
            "source_ip": ip, "username": user, **fields}


# -- features ------------------------------------------------------------------

def test_window_start():
    assert ml.window_start(datetime(2026, 6, 14, 15, 37, 59, 5, tzinfo=timezone.utc)) == T0 + timedelta(minutes=30)
    assert ml.window_start(datetime(2026, 6, 14, 15, 37), minutes=60) == T0  # naive = UTC


def test_extract_features_groups_by_entity_and_window():
    logs = [
        log(1, "login_failed", user="root", host="bastion"),
        log(2, "login_failed", user="admin", host="bastion"),
        log(3, "login_success", user="root", host="bastion"),
        log(4, "firewall_drop", dest_ip="10.0.1.1", dest_port=22),
        log(5, "firewall_drop", dest_ip="10.0.1.1", dest_port=23),
        log(6, "http_request", extra={"status": 500}),
        log(7, "http_request", extra={"status": 200}),
        log(8, "dns_query", extra={"query": "a" * 30}),
        log(9, "dns_query", extra={"query": "b" * 10}),
        log(9, "network_connection", dest_ip="1.1.1.1", extra={"orig_bytes": 1000}),
        log(9, "account_created", user="evil"),
        log(12, "login_failed", user="root"),                 # next window
        log(1, "login_success", ip="10.0.0.9", user="root"),  # other IP
        log(1, "syslog_message", ip=None),                    # no entity
    ]
    rows = ml.extract_features(logs, "ip")
    assert [(r["entity"], r["window_start"]) for r in rows] == [
        ("10.0.0.5", T0), ("10.0.0.9", T0), ("10.0.0.5", T0 + timedelta(minutes=10))]
    f = rows[0]["features"]
    assert set(f) == set(ml.FEATURES)
    assert (f["events"], f["login_failed"], f["login_success"], f["fail_ratio"]) == (11, 2, 1, 0.6667)
    assert (f["distinct_users"], f["distinct_hosts"], f["distinct_dest_ips"], f["distinct_dest_ports"]) == (3, 1, 2, 2)
    assert (f["firewall_drops"], f["http_requests"], f["http_error_ratio"]) == (2, 2, 0.5)
    assert (f["dns_queries"], f["avg_dns_length"], f["bytes_out"], f["privileged_events"]) == (2, 20, 1000, 1)

    users = ml.extract_features(logs, "user")
    root = [r for r in users if r["entity"] == "root" and r["window_start"] == T0][0]["features"]
    assert root["distinct_source_ips"] == 2 and root["events"] == 3
    assert ml.extract_features([], "ip") == []


def test_connection_regularity_detects_beacons_only():
    beacon = [log(0, "network_connection", dest_ip="203.0.113.9", second=60 * i) for i in range(9)]
    assert ml.extract_features(beacon, "ip")[0]["features"]["conn_regularity"] > 0.95
    irregular = [log(0, "network_connection", dest_ip="203.0.113.9", second=s) for s in (0, 7, 200, 210, 480, 590)]
    assert ml.extract_features(irregular, "ip")[0]["features"]["conn_regularity"] < 0.4
    few = [log(0, "network_connection", dest_ip="203.0.113.9", second=60 * i) for i in range(3)]
    assert ml.extract_features(few, "ip")[0]["features"]["conn_regularity"] == 0
    burst = [log(0, "network_connection", dest_ip="203.0.113.9", second=i) for i in range(9)]
    assert ml.extract_features(burst, "ip")[0]["features"]["conn_regularity"] == 0


def test_to_matrix_log_scales_counts_not_ratios():
    row = {"features": dict.fromkeys(ml.FEATURES, 0) | {"events": 99, "fail_ratio": 0.5}}
    matrix = ml.to_matrix([row])
    assert matrix.shape == (1, len(ml.FEATURES))
    assert matrix[0, ml.FEATURES.index("events")] == pytest.approx(4.60517, abs=1e-4)
    assert matrix[0, ml.FEATURES.index("fail_ratio")] == 0.5


# -- model ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def trained():
    """Model trained on 3 hours of normal traffic, and an attack hour to score."""
    start = datetime.now(timezone.utc) - timedelta(hours=4)
    normal = LogGenerator(seed=11, start=start, duration_minutes=180)
    normal.generate(normal=2400, scenarios=[])
    rows = {t: ml.extract_features(mlEvaluation.to_logs(normal), t) for t in ml.ENTITY_TYPES}
    bundle = ml.train(rows)
    bundle["version"] = "test"
    attack = LogGenerator(seed=12, start=start + timedelta(hours=3), duration_minutes=60)
    attack.workstations, attack.visitors = normal.workstations, normal.visitors
    truth = {t["scenario"]: t for t in attack.generate(normal=800)}
    return bundle, rows, mlEvaluation.to_logs(attack), truth


def test_train_requires_enough_data():
    with pytest.raises(ValueError):
        ml.train({"ip": ml.extract_features([log(1, "login_failed")], "ip")})


def test_bundle_contents_and_training_flag_rate(trained):
    bundle, rows, _, _ = trained
    assert set(bundle["models"]) == {"ip", "user"} and bundle["features"] == ml.FEATURES
    assert bundle["samples"]["ip"] == len(rows["ip"]) and bundle["params"]["contamination"] == 0.01
    scored = ml.score(bundle, [dict(r) for r in rows["ip"]])
    assert all(0 <= r["anomaly_score"] <= 1 for r in scored)
    assert all(r["novelty"] == 0 for r in scored)  # nothing lies outside its own training range
    assert sum(r["is_anomaly"] for r in scored) / len(scored) < 0.03


def test_attacks_score_higher_than_normal_and_are_explained(trained):
    bundle, _, logs, truth = trained
    result = ml.analyse(bundle, logs)
    by_entity = {}
    for row in result["rows"]:
        if row["entity_type"] == "ip":
            by_entity.setdefault(row["entity"], []).append(row)
    expected = {"port_scan": "distinct_dest_ports", "sql_injection": "http_requests",
                "brute_force": "login_failed", "dns_tunneling": "dns_queries"}
    for scenario, feature in expected.items():
        ip = truth[scenario].get("source_ip")
        worst = max(by_entity[ip], key=lambda r: r["anomaly_score"])
        assert worst["is_anomaly"] and worst["anomaly_score"] > 0.9, scenario
        assert worst["novelty"] >= ml.NOVELTY_THRESHOLD
        assert feature in [c["feature"] for c in worst["explanation"]], (scenario, worst["explanation"])
        top = worst["explanation"][0]
        assert top["value"] > top["typical"] and top["weight"] > 0 and top["label"]
    exfil = max(by_entity[truth["data_exfiltration"]["source_ip"]], key=lambda r: r["features"]["bytes_out"])
    assert exfil["is_anomaly"] and "bytes_out" in [c["feature"] for c in exfil["explanation"]]

    attackers = set(mlEvaluation.attack_entities(truth.values())["brute_force"]["ip"])
    for item in mlEvaluation.attack_entities(truth.values()).values():
        attackers |= item["ip"]
    benign = [r for r in result["rows"] if r["entity_type"] == "ip" and r["entity"] not in attackers]
    assert sum(r["is_anomaly"] for r in benign) / len(benign) < 0.05
    assert all(not r["explanation"] for r in benign if not r["is_anomaly"])


def test_novelty_makes_up_for_isolation_forest_range_limit(trained):
    bundle, _, _, _ = trained
    extreme = {"entity_type": "ip", "entity": "x", "window_start": T0,
               "features": dict.fromkeys(ml.FEATURES, 0) | {"events": 5000, "distinct_dest_ports": 5000, "firewall_drops": 5000}}
    (row,) = ml.score(bundle, [extreme])
    assert row["forest_score"] < 0.8 < row["anomaly_score"] and row["is_anomaly"]
    quiet = {"entity_type": "ip", "entity": "y", "window_start": T0,
             "features": dict.fromkeys(ml.FEATURES, 0) | {"events": 1, "http_requests": 1, "distinct_source_ips": 1}}
    (row,) = ml.score(bundle, [quiet])
    assert row["novelty"] == 0 and not row["is_anomaly"] and row["anomaly_score"] == row["forest_score"]
    unknown = {"entity_type": "host", "entity": "z", "window_start": T0, "features": {}}
    assert "anomaly_score" not in ml.score(bundle, [unknown])[0]


def test_coordinated_attack_is_clustered_and_ranked(trained):
    bundle, _, logs, truth = trained
    result = ml.analyse(bundle, logs)
    ips = set(truth["distributed_brute_force"]["source_ips"])
    clusters = [c for c in result["clusters"] if ips & set(c["entities"])]
    # an attack that straddles a window boundary may be found as two clusters
    found = set().union(*(c["entities"] for c in clusters)) if clusters else set()
    assert clusters and len(ips & found) >= 4
    assert clusters[0]["first_seen"] < clusters[0]["last_seen"]
    clustered = [r for r in result["rows"] if r.get("cluster") == clusters[0]["id"]]
    assert {r["entity"] for r in clustered} == set(clusters[0]["entities"])

    risk = result["risk"]
    assert [r["risk_score"] for r in risk] == sorted((r["risk_score"] for r in risk), reverse=True)
    attackers = set()
    for item in mlEvaluation.attack_entities(truth.values()).values():
        attackers |= item["ip"] | item["user"]
    assert sum(r["entity"] in attackers for r in risk[:10]) >= 7
    member = next(r for r in risk if r["entity"] in ips)
    assert member["components"]["coordinated"] == 1.0 and member["top_reasons"]


def test_cluster_needs_several_distinct_entities(trained):
    bundle, _, _, _ = trained
    same = [{"entity_type": "ip", "entity": "1.1.1.1", "window_start": T0 + timedelta(minutes=10 * i),
             "is_anomaly": True, "features": dict.fromkeys(ml.FEATURES, 0) | {"events": 50, "login_failed": 50}}
            for i in range(5)]
    assert ml.cluster_anomalies(bundle, same) == [] and all(r["cluster"] is None for r in same)
    assert ml.cluster_anomalies(bundle, same[:2]) == []


# -- baselines -----------------------------------------------------------------

def test_baseline_running_statistics_and_deviation():
    baseline = ml.Baseline()
    for value in (2, 4, 6):
        baseline.update({"events": value})
    assert baseline.n == 3 and baseline.mean["events"] == 4 and baseline.std("events") == 2
    z, feature = baseline.deviation({"events": 24})
    assert (z, feature) == (10.0, "events")
    assert baseline.deviation({"events": 3}) == (0.0, None)   # below its mean: not a risk
    restored = ml.Baseline(baseline.to_dict())
    assert restored.deviation({"events": 24}) == (10.0, "events")
    assert ml.Baseline().deviation({"events": 999}) == (0.0, None)  # no history yet


def test_apply_baselines_uses_only_earlier_windows():
    def row(i, events, entity="alice"):
        return {"entity_type": "user", "entity": entity, "window_start": T0 + timedelta(minutes=10 * i),
                "features": dict.fromkeys(ml.FEATURES, 0) | {"events": events}}
    rows = [row(3, 60), row(0, 5), row(1, 5), row(2, 5), row(0, 500, "bob")]
    baselines = ml.apply_baselines(rows)
    assert [r["baseline_z"] for r in rows] == [110.0, 0.0, 0.0, 0.0, 0.0]
    assert rows[0]["baseline_feature"] == "events" and baselines["user:alice"].n == 4
    later = [row(4, 5)]
    ml.apply_baselines(later, baselines)   # stored baselines keep learning
    assert later[0]["baseline_z"] == 0.0 and baselines["user:alice"].n == 5


def test_risk_score_components():
    base = {"entity_type": "ip", "window_start": T0, "features": {"events": 3}, "explanation": []}
    rows = [
        dict(base, entity="quiet", is_anomaly=False, anomaly_score=0.4, baseline_z=0, cluster=None),
        dict(base, entity="loud", is_anomaly=True, anomaly_score=1.0, baseline_z=25, cluster="ip-1",
             explanation=[{"label": "failed logins"}]),
        dict(base, entity="ruled", is_anomaly=False, anomaly_score=0.4, baseline_z=0, cluster=None),
    ]
    risk = {r["entity"]: r for r in ml.risk_scores(rows, {"ip:loud": {"critical": 5}, "ip:ruled": {"high": 5}})}
    assert risk["quiet"]["risk_score"] == 0 and risk["loud"]["risk_score"] == 100
    assert risk["loud"]["top_reasons"] == ["failed logins"] and risk["loud"]["id"] == "ip:loud"
    assert risk["ruled"]["components"] == {"ml": 0.0, "baseline": 0.0, "rules": 0.5, "coordinated": 0.0}
    assert risk["ruled"]["risk_score"] == 12.5
    assert abs(sum(ml.RISK_WEIGHTS.values()) - 1) < 1e-9


# -- versioning ------------------------------------------------------------------

def test_model_versioning(trained, tmp_path, monkeypatch):
    bundle, _, logs, _ = trained
    monkeypatch.setattr(ml, "MODEL_DIR", tmp_path / "models")
    assert ml.load_model() is None and ml.list_models() == {"active": None, "versions": []}
    first = ml.save_model(dict(bundle), note="first")
    second = ml.save_model(dict(bundle), note="second")
    assert (first["version"], second["version"]) == ("v1", "v2")
    registry = ml.list_models()
    assert registry["active"] == "v2" and [v["note"] for v in registry["versions"]] == ["first", "second"]
    assert registry["versions"][0]["samples"] == bundle["samples"]
    assert ml.load_model()["version"] == "v2" and ml.load_model("v1")["version"] == "v1"
    assert ml.set_active_model("v1") and ml.load_model()["version"] == "v1"
    assert not ml.set_active_model("v9") and ml.load_model("v9") is None
    # a reloaded model scores exactly like the original
    rows = ml.extract_features(logs, "ip")[:50]
    before = [r["anomaly_score"] for r in ml.score(bundle, [dict(r) for r in rows])]
    after = [r["anomaly_score"] for r in ml.score(ml.load_model("v1"), [dict(r) for r in rows])]
    assert before == after


# -- database pipeline -----------------------------------------------------------

def test_train_and_detect_from_database(db, tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "MODEL_DIR", tmp_path / "models")
    assert ml.detect()["reason"] == "no trained model"
    with pytest.raises(ValueError):
        ml.train_from_db()

    start = datetime.now(timezone.utc) - timedelta(hours=3, minutes=5)
    normal = LogGenerator(seed=21, start=start, duration_minutes=120)
    normal.generate(normal=1600, scenarios=[])
    for source, lines in normal.by_source().items():
        ingestion.ingest_batch(lines, source)
    entry = ml.train_from_db(hours=24)
    assert entry["version"] == "v1" and entry["samples"]["ip"] > 100

    attack = LogGenerator(seed=22, start=start + timedelta(hours=2), duration_minutes=60)
    attack.workstations, attack.visitors = normal.workstations, normal.visitors
    truth = {t["scenario"]: t for t in attack.generate(normal=600, scenarios=["port_scan", "brute_force"])}
    for source, lines in attack.by_source().items():
        ingestion.ingest_batch(lines, source)

    summary = ml.detect(hours=1.2)
    assert summary["ran"] and summary["model_version"] == "v1" and summary["anomalies"] >= 2
    scanner = truth["port_scan"]["source_ip"]
    alert = db.alerts.find_one({"entity": scanner})
    # shared Alert model (API contract)
    contract = {"timestamp", "source_ip", "rule_name", "description", "severity", "detection_type",
                "anomaly_score", "mitre_technique", "mitre_tactic", "resolved"}
    assert contract <= set(alert) and alert["detection_type"] == "ml-detected"
    assert alert["source_ip"] == scanner and alert["severity"] in ("HIGH", "CRITICAL")
    assert "distinct destination ports" in alert["description"] and alert["resolved"] is False

    top = ml.get_anomalies(limit=5)
    assert top[0]["anomaly_score"] >= top[-1]["anomaly_score"] and "id" in top[0]
    assert ml.count_anomalies() == summary["anomalies"] == db.alerts.count_documents({})
    # the exact order depends on where the 10-minute window boundaries fall
    assert len(ml.get_entity_risk(limit=3, entity_type="ip")) == 3
    ranked = {e["entity"]: e for e in ml.get_entity_risk(limit=200, entity_type="ip")}
    brute = truth["brute_force"]["source_ip"]
    assert ranked[scanner]["risk_score"] > 35 and ranked[brute]["risk_score"] > 35
    assert ranked[brute]["components"]["rules"] > 0  # rule-style alerts on the same entity count too
    assert list(ranked)[:10].count(scanner) + list(ranked)[:10].count(brute) == 2
    assert ml.get_entity_risk(min_score=101) == []

    # scoring again must not duplicate alerts or undo an analyst's decision
    assert ml.set_anomaly_resolved(alert["_id"]) and not ml.set_anomaly_resolved("missing")
    again = ml.detect(hours=1.2)
    assert db.alerts.count_documents({}) == again["anomalies"] == summary["anomalies"]
    assert db.alerts.find_one({"_id": alert["_id"]})["resolved"] is True
    assert ml.count_anomalies(resolved=False) == summary["anomalies"] - 1

    profile = ml.get_entity_profile("ip", scanner)
    assert profile["risk"]["risk_score"] > 40 and profile["anomalies"][0]["entity"] == scanner
    assert profile["baseline"]["windows"] >= 1
    assert ml.get_entity_profile("ip", "8.8.8.8") is None


def test_ml_without_database(no_db, tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "MODEL_DIR", tmp_path)
    assert ml.fetch_logs() == [] and ml.get_anomalies() == [] and ml.count_anomalies() == 0
    assert ml.get_entity_risk() == [] and ml.get_entity_profile("ip", "1.1.1.1") is None
    assert ml.set_anomaly_resolved("x") is False
