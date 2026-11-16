"""
ML and Behavioral Analytics (UEBA)

Pipeline, per entity (source IP or user) and time window:
    logs -> feature extraction -> Isolation Forest anomaly score
         -> per-entity behavioral baseline (deviation from the entity's own past)
         -> DBSCAN clustering of anomalies (coordinated activity)
         -> composite risk score per entity
         -> 'ml-detected' alerts in the shared Alert model

Models are versioned on disk (models/registry.json + one joblib file each).
See docs/ml-approach.md for the reasoning and the measured false-positive rate.

    python backend/ml.py train --hours 24
    python backend/ml.py detect --hours 1
"""

import argparse
import hashlib
import json
import math
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from . import dataBase as database, mitre, utils
    from .models import Alert, DetectionType, Severity, document_to_api
except ImportError:  # running with backend/ on sys.path (python backend/main.py)
    import dataBase as database
    import mitre
    import utils
    from models import Alert, DetectionType, Severity, document_to_api

MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", Path(__file__).resolve().parent.parent / "models"))
ANOMALIES_COLLECTION = database.ALERTS_COLLECTION
RISK_COLLECTION = "entity_risk"
BASELINES_COLLECTION = "baselines"

WINDOW_MINUTES = 10
ENTITY_TYPES = ("ip", "user")
_ENTITY_FIELD = {"ip": "source_ip", "user": "username"}

# Counts are log-scaled before modelling; ratios are already in [0, 1]
COUNT_FEATURES = [
    "events", "login_failed", "login_success", "distinct_users", "distinct_source_ips",
    "distinct_hosts", "distinct_dest_ips", "distinct_dest_ports", "firewall_drops",
    "ids_alerts", "http_requests", "dns_queries", "avg_dns_length", "bytes_out",
    "privileged_events", "sudo_failed",
]
RATIO_FEATURES = ["fail_ratio", "http_error_ratio", "conn_regularity"]
FEATURES = COUNT_FEATURES + RATIO_FEATURES

FEATURE_LABELS = {
    "events": "events", "login_failed": "failed logins", "login_success": "successful logins",
    "distinct_users": "distinct users tried", "distinct_source_ips": "distinct source IPs",
    "distinct_hosts": "distinct hosts reached", "distinct_dest_ips": "distinct destination IPs",
    "distinct_dest_ports": "distinct destination ports", "firewall_drops": "firewall drops",
    "ids_alerts": "IDS alerts", "http_requests": "HTTP requests", "dns_queries": "DNS queries",
    "avg_dns_length": "average DNS query length", "bytes_out": "bytes sent out",
    "privileged_events": "privilege / account events", "sudo_failed": "failed sudo attempts",
    "fail_ratio": "login failure ratio", "http_error_ratio": "HTTP error ratio",
    "conn_regularity": "connection regularity (beaconing)",
}

_PRIVILEGED = {"account_created", "privilege_assigned", "explicit_credential_logon", "account_locked"}


# ---------------------------------------------------------------------------
# Feature extraction (pure functions, no database)
# ---------------------------------------------------------------------------

def window_start(timestamp: datetime, minutes: int = WINDOW_MINUTES) -> datetime:
    timestamp = utils.to_utc(timestamp)
    return timestamp.replace(minute=timestamp.minute - timestamp.minute % minutes,
                             second=0, microsecond=0)


def _regularity(times_by_dest: Dict[str, List[datetime]]) -> float:
    """
    1.0 when connections to one destination are evenly spaced (beaconing),
    0.0 when they are irregular or there are fewer than 4 of them.
    """
    best = 0.0
    for times in times_by_dest.values():
        if len(times) < 4:
            continue
        times = sorted(times)
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean = sum(gaps) / len(gaps)
        if mean < 5:  # bursts are not beacons
            continue
        cv = float(np.std(gaps)) / mean
        best = max(best, 1.0 - min(cv, 1.0))
    return round(best, 4)


def _summarise(logs: List[Dict[str, Any]]) -> Dict[str, float]:
    count = defaultdict(int)
    users, sources, hosts, dest_ips, dest_ports = set(), set(), set(), set(), set()
    dns_lengths: List[int] = []
    http_errors = 0
    bytes_out = 0
    conn_times: Dict[str, List[datetime]] = defaultdict(list)

    for log in logs:
        event = log.get("event_type")
        extra = log.get("extra") or {}
        count[event] += 1
        if log.get("username"):
            users.add(log["username"])
        if log.get("source_ip"):
            sources.add(log["source_ip"])
        if log.get("host") and event in ("login_success", "login_failed", "explicit_credential_logon"):
            hosts.add(log["host"])
        if extra.get("target_server"):
            hosts.add(extra["target_server"])
        if log.get("dest_ip"):
            dest_ips.add(log["dest_ip"])
        if log.get("dest_port") is not None:
            dest_ports.add(log["dest_port"])
        if event == "dns_query":
            dns_lengths.append(len(str(extra.get("query") or "")))
        elif event == "http_request":
            if (extra.get("status") or 0) >= 400:
                http_errors += 1
        elif event == "network_connection":
            bytes_out += extra.get("orig_bytes") or 0
            if log.get("dest_ip"):
                conn_times[log["dest_ip"]].append(utils.to_utc(log["timestamp"]))

    logins = count["login_failed"] + count["login_success"]
    return {
        "events": len(logs),
        "login_failed": count["login_failed"],
        "login_success": count["login_success"],
        "distinct_users": len(users),
        "distinct_source_ips": len(sources),
        "distinct_hosts": len(hosts),
        "distinct_dest_ips": len(dest_ips),
        "distinct_dest_ports": len(dest_ports),
        "firewall_drops": count["firewall_drop"],
        "ids_alerts": count["ids_alert"],
        "http_requests": count["http_request"],
        "dns_queries": count["dns_query"],
        "avg_dns_length": round(sum(dns_lengths) / len(dns_lengths), 2) if dns_lengths else 0,
        "bytes_out": bytes_out,
        "privileged_events": sum(count[e] for e in _PRIVILEGED),
        "sudo_failed": count["sudo_failed"],
        "fail_ratio": round(count["login_failed"] / logins, 4) if logins else 0.0,
        "http_error_ratio": round(http_errors / count["http_request"], 4) if count["http_request"] else 0.0,
        "conn_regularity": _regularity(conn_times),
    }


def extract_features(logs: Iterable[Dict[str, Any]], entity_type: str = "ip",
                     window_minutes: int = WINDOW_MINUTES) -> List[Dict[str, Any]]:
    """
    Group logs by (entity, time window) and compute one feature row per group:
    {"entity_type", "entity", "window_start", "features": {name: value}}
    """
    field = _ENTITY_FIELD[entity_type]
    groups: Dict[Tuple[str, datetime], List[Dict[str, Any]]] = defaultdict(list)
    for log in logs:
        entity, timestamp = log.get(field), log.get("timestamp")
        if entity and isinstance(timestamp, datetime):
            groups[(entity, window_start(timestamp, window_minutes))].append(log)
    rows = [{"entity_type": entity_type, "entity": entity, "window_start": start,
             "features": _summarise(group)}
            for (entity, start), group in groups.items()]
    rows.sort(key=lambda row: (row["window_start"], row["entity"]))
    return rows


def to_matrix(rows: List[Dict[str, Any]]) -> np.ndarray:
    """Feature rows -> model input (log-scaled counts, raw ratios)."""
    matrix = np.zeros((len(rows), len(FEATURES)))
    for i, row in enumerate(rows):
        features = row["features"]
        for j, name in enumerate(FEATURES):
            value = float(features.get(name, 0) or 0)
            matrix[i, j] = math.log1p(max(value, 0)) if name in COUNT_FEATURES else value
    return matrix


# ---------------------------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------------------------

def train(rows_by_type: Dict[str, List[Dict[str, Any]]], contamination: float = 0.01,
          n_estimators: int = 200, seed: int = 42) -> Dict[str, Any]:
    """
    Fit one Isolation Forest per entity type. Returns a model bundle (not yet saved).
    'contamination' is the share of training rows assumed to be anomalous.
    """
    bundle: Dict[str, Any] = {
        "features": list(FEATURES), "window_minutes": WINDOW_MINUTES,
        "params": {"contamination": contamination, "n_estimators": n_estimators, "seed": seed},
        "trained_at": utils.utcnow().isoformat(), "models": {}, "samples": {},
    }
    for entity_type, rows in rows_by_type.items():
        if len(rows) < 20:
            continue  # too little data to learn what normal looks like
        matrix = to_matrix(rows)
        forest = IsolationForest(n_estimators=n_estimators, contamination=contamination,
                                 random_state=seed).fit(matrix)
        raw = np.array([[row["features"].get(name, 0) or 0 for name in FEATURES] for row in rows],
                       dtype=float)
        bundle["models"][entity_type] = {
            "forest": forest,
            "scaler": StandardScaler().fit(matrix),
            # typical raw values, used to explain why a row is unusual
            "median": np.median(raw, axis=0),
            "p95": np.percentile(raw, 95, axis=0),
            "max": raw.max(axis=0),
        }
        bundle["samples"][entity_type] = len(rows)
    if not bundle["models"]:
        raise ValueError("Not enough data to train (need at least 20 entity windows)")
    return bundle


def explain(model: Dict[str, Any], row: Dict[str, Any], top: int = 3) -> List[Dict[str, Any]]:
    """
    Feature-importance explanation: the features of this row that are furthest
    above what 95% of the training rows looked like.
    """
    scale = model["scaler"].scale_

    def above(reference: np.ndarray) -> List[Dict[str, Any]]:
        found = []
        for j, name in enumerate(FEATURES):
            value = float(row["features"].get(name, 0) or 0)
            limit = float(reference[j])
            if value <= limit:
                continue
            if name in COUNT_FEATURES:
                distance = (math.log1p(value) - math.log1p(limit)) / max(float(scale[j]), 0.1)
            else:
                distance = (value - limit) / max(float(scale[j]), 0.1)
            found.append({"feature": name, "label": FEATURE_LABELS[name], "value": value,
                          "typical": float(model["median"][j]), "weight": round(float(distance), 2)})
        return found

    # an unusual *combination* may have no single feature above the 95th percentile;
    # fall back to what is above the median
    contributions = above(model["p95"]) or above(model["median"])
    contributions.sort(key=lambda c: c["weight"], reverse=True)
    return contributions[:top]


NOVELTY_THRESHOLD = 2.0  # scaled units above the largest value seen in training


def novelty(model: Dict[str, Any], row: Dict[str, Any]) -> float:
    """
    How far the row lies beyond the largest value seen in training, on its most
    extreme feature (in units of that feature's spread). 0 when inside the range.

    An Isolation Forest cannot do this itself: a tree only splits inside the
    range it was trained on, so a value 50 times larger than anything seen
    before scores the same as the largest training value.
    """
    scale = model["scaler"].scale_
    worst = 0.0
    for j, name in enumerate(FEATURES):
        value = float(row["features"].get(name, 0) or 0)
        highest = float(model["max"][j])
        if value <= highest:
            continue
        if name in COUNT_FEATURES:
            distance = (math.log1p(value) - math.log1p(highest)) / max(scale[j], 0.25)
        else:
            distance = (value - highest) / max(scale[j], 0.1)
        worst = max(worst, distance)
    return round(float(worst), 3)


def score(bundle: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add 'anomaly_score' (0-1, higher is more anomalous), 'is_anomaly' and
    'explanation' to each row. The score is the Isolation Forest score, pushed
    towards 1 by how far the row lies outside the training range (novelty).
    Rows of entity types the bundle has no model for are returned unscored.
    """
    by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_type[row["entity_type"]].append(row)
    for entity_type, group in by_type.items():
        model = bundle["models"].get(entity_type)
        if model is None:
            continue
        matrix = to_matrix(group)
        scores = np.clip(-model["forest"].score_samples(matrix), 0, 1)
        flagged = model["forest"].predict(matrix) == -1
        for row, forest_score, forest_flag in zip(group, scores, flagged):
            distance = novelty(model, row)
            combined = forest_score + (1 - forest_score) * (1 - math.exp(-distance / 4))
            row["forest_score"] = round(float(forest_score), 4)
            row["novelty"] = distance
            row["anomaly_score"] = round(float(combined), 4)
            row["is_anomaly"] = bool(forest_flag) or distance >= NOVELTY_THRESHOLD
            row["explanation"] = explain(model, row) if row["is_anomaly"] else []
    return rows


# ---------------------------------------------------------------------------
# Behavioral baselines (UEBA): how far is an entity from its own past?
# ---------------------------------------------------------------------------

class Baseline:
    """Running mean / variance per feature for one entity (Welford's algorithm)."""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        data = data or {}
        self.n: int = data.get("n", 0)
        self.mean: Dict[str, float] = dict(data.get("mean", {}))
        self.m2: Dict[str, float] = dict(data.get("m2", {}))

    def update(self, features: Dict[str, float]) -> None:
        self.n += 1
        for name in FEATURES:
            value = float(features.get(name, 0) or 0)
            mean = self.mean.get(name, 0.0)
            delta = value - mean
            mean += delta / self.n
            self.mean[name] = mean
            self.m2[name] = self.m2.get(name, 0.0) + delta * (value - mean)

    def std(self, name: str) -> float:
        return math.sqrt(self.m2.get(name, 0.0) / (self.n - 1)) if self.n > 1 else 0.0

    def deviation(self, features: Dict[str, float], min_windows: int = 3) -> Tuple[float, Optional[str]]:
        """
        Largest z-score of this window against the entity's history, with the
        feature responsible. (0, None) until enough history exists.
        """
        if self.n < min_windows:
            return 0.0, None
        worst, worst_name = 0.0, None
        for name in FEATURES:
            value = float(features.get(name, 0) or 0)
            mean = self.mean.get(name, 0.0)
            # floor the spread so a perfectly constant history does not divide by zero
            spread = max(self.std(name), 0.1 * abs(mean), 0.5 if name in COUNT_FEATURES else 0.05)
            z = (value - mean) / spread
            if z > worst:
                worst, worst_name = z, name
        return round(worst, 2), worst_name

    def to_dict(self) -> Dict[str, Any]:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}


def apply_baselines(rows: List[Dict[str, Any]],
                    baselines: Optional[Dict[str, Baseline]] = None) -> Dict[str, Baseline]:
    """
    Walk the rows in time order: compare each window with the entity's baseline
    built from *earlier* windows only, then add the window to the baseline.
    Adds 'baseline_z' and 'baseline_feature' to each row. Returns the baselines.
    """
    baselines = baselines if baselines is not None else {}
    for row in sorted(rows, key=lambda r: r["window_start"]):
        key = f'{row["entity_type"]}:{row["entity"]}'
        baseline = baselines.setdefault(key, Baseline())
        row["baseline_z"], row["baseline_feature"] = baseline.deviation(row["features"])
        baseline.update(row["features"])
    return baselines


# ---------------------------------------------------------------------------
# DBSCAN: anomalies that look alike at the same time = coordinated activity
# ---------------------------------------------------------------------------

def cluster_anomalies(bundle: Dict[str, Any], rows: List[Dict[str, Any]],
                      eps: float = 1.2, min_samples: int = 3) -> List[Dict[str, Any]]:
    """
    Cluster the anomalous rows of each entity type on their scaled features.
    A cluster spanning several distinct entities is flagged as coordinated.
    Sets row['cluster'] (None = no cluster) and returns the cluster summaries.
    """
    clusters: List[Dict[str, Any]] = []
    for row in rows:
        row["cluster"] = None
    for entity_type, model in bundle["models"].items():
        group = [r for r in rows if r["entity_type"] == entity_type and r.get("is_anomaly")]
        if len(group) < min_samples:
            continue
        scaled = model["scaler"].transform(to_matrix(group))
        labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(scaled)
        for label in sorted(set(labels) - {-1}):
            members = [row for row, l in zip(group, labels) if l == label]
            entities = sorted({row["entity"] for row in members})
            if len(entities) < min_samples:
                continue  # the same entity over several windows is not coordination
            cluster_id = f"{entity_type}-{len(clusters) + 1}"
            for row in members:
                row["cluster"] = cluster_id
            clusters.append({"id": cluster_id, "entity_type": entity_type, "entities": entities,
                             "windows": len(members),
                             "first_seen": min(r["window_start"] for r in members),
                             "last_seen": max(r["window_start"] + timedelta(minutes=WINDOW_MINUTES)
                                              for r in members)})
    return clusters


# ---------------------------------------------------------------------------
# Composite risk score per entity
# ---------------------------------------------------------------------------

RISK_WEIGHTS = {"ml": 0.45, "baseline": 0.20, "rules": 0.25, "coordinated": 0.10}


def risk_scores(rows: List[Dict[str, Any]],
                rule_severity: Optional[Dict[str, Dict[str, int]]] = None) -> List[Dict[str, Any]]:
    """
    One 0-100 risk score per entity, combining:
      ml          highest anomaly score among its anomalous windows
      baseline    largest deviation from its own history (z of 10 or more = 1.0)
      rules       severity of rule-based alerts raised on it
      coordinated part of a DBSCAN cluster with other entities
    rule_severity maps 'type:entity' -> {'critical': n, 'high': n, 'medium': n}.
    """
    rule_severity = rule_severity or {}
    by_entity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_entity[f'{row["entity_type"]}:{row["entity"]}'].append(row)

    results = []
    for key, group in by_entity.items():
        anomalous = [r for r in group if r.get("is_anomaly")]
        ml = max((r["anomaly_score"] for r in anomalous), default=0.0)
        z = max((r.get("baseline_z") or 0.0 for r in group), default=0.0)
        severities = rule_severity.get(key, {})
        rules = min(1.0, (8 * severities.get("critical", 0) + 4 * severities.get("high", 0)
                          + severities.get("medium", 0)) / 40)
        coordinated = any(r.get("cluster") for r in group)
        components = {"ml": round(ml, 3), "baseline": round(min(z / 10, 1.0), 3),
                      "rules": round(rules, 3), "coordinated": 1.0 if coordinated else 0.0}
        risk = 100 * sum(RISK_WEIGHTS[name] * value for name, value in components.items())
        top = max(anomalous, key=lambda r: r["anomaly_score"], default=None)
        results.append({
            "id": key, "entity_type": group[0]["entity_type"], "entity": group[0]["entity"],
            "risk_score": round(risk, 1), "components": components,
            "anomalous_windows": len(anomalous), "windows": len(group),
            "events": int(sum(r["features"]["events"] for r in group)),
            "top_reasons": [c["label"] for c in top["explanation"]] if top else [],
            "last_seen": max(r["window_start"] for r in group),
        })
    results.sort(key=lambda r: r["risk_score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Model versioning
# ---------------------------------------------------------------------------

def _registry_path() -> Path:
    return MODEL_DIR / "registry.json"


def _read_registry() -> Dict[str, Any]:
    try:
        return json.loads(_registry_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"active": None, "versions": []}


def save_model(bundle: Dict[str, Any], note: str = "") -> Dict[str, Any]:
    """Store a bundle as a new version and make it the active one."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    registry = _read_registry()
    version = f"v{len(registry['versions']) + 1}"
    bundle["version"] = version
    joblib.dump(bundle, MODEL_DIR / f"model_{version}.joblib")
    entry = {"version": version, "trained_at": bundle["trained_at"], "params": bundle["params"],
             "samples": bundle["samples"], "features": bundle["features"],
             "entity_types": sorted(bundle["models"]), "note": note}
    registry["versions"].append(entry)
    registry["active"] = version
    _registry_path().write_text(json.dumps(registry, indent=2) + "\n")
    return entry


def list_models() -> Dict[str, Any]:
    return _read_registry()


def set_active_model(version: str) -> bool:
    registry = _read_registry()
    if version not in [entry["version"] for entry in registry["versions"]]:
        return False
    registry["active"] = version
    _registry_path().write_text(json.dumps(registry, indent=2) + "\n")
    return True


def load_model(version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load a model version (the active one by default). None when there is none."""
    version = version or _read_registry()["active"]
    path = MODEL_DIR / f"model_{version}.joblib"
    if not version or not path.exists():
        return None
    return joblib.load(path)


# ---------------------------------------------------------------------------
# Full analysis (pure) and the database pipeline around it
# ---------------------------------------------------------------------------

def analyse(bundle: Dict[str, Any], logs: List[Dict[str, Any]],
            baselines: Optional[Dict[str, Baseline]] = None,
            rule_severity: Optional[Dict[str, Dict[str, int]]] = None) -> Dict[str, Any]:
    """Run the whole pipeline on a list of logs. No database access."""
    rows: List[Dict[str, Any]] = []
    for entity_type in ENTITY_TYPES:
        rows += extract_features(logs, entity_type, bundle["window_minutes"])
    score(bundle, rows)
    rows = [row for row in rows if "anomaly_score" in row]
    baselines = apply_baselines(rows, baselines)
    clusters = cluster_anomalies(bundle, rows)
    return {"rows": rows, "anomalies": [row for row in rows if row["is_anomaly"]],
            "clusters": clusters, "risk": risk_scores(rows, rule_severity),
            "baselines": baselines}


def _severity(row: Dict[str, Any]) -> Severity:
    value = row["anomaly_score"]
    if value >= 0.9:
        return Severity.CRITICAL
    return Severity.HIGH if value >= 0.75 or row.get("cluster") else Severity.MEDIUM


def describe(row: Dict[str, Any]) -> str:
    kind = "IP" if row["entity_type"] == "ip" else "user"
    reasons = [f'{c["label"]} {c["value"]:g} (typical {c["typical"]:g})' for c in row["explanation"]]
    text = f'Unusual behaviour for {kind} {row["entity"]}'
    if reasons:
        text += ": " + ", ".join(reasons)
    if row.get("cluster"):
        text += f'. Part of coordinated cluster {row["cluster"]}'
    return text


def anomaly_to_alert(row: Dict[str, Any], model_version: str) -> Dict[str, Any]:
    """Shape an anomalous row as an 'ml-detected' alert document."""
    key = f'{row["entity_type"]}|{row["entity"]}|{row["window_start"].isoformat()}'
    alert = Alert(
        id=hashlib.sha1(key.encode()).hexdigest()[:32],
        timestamp=row["window_start"],
        source_ip=row["entity"] if row["entity_type"] == "ip" else None,
        rule_name="ml_behavioral_anomaly", description=describe(row), severity=_severity(row),
        detection_type=DetectionType.ML_DETECTED, anomaly_score=row["anomaly_score"],
        **{key: value for key, value in mitre.describe(
            mitre.technique_for_anomaly(row["explanation"], row["entity"])).items()
           if key != "mitre_name"},
    )
    doc = alert.to_document()
    doc.update(entity_type=row["entity_type"], entity=row["entity"], features=row["features"],
               explanation=row["explanation"], cluster=row.get("cluster"),
               baseline_z=row.get("baseline_z"), baseline_feature=row.get("baseline_feature"),
               model_version=model_version, window_minutes=WINDOW_MINUTES)
    return doc


_PROJECTION = {"timestamp": 1, "source_ip": 1, "username": 1, "event_type": 1, "host": 1,
               "dest_ip": 1, "dest_port": 1, "extra": 1}


def fetch_logs(since: Optional[datetime] = None, until: Optional[datetime] = None) -> List[Dict[str, Any]]:
    logs = database.get_collection(database.LOGS_COLLECTION)
    if logs is None:
        return []
    query: Dict[str, Any] = {}
    if since or until:
        query["timestamp"] = {}
        if since:
            query["timestamp"]["$gte"] = since
        if until:
            query["timestamp"]["$lt"] = until
    return list(logs.find(query, _PROJECTION))


def train_from_db(hours: float = 24, contamination: float = 0.01, note: str = "") -> Dict[str, Any]:
    """Train on the logs of the last 'hours' and save the model as a new version."""
    logs = fetch_logs(since=utils.utcnow() - timedelta(hours=hours))
    rows = {entity_type: extract_features(logs, entity_type) for entity_type in ENTITY_TYPES}
    bundle = train(rows, contamination=contamination)
    return save_model(bundle, note or f"trained on the last {hours:g}h ({len(logs)} logs)")


def _rule_severity(logs: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Severity counts of rule-style alerts per entity, from the same logs."""
    try:
        from .ingestion import alert_severity, HIGH_EVENT_TYPES, MEDIUM_EVENT_TYPES, IDS
    except ImportError:
        from ingestion import alert_severity, HIGH_EVENT_TYPES, MEDIUM_EVENT_TYPES, IDS
    alert_types = set(HIGH_EVENT_TYPES + MEDIUM_EVENT_TYPES + [IDS])
    counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for log in logs:
        if log.get("event_type") not in alert_types:
            continue
        severity = alert_severity(log)
        for entity_type, field in _ENTITY_FIELD.items():
            if log.get(field):
                counts[f"{entity_type}:{log[field]}"][severity] += 1
    return counts


def detect(hours: float = 1, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Score the logs of the last 'hours' with the active model and store the
    results: ml-detected alerts, entity risk scores and baselines.
    """
    summary = {"ran": False, "model_version": None, "logs": 0, "windows": 0, "anomalies": 0,
               "clusters": 0, "entities": 0}
    bundle = load_model(version)
    db = database.get_db()
    if bundle is None or db is None:
        summary["reason"] = "no trained model" if bundle is None else "database unavailable"
        return summary
    logs = fetch_logs(since=utils.utcnow() - timedelta(hours=hours))
    result = analyse(bundle, logs, rule_severity=_rule_severity(logs))
    now = utils.utcnow()

    for row in result["anomalies"]:
        doc = anomaly_to_alert(row, bundle["version"])
        alert_id = doc.pop("_id")
        doc.pop("resolved")  # keep the analyst's decision when the window is scored again
        db[ANOMALIES_COLLECTION].update_one(
            {"_id": alert_id}, {"$set": doc, "$setOnInsert": {"resolved": False}}, upsert=True)
    for entity in result["risk"]:
        doc = dict(entity, updated_at=now, model_version=bundle["version"])
        db[RISK_COLLECTION].replace_one({"_id": doc.pop("id")}, doc, upsert=True)
    for key, baseline in result["baselines"].items():
        db[BASELINES_COLLECTION].replace_one(
            {"_id": key}, dict(baseline.to_dict(), updated_at=now), upsert=True)

    summary.update(ran=True, model_version=bundle["version"], logs=len(logs),
                   windows=len(result["rows"]), anomalies=len(result["anomalies"]),
                   clusters=len(result["clusters"]), entities=len(result["risk"]))
    return summary


# ---------------------------------------------------------------------------
# Retrieval for the API
# ---------------------------------------------------------------------------

def _ml_query(since: Optional[datetime] = None, resolved: Optional[bool] = None) -> Dict[str, Any]:
    query: Dict[str, Any] = {"detection_type": DetectionType.ML_DETECTED.value}
    if since:
        query["timestamp"] = {"$gte": since}
    if resolved is not None:
        query["resolved"] = resolved
    return query


def get_anomalies(limit: int = 50, offset: int = 0, since: Optional[datetime] = None,
                  resolved: Optional[bool] = None) -> List[Dict[str, Any]]:
    """ML-detected alerts, highest anomaly score first."""
    alerts = database.get_collection(ANOMALIES_COLLECTION)
    if alerts is None:
        return []
    cursor = (alerts.find(_ml_query(since, resolved))
              .sort([("anomaly_score", -1), ("timestamp", -1)]).skip(offset).limit(limit))
    return [document_to_api(doc) for doc in cursor]


def count_anomalies(since: Optional[datetime] = None, resolved: Optional[bool] = None) -> int:
    alerts = database.get_collection(ANOMALIES_COLLECTION)
    return 0 if alerts is None else alerts.count_documents(_ml_query(since, resolved))


def count_anomaly_techniques(since: Optional[datetime] = None) -> Dict[str, int]:
    """ML alerts per MITRE technique: {'T1110': 4, ...}"""
    alerts = database.get_collection(ANOMALIES_COLLECTION)
    if alerts is None:
        return {}
    pipeline = [{"$match": _ml_query(since)},
                {"$group": {"_id": "$mitre_technique", "count": {"$sum": 1}}}]
    return {row["_id"]: row["count"] for row in alerts.aggregate(pipeline) if row["_id"]}


def set_anomaly_resolved(alert_id: str, resolved: bool = True) -> bool:
    alerts = database.get_collection(ANOMALIES_COLLECTION)
    if alerts is None:
        return False
    return alerts.update_one({"_id": alert_id}, {"$set": {"resolved": resolved}}).matched_count == 1


def get_entity_risk(limit: int = 20, entity_type: Optional[str] = None,
                    min_score: float = 0) -> List[Dict[str, Any]]:
    """Entities ranked by composite risk score."""
    collection = database.get_collection(RISK_COLLECTION)
    if collection is None:
        return []
    query: Dict[str, Any] = {"risk_score": {"$gte": min_score}}
    if entity_type:
        query["entity_type"] = entity_type
    cursor = collection.find(query).sort([("risk_score", -1), ("_id", 1)]).limit(limit)
    return [document_to_api(doc) for doc in cursor]


def get_entity_profile(entity_type: str, entity: str) -> Optional[Dict[str, Any]]:
    """Everything known about one entity: risk, baseline and its ML alerts."""
    db = database.get_db()
    if db is None:
        return None
    key = f"{entity_type}:{entity}"
    risk = db[RISK_COLLECTION].find_one({"_id": key})
    baseline = db[BASELINES_COLLECTION].find_one({"_id": key})
    anomalies = list(db[ANOMALIES_COLLECTION]
                     .find({"entity_type": entity_type, "entity": entity})
                     .sort("timestamp", -1).limit(20))
    if risk is None and baseline is None and not anomalies:
        return None
    usual = None
    if baseline:
        usual = {"windows": baseline["n"],
                 "mean": {name: round(value, 2) for name, value in baseline["mean"].items()
                          if value}}
    return {"entity_type": entity_type, "entity": entity,
            "risk": document_to_api(risk) if risk else None, "baseline": usual,
            "anomalies": [document_to_api(doc) for doc in anomalies]}


def main():
    parser = argparse.ArgumentParser(description="ARGUS ML / UEBA engine")
    sub = parser.add_subparsers(dest="command", required=True)
    p_train = sub.add_parser("train", help="train a new model version from stored logs")
    p_train.add_argument("--hours", type=float, default=24)
    p_train.add_argument("--contamination", type=float, default=0.01)
    p_detect = sub.add_parser("detect", help="score recent logs with the active model")
    p_detect.add_argument("--hours", type=float, default=1)
    sub.add_parser("models", help="list model versions")
    args = parser.parse_args()

    if args.command == "train":
        print(json.dumps(train_from_db(args.hours, args.contamination), indent=2))
    elif args.command == "detect":
        print(json.dumps(detect(args.hours), indent=2))
    else:
        print(json.dumps(list_models(), indent=2))


if __name__ == "__main__":
    main()
