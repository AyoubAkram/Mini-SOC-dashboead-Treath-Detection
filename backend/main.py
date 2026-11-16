from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import asyncio
import os
import shutil
import sys
import subprocess
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

# Initialize FastAPI app
app = FastAPI(
    title="SOC Dashboard API",
    description="Security Operations Center - Threat Detection API",
    version="0.1.0"
)

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import ingestion module
from ingestion import (
    get_logs, get_log_count, count_by_event_type, count_by_log_source,
    top_source_ips, count_unique_source_ips, verify_batch,
    get_alert_events, count_alert_events, alert_severity_counts, set_alert_status,
    count_alert_types, alert_volume,
)
import ml
from dataBase import is_connected
from models import LogSource
from utils import is_private_ip, utcnow

# Global variable to store collector process
collector_process = None

# TODO: Import and setup database connection
# from .database import engine, SessionLocal, Base
# Base.metadata.create_all(bind=engine)

# TODO: Import detection module
# from .detection import ThreatDetector


ml_task = None


async def ml_detection_loop(interval: float):
    """Score recent logs with the active model at a fixed interval."""
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(ml.detect, 1)
        except Exception as e:
            print(f"✗ ML detection failed: {e}")


@app.on_event("startup")
async def startup_event():
    """Start log collection and API on startup"""
    global collector_process
    
    print("=" * 60)
    print("SOC Dashboard API starting...")
    print("MongoDB ingestion module loaded")
    print("=" * 60)
    
    # Periodic ML detection (ML_DETECT_INTERVAL seconds, 0 disables it)
    global ml_task
    interval = float(os.getenv("ML_DETECT_INTERVAL", "60"))
    if interval > 0:
        ml_task = asyncio.create_task(ml_detection_loop(interval))
        print(f"✓ ML detection every {interval:g}s (when a trained model exists)")

    # Start the log collector process
    # SOC_COLLECTOR: auto (default) | journald | syslog | off
    mode = os.getenv("SOC_COLLECTOR", "auto").lower()
    if mode == "off":
        print("Log collector disabled (SOC_COLLECTOR=off)")
        return
    try:
        collector_dir = Path(__file__).parent.parent / "collector"
        if mode == "journald" or (mode == "auto" and shutil.which("journalctl")):
            print("✓ journalctl found. using journalctl for log collection.")
            collector_path = collector_dir / "journalLogs.py"
        elif Path("/var/log/syslog").exists():
            print("✗ journalctl not found. falling back to syslog.")
            collector_path = collector_dir / "sylog.py"
        else:
            print("✗ No journalctl and no /var/log/syslog: log collector not started")
            return
        print(f"\n🔄 Starting log collector from: {collector_path}")

        # Output is inherited: an unread PIPE would fill up and block the collector
        collector_process = subprocess.Popen([sys.executable, str(collector_path)])
        print(f"✓ Log collector started (PID: {collector_process.pid})")
        print("✓ Logs are being ingested into MongoDB in real-time")
    except Exception as e:
        print(f"✗ Failed to start log collector: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up collector process on shutdown"""
    global collector_process

    if ml_task:
        ml_task.cancel()

    if collector_process:
        print("\n" + "=" * 60)
        print("Shutting down SOC Dashboard API...")
        print("Terminating log collector...")
        
        try:
            collector_process.terminate()
            collector_process.wait(timeout=5)
            print("✓ Log collector terminated")
        except subprocess.TimeoutExpired:
            collector_process.kill()
            print("✓ Log collector killed")
        except Exception as e:
            print(f"✗ Error terminating collector: {e}")
        
        print("=" * 60)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "operational",
        "service": "SOC Dashboard API",
        "timestamp": utcnow().isoformat()
    }


TIME_RANGES = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}


def range_start(time_range: str, periods: int = 1) -> datetime:
    """Start of the selected dashboard time range (unknown values mean 24h)."""
    hours = TIME_RANGES.get(time_range, 24)
    return utcnow() - timedelta(hours=hours * periods)


def trend(current: int, previous: int) -> Optional[float]:
    """Change in percent against the previous period (None when there is no baseline)."""
    if not previous:
        return None
    return round(100 * (current - previous) / previous, 1)


def threat_score(severity_counts: Dict[str, int], total_events: int) -> float:
    """
    Placeholder 0-10 score until the ML risk scoring exists: the severity-weighted
    share of alert events among all events of the period.
    """
    weighted = (8 * severity_counts["critical"] + 4 * severity_counts["high"]
                + severity_counts["medium"])
    quiet = max(total_events - sum(severity_counts.values()), 0)
    if weighted == 0:
        return 0.0
    return round(10 * weighted / (weighted + quiet), 1)


def threat_level(score: float) -> str:
    if score >= 7.5:
        return "critical"
    if score >= 5:
        return "high"
    return "medium" if score >= 2.5 else "low"


def to_alert(log: Dict[str, Any]) -> Dict[str, Any]:
    """Shape a stored log as an alert for the dashboard."""
    destination = log.get("dest_ip") or log.get("host") or "-"
    if log.get("dest_ip") and log.get("dest_port"):
        destination = f"{log['dest_ip']}:{log['dest_port']}"
    return {
        "id": log["id"],
        "timestamp": log.get("timestamp", ""),
        "severity": log["severity"],
        "type": str(log.get("event_type", "unknown")).replace("_", " ").title(),
        "event_type": log.get("event_type"),
        "log_source": log.get("log_source"),
        "source": log.get("source_ip") or log.get("host") or "unknown",
        "destination": destination,
        "username": log.get("username"),
        "description": log.get("message", ""),
        "status": log["status"]
    }


@app.get("/api/stats")
async def get_stats(time_range: str = "24h") -> Dict[str, Any]:
    """
    Get dashboard statistics for the selected time range from MongoDB logs
    """
    since, previous = range_start(time_range), range_start(time_range, periods=2)
    total = get_log_count(since=since)
    alerts = count_alert_events(since=since, status="unresolved")
    failed = get_log_count(since=since, event_type="login_failed")
    severity_counts = alert_severity_counts(since=since, status="unresolved")
    score = threat_score(severity_counts, total)
    return {
        "time_range": time_range if time_range in TIME_RANGES else "24h",
        "database_connected": is_connected(),
        "total_events": total,
        "total_events_trend": trend(total, get_log_count(since=previous, until=since)),
        "active_alerts": alerts,
        "active_alerts_trend": trend(alerts, count_alert_events(since=previous, until=since,
                                                                status="unresolved")),
        "failed_logins": failed,
        "failed_logins_trend": trend(failed, get_log_count(since=previous, until=since,
                                                           event_type="login_failed")),
        "unique_source_ips": count_unique_source_ips(since=since),
        "severity_counts": severity_counts,
        "threat_score": score,
        "threat_level": threat_level(score),
        "rule_alerts": count_alert_events(since=since),
        "ml_alerts": ml.count_anomalies(since=since),
        "timestamp": utcnow().isoformat()
    }


@app.get("/api/logs")
async def list_logs(
    limit: int = 50,
    offset: int = 0,
    log_source: Optional[LogSource] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get normalized logs (most recent first), with optional filters
    """
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    filters = {
        "log_source": log_source.value if log_source else None,
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "search": search,
    }
    return {
        "logs": get_logs(limit=limit, offset=offset, **filters),
        "total": get_log_count(**filters),
        "limit": limit,
        "offset": offset
    }


@app.get("/api/batches/{batch_id}/verify")
async def verify_log_batch(batch_id: str) -> Dict[str, Any]:
    """Check the SHA-256 integrity hash of an ingested batch"""
    return verify_batch(batch_id)


@app.get("/api/alerts")
async def get_alerts(
    limit: int = 50,
    offset: int = 0,
    time_range: str = "24h",
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get recent security alerts from MongoDB
    TODO: Replace with alerts produced by the detection engine
    """
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    filters = {"since": range_start(time_range), "severity": severity, "status": status,
               "search": search}
    return {
        "alerts": [to_alert(log) for log in get_alert_events(limit=limit, offset=offset, **filters)],
        "total": count_alert_events(**filters),
        "limit": limit,
        "offset": offset
    }


@app.get("/api/threats")
async def get_threats(limit: int = 10, time_range: str = "24h",
                      severity: Optional[str] = None) -> Dict[str, Any]:
    """
    Get active threats: unresolved alerts raised by the IDS sensor
    TODO: Integrate with real threat detection engine
    """
    limit = max(1, min(limit, 200))
    filters = {"since": range_start(time_range), "severity": severity, "status": "unresolved",
               "ids_only": True}
    threats = [
        {
            "id": log["id"],
            "severity": log["severity"],
            "title": log.get("message", ""),
            "description": (log.get("extra") or {}).get("classification") or "",
            "source": log.get("source_ip") or "unknown",
            "target": to_alert(log)["destination"],
            "timestamp": log.get("timestamp", ""),
            "status": log["status"]
        }
        for log in get_alert_events(limit=limit, **filters)
    ]
    return {
        "threats": threats,
        "total": count_alert_events(**filters)
    }


@app.get("/api/timeline")
async def get_timeline(limit: int = 20, time_range: str = "24h") -> Dict[str, Any]:
    """
    Get event timeline: the most recent high and critical alerts
    """
    limit = max(1, min(limit, 200))
    since = range_start(time_range)
    events = get_alert_events(limit=limit, since=since, severity="critical")
    events += get_alert_events(limit=limit, since=since, severity="high")
    events.sort(key=lambda log: log.get("timestamp", ""), reverse=True)
    timeline = [
        {
            "id": log["id"],
            "timestamp": log.get("timestamp", ""),
            "severity": log["severity"],
            "title": to_alert(log)["type"],
            "description": log.get("message", "")
        }
        for log in events[:limit]
    ]
    return {
        "timeline": timeline,
        "total": len(timeline)
    }


@app.get("/api/event-types")
async def get_event_types(limit: int = 10, time_range: str = "24h") -> Dict[str, Any]:
    """
    Get top event types, aggregated from the stored logs
    """
    since = range_start(time_range)
    counts = count_by_event_type(limit=limit, since=since)
    top = counts[0]["count"] if counts else 0
    return {
        "event_types": [
            {
                "name": row["value"],
                "count": row["count"],
                "percentage": round(100 * row["count"] / top) if top else 0
            }
            for row in counts
        ],
        "log_sources": [
            {"name": row["value"], "count": row["count"]}
            for row in count_by_log_source(since=since)
        ]
    }


@app.get("/api/source-ips")
async def get_source_ips(limit: int = 10, time_range: str = "24h") -> Dict[str, Any]:
    """
    Get top source IPs, aggregated from the stored logs
    TODO: Add GeoIP location and threat level from threat intelligence
    """
    return {
        "source_ips": [
            {
                "ip": row["value"],
                "location": "Internal Network" if is_private_ip(row["value"]) else "External",
                "event_count": row["count"],
                "threat_level": "unknown"
            }
            for row in top_source_ips(limit=limit, since=range_start(time_range))
        ]
    }


# time range -> size of one chart bucket in minutes
VOLUME_BUCKETS = {"1h": 5, "24h": 60, "7d": 6 * 60, "30d": 24 * 60}


@app.get("/api/alert-volume")
async def get_alert_volume(time_range: str = "24h") -> Dict[str, Any]:
    """
    Alert volume over time, per severity, plus ML-detected anomalies per bucket
    """
    time_range = time_range if time_range in TIME_RANGES else "24h"
    minutes = VOLUME_BUCKETS[time_range]
    since, until = range_start(time_range), utcnow()
    buckets = alert_volume(since, until, minutes)
    ml_counts: Dict[int, int] = {}
    for anomaly in ml.get_anomalies(limit=5000, since=since):
        start = int(datetime.fromisoformat(anomaly["timestamp"]).timestamp()) // (minutes * 60)
        ml_counts[start] = ml_counts.get(start, 0) + 1
    return {
        "bucket_minutes": minutes,
        "buckets": [
            {
                "time": bucket["time"].isoformat(),
                "critical": bucket["critical"],
                "high": bucket["high"],
                "medium": bucket["medium"],
                "low": bucket["low"],
                "ml": ml_counts.get(int(bucket["time"].timestamp()) // (minutes * 60), 0)
            }
            for bucket in buckets
        ]
    }


@app.get("/api/attack-types")
async def get_attack_types(limit: int = 8, time_range: str = "24h") -> Dict[str, Any]:
    """
    Alerts grouped by type
    """
    return {
        "attack_types": [
            {"name": row["value"], "count": row["count"]}
            for row in count_alert_types(limit=limit, since=range_start(time_range))
        ]
    }


# ---------------------------------------------------------------------------
# ML / UEBA
# ---------------------------------------------------------------------------

@app.get("/api/ml/models")
async def list_ml_models() -> Dict[str, Any]:
    """Model versions and the active one"""
    return ml.list_models()


@app.post("/api/ml/train")
async def train_ml_model(hours: float = 24, contamination: float = 0.01) -> Dict[str, Any]:
    """
    Train a new model version on the logs of the last 'hours' and activate it
    """
    if not 0 < contamination <= 0.2:
        raise HTTPException(status_code=422, detail="contamination must be between 0 and 0.2")
    try:
        return await asyncio.to_thread(ml.train_from_db, hours, contamination)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.post("/api/ml/models/{version}/activate")
async def activate_ml_model(version: str) -> Dict[str, Any]:
    """Switch the model used for detection (rollback to an older version)"""
    if not ml.set_active_model(version):
        raise HTTPException(status_code=404, detail="Model version not found")
    return ml.list_models()


@app.post("/api/ml/detect")
async def run_ml_detection(hours: float = 1) -> Dict[str, Any]:
    """
    Score the logs of the last 'hours' with the active model
    """
    return await asyncio.to_thread(ml.detect, hours)


@app.get("/api/ml/anomalies")
async def get_ml_anomalies(limit: int = 20, offset: int = 0, time_range: str = "24h",
                           resolved: Optional[bool] = None) -> Dict[str, Any]:
    """
    ML-detected alerts (shared Alert model), highest anomaly score first
    """
    limit = max(1, min(limit, 200))
    since = range_start(time_range)
    return {
        "anomalies": ml.get_anomalies(limit=limit, offset=max(0, offset), since=since,
                                      resolved=resolved),
        "total": ml.count_anomalies(since=since, resolved=resolved)
    }


@app.patch("/api/ml/anomalies/{alert_id}/resolve")
@app.post("/api/ml/anomalies/{alert_id}/resolve")
async def resolve_ml_anomaly(alert_id: str, resolved: bool = True) -> Dict[str, Any]:
    """Resolve (or reopen with resolved=false) an ML-detected alert"""
    if not ml.set_anomaly_resolved(alert_id, resolved):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_id": alert_id, "resolved": resolved}


@app.get("/api/ml/entities")
async def get_risky_entities(limit: int = 10, entity_type: Optional[str] = None,
                             min_score: float = 0) -> Dict[str, Any]:
    """
    Entities (IPs and users) ranked by composite risk score
    """
    return {"entities": ml.get_entity_risk(limit=max(1, min(limit, 200)),
                                           entity_type=entity_type, min_score=min_score)}


@app.get("/api/entities/{entity_type}/{entity}")
async def get_entity(entity_type: str, entity: str) -> Dict[str, Any]:
    """
    Entity profile: risk score, behavioral baseline, ML alerts and recent logs
    """
    if entity_type not in ml.ENTITY_TYPES:
        raise HTTPException(status_code=404, detail="Unknown entity type")
    profile = ml.get_entity_profile(entity_type, entity) or {
        "entity_type": entity_type, "entity": entity, "risk": None, "baseline": None,
        "anomalies": []}
    field = "source_ip" if entity_type == "ip" else "username"
    profile["recent_logs"] = get_logs(limit=25, **{field: entity})
    profile["total_logs"] = get_log_count(**{field: entity})
    if not profile["total_logs"] and not profile["risk"] and not profile["anomalies"]:
        raise HTTPException(status_code=404, detail="Entity not found")
    return profile


def update_alert_status(alert_id: str, status: str) -> Dict[str, Any]:
    if not set_alert_status(alert_id, status):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "alert_id": alert_id,
        "status": status,
        "timestamp": utcnow().isoformat()
    }


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str) -> Dict[str, Any]:
    """
    Acknowledge an alert: it is now being investigated
    """
    return update_alert_status(alert_id, "investigating")


@app.post("/api/alerts/{alert_id}/resolve")
@app.patch("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str) -> Dict[str, Any]:
    """
    Resolve an alert and close the investigation
    """
    return update_alert_status(alert_id, "resolved")


@app.post("/api/alerts/{alert_id}/reopen")
async def reopen_alert(alert_id: str) -> Dict[str, Any]:
    """Put an alert back to open"""
    return update_alert_status(alert_id, "open")


@app.post("/api/threats/{threat_id}/investigate")
async def investigate_threat(threat_id: str) -> Dict[str, Any]:
    """
    Start investigation on a threat
    """
    return update_alert_status(threat_id, "investigating")


@app.get("/api/health")
async def health_check() -> Dict[str, str]:
    """Service health check"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
