"""
Log Ingestion Module
Normalizes raw logs from every source into the unified LogEntry schema, stores
them in MongoDB and records a SHA-256 hash per batch for log integrity.
"""

import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from . import dataBase as database, parsers, utils
    from .models import EventType, LogBatch, LogEntry, LogSource, document_to_api
except ImportError:  # running with backend/ on sys.path (python backend/main.py)
    import dataBase as database
    import parsers
    import utils
    from models import EventType, LogBatch, LogEntry, LogSource, document_to_api

# journalctl -o json output; entries are stored as linux_auth or syslog
JOURNALD = "journald"

SECURITY_EVENT_TYPES = [
    EventType.LOGIN_FAILED.value, EventType.LOGIN_SUCCESS.value, EventType.INVALID_USER.value,
    EventType.SUDO_COMMAND.value, EventType.SUDO_FAILED.value, EventType.ACCOUNT_CREATED.value,
    EventType.ACCOUNT_LOCKED.value, EventType.PRIVILEGE_ASSIGNED.value,
    EventType.EXPLICIT_CREDENTIAL_LOGON.value,
]


def _logs():
    return database.get_collection(database.LOGS_COLLECTION)


def _batches():
    return database.get_collection(database.BATCHES_COLLECTION)


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

def _batch_source(log_source) -> LogSource:
    """Source recorded on the batch (journald has no LogSource of its own)."""
    return LogSource.SYSLOG if log_source == JOURNALD else LogSource(log_source)


def normalize(lines: Iterable[str], log_source) -> Tuple[List[LogEntry], int]:
    """
    Parse raw lines into LogEntry objects. Pure function: no database access.

    Lines the parser does not recognise are kept as 'unknown' entries flagged
    with extra.parse_error, so nothing is silently dropped and the batch hash
    still covers every line. Blank lines and Zeek headers are skipped.

    Returns (entries, number_of_parse_errors).
    """
    journald = log_source == JOURNALD
    source = _batch_source(log_source)
    entries: List[LogEntry] = []
    errors = 0

    for line in lines:
        line = line.rstrip("\r\n")
        if not journald and parsers.is_ignorable(source, line):
            if source == LogSource.ZEEK:
                parsers.parse_zeek(line)  # let the parser see '#fields' headers
            continue
        if journald and not line.strip():
            continue
        try:
            entry = parsers.parse_journald(line) if journald else parsers.parse_line(source, line)
        except Exception as e:  # a parser bug must never stop the pipeline
            print(f"Parser error on {source.value} line: {e}")
            entry = None
        if entry is None:
            errors += 1
            entry = LogEntry(timestamp=utils.utcnow(), log_source=source,
                             event_type=EventType.UNKNOWN, message=line[:500], raw=line,
                             extra={"parse_error": True})
        entries.append(entry)
    return entries, errors


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def ingest_batch(lines: Iterable[str], log_source) -> Dict[str, Any]:
    """
    Normalize and store one batch of raw lines.

    Returns a summary: batch_id, sha256, count, parse_errors, stored.
    'stored' is False when MongoDB is not reachable.
    """
    entries, errors = normalize(lines, log_source)
    summary = {"batch_id": None, "sha256": None, "count": len(entries),
               "parse_errors": errors, "stored": False}
    if not entries:
        return summary

    batch = LogBatch(log_source=_batch_source(log_source), count=len(entries), parse_errors=errors,
                     sha256=utils.sha256_batch(entry.raw for entry in entries))
    now = utils.utcnow()
    for seq, entry in enumerate(entries):
        entry.batch_id = batch.id
        entry.batch_seq = seq
        entry.ingested_at = now
    summary.update(batch_id=batch.id, sha256=batch.sha256)

    logs, batches = _logs(), _batches()
    if logs is None or batches is None:
        print("MongoDB not connected")
        return summary
    try:
        logs.insert_many([entry.to_document() for entry in entries])
        batches.insert_one(batch.to_document())
        summary["stored"] = True
    except Exception as e:
        print(f"Error ingesting batch: {e}")
    return summary


def ingest_log(log_entry: str, log_source=JOURNALD) -> bool:
    """
    Ingest a single raw log line.

    Args:
        log_entry: the raw line (a JSON string from journalctl by default)
        log_source: 'journald' or any LogSource value

    Returns:
        bool: True if the line was stored
    """
    return ingest_batch([log_entry], log_source)["stored"]


def ingest_file(path, log_source, batch_size: int = 500) -> List[Dict[str, Any]]:
    """Ingest a whole log file in batches. Returns one summary per batch."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    records = parsers.split_records(log_source, text) if log_source != JOURNALD else text.splitlines()
    return [ingest_batch(records[i:i + batch_size], log_source)
            for i in range(0, len(records), batch_size)]


def verify_batch(batch_id: str) -> Dict[str, Any]:
    """
    Recompute the SHA-256 of a stored batch and compare it with the recorded
    hash. A mismatch means logs were modified, removed or added after ingestion.
    """
    logs, batches = _logs(), _batches()
    if logs is None or batches is None:
        return {"batch_id": batch_id, "valid": False, "reason": "database unavailable"}
    record = batches.find_one({"_id": batch_id})
    if record is None:
        return {"batch_id": batch_id, "valid": False, "reason": "batch not found"}

    docs = list(logs.find({"batch_id": batch_id}).sort("batch_seq", 1))
    actual = utils.sha256_batch(doc.get("raw", "") for doc in docs)
    valid = actual == record["sha256"] and len(docs) == record["count"]
    result = {"batch_id": batch_id, "valid": valid, "expected_sha256": record["sha256"],
              "actual_sha256": actual, "expected_count": record["count"], "actual_count": len(docs)}
    if not valid:
        result["reason"] = "count mismatch" if len(docs) != record["count"] else "hash mismatch"
    return result


class LogBatcher:
    """
    Buffers lines from a live stream and ingests them in batches, flushing when
    the buffer is full or when the oldest line has waited max_age seconds.
    Thread-safe; call close() when the stream ends.
    """

    def __init__(self, log_source, max_size: int = 100, max_age: float = 2.0):
        self.log_source = log_source
        self.max_size = max_size
        self.max_age = max_age
        self._lines: List[str] = []
        self._first_at: Optional[float] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def add(self, line: str) -> None:
        with self._lock:
            if not self._lines:
                self._first_at = time.monotonic()
            self._lines.append(line)
            full = len(self._lines) >= self.max_size
        if full:
            self.flush()

    def flush(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            lines, self._lines, self._first_at = self._lines, [], None
        return ingest_batch(lines, self.log_source) if lines else None

    def _run(self) -> None:
        while not self._stop.wait(min(self.max_age / 2, 0.5)):
            with self._lock:
                due = self._first_at is not None and time.monotonic() - self._first_at >= self.max_age
            if due:
                self.flush()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.flush()


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def _find(query: Dict[str, Any], limit: int, offset: int = 0) -> List[Dict[str, Any]]:
    logs = _logs()
    if logs is None:
        return []
    try:
        cursor = logs.find(query).sort("timestamp", -1).skip(offset).limit(limit)
        return [document_to_api(doc) for doc in cursor]
    except Exception as e:
        print(f"Error retrieving logs: {e}")
        return []


def build_query(log_source: Optional[str] = None, event_type: Optional[str] = None,
                source_ip: Optional[str] = None, username: Optional[str] = None,
                search: Optional[str] = None, since=None, until=None) -> Dict[str, Any]:
    query: Dict[str, Any] = {}
    if since is not None or until is not None:
        query["timestamp"] = {}
        if since is not None:
            query["timestamp"]["$gte"] = since
        if until is not None:
            query["timestamp"]["$lt"] = until
    if log_source:
        query["log_source"] = log_source
    if event_type:
        query["event_type"] = event_type
    if source_ip:
        query["source_ip"] = source_ip
    if username:
        query["username"] = username
    if search:
        query["message"] = {"$regex": re.escape(search), "$options": "i"}
    return query


def get_logs(limit: int = 50, offset: int = 0, **filters) -> List[Dict[str, Any]]:
    """
    Retrieve normalized logs, most recent first.

    Args:
        limit: Maximum number of logs to return
        offset: Number of logs to skip from the beginning
        filters: log_source, event_type, source_ip, username, search

    Returns:
        List of log entries in the API shape
    """
    return _find(build_query(**filters), limit, offset)


def get_log_count(**filters) -> int:
    """Get the number of stored logs matching the filters (all logs by default)."""
    logs = _logs()
    if logs is None:
        return 0
    try:
        return logs.count_documents(build_query(**filters))
    except Exception as e:
        print(f"Error counting logs: {e}")
        return 0


def filter_logs_by_service(service_name: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Filter logs by the process / service that produced them (e.g. 'sshd')."""
    names = [service_name, f"{service_name}d", f"{service_name}.service"]
    return _find({"$or": [{"process": {"$in": names}}, {"extra.unit": {"$in": names}}]}, limit)


def filter_logs_by_command(command: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Filter logs by command / process name (e.g. 'sudo')."""
    return _find({"process": command}, limit)


def get_security_logs(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Get authentication and privilege related logs from every source."""
    return _find({"event_type": {"$in": SECURITY_EVENT_TYPES}}, limit, offset)


def _aggregate_counts(field: str, limit: int, **filters) -> List[Dict[str, Any]]:
    logs = _logs()
    if logs is None:
        return []
    try:
        match = build_query(**filters)
        match[field] = {"$ne": None}
        pipeline = [
            {"$match": match},
            {"$group": {"_id": f"${field}", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": limit},
        ]
        return [{"value": row["_id"], "count": row["count"]} for row in logs.aggregate(pipeline)]
    except Exception as e:
        print(f"Error aggregating logs by {field}: {e}")
        return []


def count_by_event_type(limit: int = 10, **filters) -> List[Dict[str, Any]]:
    """Most frequent event types: [{'value': 'login_failed', 'count': 42}, ...]"""
    return _aggregate_counts("event_type", limit, **filters)


def count_by_log_source(limit: int = 10, **filters) -> List[Dict[str, Any]]:
    return _aggregate_counts("log_source", limit, **filters)


def top_source_ips(limit: int = 10, **filters) -> List[Dict[str, Any]]:
    """Most active source IPs: [{'value': '1.2.3.4', 'count': 42}, ...]"""
    return _aggregate_counts("source_ip", limit, **filters)


def count_unique_source_ips(**filters) -> int:
    logs = _logs()
    if logs is None:
        return 0
    try:
        match = build_query(**filters)
        match["source_ip"] = {"$ne": None}
        rows = list(logs.aggregate([{"$match": match}, {"$group": {"_id": "$source_ip"}},
                                    {"$count": "n"}]))
        return rows[0]["n"] if rows else 0
    except Exception as e:
        print(f"Error counting source IPs: {e}")
        return 0


# ---------------------------------------------------------------------------
# Alert view
# Until the detection engine writes real alerts, suspicious raw events are shown
# as alerts: failed / privileged authentication events and IDS alerts.
# ---------------------------------------------------------------------------

HIGH_EVENT_TYPES = [EventType.ACCOUNT_CREATED.value, EventType.PRIVILEGE_ASSIGNED.value,
                    EventType.SUDO_FAILED.value]
MEDIUM_EVENT_TYPES = [EventType.LOGIN_FAILED.value, EventType.INVALID_USER.value,
                      EventType.ACCOUNT_LOCKED.value, EventType.EXPLICIT_CREDENTIAL_LOGON.value]
IDS = EventType.IDS_ALERT.value
ALERT_STATUSES = ("open", "investigating", "resolved")

# severity -> MongoDB condition (IDS alerts use the sensor's own priority, 1 = worst)
_SEVERITY_CONDITIONS = {
    "critical": {"event_type": IDS, "extra.priority": 1},
    "high": {"$or": [{"event_type": {"$in": HIGH_EVENT_TYPES}},
                     {"event_type": IDS, "extra.priority": 2}]},
    "medium": {"$or": [{"event_type": {"$in": MEDIUM_EVENT_TYPES}},
                       {"event_type": IDS, "extra.priority": 3}]},
    "low": {"event_type": IDS, "extra.priority": {"$nin": [1, 2, 3]}},
}


def alert_severity(doc: Dict[str, Any]) -> str:
    """Severity of a log shown as an alert (same rules as _SEVERITY_CONDITIONS)."""
    event_type = doc.get("event_type")
    if event_type == IDS:
        priority = (doc.get("extra") or {}).get("priority")
        return {1: "critical", 2: "high", 3: "medium"}.get(priority, "low")
    if event_type in HIGH_EVENT_TYPES:
        return "high"
    return "medium" if event_type in MEDIUM_EVENT_TYPES else "low"


def alert_query(since=None, until=None, severity: Optional[str] = None,
                status: Optional[str] = None, search: Optional[str] = None,
                ids_only: bool = False) -> Dict[str, Any]:
    """
    MongoDB query selecting the logs shown as alerts.
    status: open | investigating | resolved | unresolved
    """
    conditions: List[Dict[str, Any]] = []
    if ids_only:
        conditions.append({"event_type": IDS})
    else:
        conditions.append({"event_type": {"$in": HIGH_EVENT_TYPES + MEDIUM_EVENT_TYPES + [IDS]}})
    time_range = build_query(since=since, until=until)
    if time_range:
        conditions.append(time_range)
    if severity in _SEVERITY_CONDITIONS:
        conditions.append(_SEVERITY_CONDITIONS[severity])
    if status == "unresolved":
        conditions.append({"alert_status": {"$ne": "resolved"}})
    elif status == "open":
        conditions.append({"alert_status": {"$in": [None, "open"]}})
    elif status in ALERT_STATUSES:
        conditions.append({"alert_status": status})
    if search:
        pattern = {"$regex": re.escape(search), "$options": "i"}
        conditions.append({"$or": [{"message": pattern}, {"source_ip": pattern},
                                   {"username": pattern}, {"host": pattern},
                                   {"event_type": pattern}]})
    return {"$and": conditions}


def get_alert_events(limit: int = 50, offset: int = 0, **filters) -> List[Dict[str, Any]]:
    """Logs shown as alerts, most recent first, each with 'severity' and 'status'."""
    events = _find(alert_query(**filters), limit, offset)
    for event in events:
        event["severity"] = alert_severity(event)
        event["status"] = event.pop("alert_status", None) or "open"
    return events


def count_alert_events(**filters) -> int:
    logs = _logs()
    if logs is None:
        return 0
    try:
        return logs.count_documents(alert_query(**filters))
    except Exception as e:
        print(f"Error counting alerts: {e}")
        return 0


def alert_severity_counts(**filters) -> Dict[str, int]:
    """Number of alerts per severity: {'critical': 1, 'high': 4, 'medium': 20, 'low': 0}"""
    filters.pop("severity", None)
    return {severity: count_alert_events(severity=severity, **filters)
            for severity in _SEVERITY_CONDITIONS}


def count_alert_types(limit: int = 10, **filters) -> List[Dict[str, Any]]:
    """Alerts per event type: [{'value': 'login_failed', 'count': 42}, ...]"""
    logs = _logs()
    if logs is None:
        return []
    try:
        pipeline = [
            {"$match": alert_query(**filters)},
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": limit},
        ]
        return [{"value": row["_id"], "count": row["count"]} for row in logs.aggregate(pipeline)]
    except Exception as e:
        print(f"Error counting alert types: {e}")
        return []


def alert_volume(since, until, bucket_minutes: int) -> List[Dict[str, Any]]:
    """
    Alerts per time bucket and severity, oldest first, with empty buckets
    included: [{'time': datetime, 'critical': 0, 'high': 2, 'medium': 5, 'low': 0}, ...]
    """
    step = bucket_minutes * 60
    first = int(utils.to_utc(since).timestamp()) // step * step
    last = int(utils.to_utc(until).timestamp()) // step * step
    buckets = {start: {"critical": 0, "high": 0, "medium": 0, "low": 0}
               for start in range(first, last + 1, step)}
    logs = _logs()
    if logs is not None:
        try:
            cursor = logs.find(alert_query(since=since, until=until),
                               {"timestamp": 1, "event_type": 1, "extra.priority": 1})
            for doc in cursor:
                start = int(utils.to_utc(doc["timestamp"]).timestamp()) // step * step
                if start in buckets:
                    buckets[start][alert_severity(doc)] += 1
        except Exception as e:
            print(f"Error computing alert volume: {e}")
    return [dict(counts, time=utils.parse_epoch(start)) for start, counts in sorted(buckets.items())]


def set_alert_status(log_id: str, status: str) -> bool:
    """
    Set the triage status of a log shown as an alert. Returns False when the
    log does not exist. The raw line is untouched, so batch hashes stay valid.
    """
    logs = _logs()
    if logs is None or status not in ALERT_STATUSES:
        return False
    try:
        result = logs.update_one({"_id": log_id},
                                 {"$set": {"alert_status": status,
                                           "alert_status_at": utils.utcnow()}})
        return result.matched_count == 1
    except Exception as e:
        print(f"Error updating alert status: {e}")
        return False


def clear_logs() -> int:
    """Clear all logs and batch records from MongoDB"""
    logs, batches = _logs(), _batches()
    if logs is None:
        return 0
    try:
        result = logs.delete_many({})
        if batches is not None:
            batches.delete_many({})
        return result.deleted_count
    except Exception as e:
        print(f"Error clearing logs: {e}")
        return 0
