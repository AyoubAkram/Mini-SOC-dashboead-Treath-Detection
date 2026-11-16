"""Normalizer, storage, integrity hashing and retrieval (MongoDB mocked with mongomock)."""

import json
import time

from backend import ingestion, utils
from backend.models import EventType, LogEntry, LogSource

AUTH = [
    "Jun 14 15:16:01 bastion sshd[1]: Failed password for root from 203.0.113.7 port 1001 ssh2",
    "Jun 14 15:16:02 bastion sshd[1]: Failed password for root from 203.0.113.7 port 1002 ssh2",
    "Jun 14 15:16:03 bastion sshd[1]: Accepted password for root from 203.0.113.7 port 1003 ssh2",
    "Jun 14 15:16:09 bastion sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls",
]
WEB = ['198.51.100.9 - - [14/Jun/2026:15:16:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8"']


def test_normalize_is_pure_and_keeps_unparsed_lines(no_db):
    entries, errors = ingestion.normalize(AUTH + ["", "   ", "garbage line\n"], "linux_auth")
    assert len(entries) == 5 and errors == 1
    assert all(isinstance(e, LogEntry) for e in entries)
    bad = entries[-1]
    assert bad.event_type == EventType.UNKNOWN and bad.extra == {"parse_error": True}
    assert bad.raw == "garbage line" and bad.log_source == LogSource.LINUX_AUTH


def test_normalize_zeek_skips_headers_but_uses_fields(no_db):
    lines = ["#separator \\x09", "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery",
             "1781450161.1\tC1\t10.0.0.5\t4000\t10.0.0.2\t53\tudp\texample.com", "#close 2026-06-14"]
    entries, errors = ingestion.normalize(lines, LogSource.ZEEK)
    assert errors == 0 and len(entries) == 1 and entries[0].event_type == EventType.DNS_QUERY


def test_ingest_batch_stores_unified_schema(db):
    result = ingestion.ingest_batch(AUTH, "linux_auth")
    assert result["stored"] and result["count"] == 4 and result["parse_errors"] == 0
    assert result["sha256"] == utils.sha256_batch(AUTH)
    assert db.logs.count_documents({}) == 4 and db.log_batches.count_documents({}) == 1

    doc = db.logs.find_one({"batch_seq": 0})
    contract = {"timestamp", "source_ip", "username", "event_type", "log_source", "message", "raw"}
    assert contract <= set(doc) and isinstance(doc["_id"], str)
    assert doc["event_type"] == "login_failed" and doc["log_source"] == "linux_auth"
    assert doc["batch_id"] == result["batch_id"] and doc["raw"] == AUTH[0]

    batch = db.log_batches.find_one({"_id": result["batch_id"]})
    assert batch["sha256"] == result["sha256"] and batch["count"] == 4 and batch["log_source"] == "linux_auth"


def test_ingest_without_database_reports_not_stored(no_db):
    result = ingestion.ingest_batch(AUTH, "linux_auth")
    assert result["stored"] is False and result["count"] == 4 and result["sha256"]
    assert ingestion.ingest_log(AUTH[0], "linux_auth") is False
    assert ingestion.get_logs() == [] and ingestion.get_log_count() == 0
    assert ingestion.get_security_logs() == [] and ingestion.top_source_ips() == []
    assert ingestion.clear_logs() == 0
    assert ingestion.verify_batch("x")["valid"] is False


def test_empty_batch_stores_nothing(db):
    result = ingestion.ingest_batch(["", "\n"], "web")
    assert result == {"batch_id": None, "sha256": None, "count": 0, "parse_errors": 0, "stored": False}
    assert db.log_batches.count_documents({}) == 0


def test_ingest_log_journald_default(db):
    line = json.dumps({"__REALTIME_TIMESTAMP": "1781450161000000", "_HOSTNAME": "kali", "_COMM": "sudo",
                       "SYSLOG_IDENTIFIER": "sudo",
                       "MESSAGE": "  casper : TTY=pts/0 ; PWD=/home/casper ; USER=root ; COMMAND=/usr/bin/id"})
    assert ingestion.ingest_log(line) is True
    doc = db.logs.find_one()
    assert doc["log_source"] == "linux_auth" and doc["event_type"] == "sudo_command" and doc["username"] == "casper"
    assert ingestion.ingest_log("not json at all") is True  # kept as an unknown entry
    assert db.logs.count_documents({"extra.parse_error": True}) == 1


def test_verify_batch_detects_tampering(db):
    batch_id = ingestion.ingest_batch(AUTH, "linux_auth")["batch_id"]
    assert ingestion.verify_batch(batch_id)["valid"] is True

    db.logs.update_one({"batch_id": batch_id, "batch_seq": 1}, {"$set": {"raw": AUTH[1].replace("root", "nobody")}})
    result = ingestion.verify_batch(batch_id)
    assert result["valid"] is False and result["reason"] == "hash mismatch"

    other = ingestion.ingest_batch(AUTH, "linux_auth")["batch_id"]
    db.logs.delete_one({"batch_id": other, "batch_seq": 3})
    result = ingestion.verify_batch(other)
    assert result["valid"] is False and result["reason"] == "count mismatch" and result["actual_count"] == 3

    assert ingestion.verify_batch("missing")["reason"] == "batch not found"


def test_ingest_file_batches_and_cloudtrail_records_wrapper(db, tmp_path):
    auth_file = tmp_path / "linux_auth.log"
    auth_file.write_text("\n".join(AUTH * 3) + "\n")
    results = ingestion.ingest_file(auth_file, "linux_auth", batch_size=5)
    assert [r["count"] for r in results] == [5, 5, 2]
    assert all(ingestion.verify_batch(r["batch_id"])["valid"] for r in results)

    trail = tmp_path / "trail.json"
    trail.write_text(json.dumps({"Records": [
        {"eventTime": "2026-06-14T15:16:01Z", "eventName": "CreateUser", "sourceIPAddress": "203.0.113.7",
         "userIdentity": {"userName": "carol"}}]}, indent=2))
    (result,) = ingestion.ingest_file(trail, "cloudtrail")
    assert result["count"] == 1 and result["parse_errors"] == 0
    assert db.logs.count_documents({"event_type": "account_created"}) == 1


def test_retrieval_filters_and_api_shape(db):
    ingestion.ingest_batch(AUTH, "linux_auth")
    ingestion.ingest_batch(WEB, "web")
    assert ingestion.get_log_count() == 5

    logs = ingestion.get_logs()
    assert len(logs) == 5 and "id" in logs[0] and "_id" not in logs[0]
    assert logs[0]["timestamp"] > logs[-1]["timestamp"]  # most recent first, ISO strings
    json.dumps(logs)  # must be JSON serializable for the API

    assert len(ingestion.get_logs(log_source="web")) == 1
    assert len(ingestion.get_logs(event_type="login_failed")) == 2
    assert len(ingestion.get_logs(source_ip="203.0.113.7")) == 3
    assert len(ingestion.get_logs(username="bob")) == 1
    assert len(ingestion.get_logs(search="failed PASSWORD")) == 2
    assert ingestion.get_logs(search=".*") == []  # search text is not a regex
    assert ingestion.get_log_count(log_source="linux_auth", event_type="login_success") == 1
    assert len(ingestion.get_logs(limit=2)) == 2 and len(ingestion.get_logs(limit=10, offset=4)) == 1

    assert {log["event_type"] for log in ingestion.get_security_logs()} == {"login_failed", "login_success", "sudo_command"}
    assert len(ingestion.filter_logs_by_service("ssh")) == 3
    assert len(ingestion.filter_logs_by_command("sudo")) == 1


def test_aggregations_and_clear(db):
    ingestion.ingest_batch(AUTH, "linux_auth")
    ingestion.ingest_batch(WEB, "web")
    assert ingestion.count_by_event_type()[0] == {"value": "login_failed", "count": 2}
    assert ingestion.top_source_ips() == [{"value": "203.0.113.7", "count": 3}, {"value": "198.51.100.9", "count": 1}]
    assert ingestion.top_source_ips(limit=1) == [{"value": "203.0.113.7", "count": 3}]
    assert {row["value"]: row["count"] for row in ingestion.count_by_log_source()} == {"linux_auth": 4, "web": 1}
    assert ingestion.clear_logs() == 5
    assert ingestion.get_log_count() == 0 and db.log_batches.count_documents({}) == 0


def test_log_batcher_flushes_on_size_age_and_close(db):
    batcher = ingestion.LogBatcher("linux_auth", max_size=3, max_age=0.3)
    for line in AUTH:  # 4 lines: one full batch of 3 right away, 1 left in the buffer
        batcher.add(line)
    assert db.logs.count_documents({}) == 3
    deadline = time.time() + 3
    while db.logs.count_documents({}) < 4 and time.time() < deadline:
        time.sleep(0.05)
    assert db.logs.count_documents({}) == 4  # flushed by age without a new line arriving
    batcher.add(AUTH[0])
    batcher.close()
    assert db.logs.count_documents({}) == 5 and db.log_batches.count_documents({}) == 3
    assert batcher.flush() is None


def test_database_retries_after_cooldown(monkeypatch):
    from backend import dataBase as database
    database.reset_connection()
    monkeypatch.setattr(database, "MONGO_URI", "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200")
    assert database.get_db() is None            # connection refused
    monkeypatch.setattr(database, "MongoClient", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no retry yet")))
    assert database.get_db() is None            # inside the cooldown: no new attempt
    import mongomock
    monkeypatch.setattr(database, "RETRY_SECONDS", 0)
    monkeypatch.setattr(database, "MongoClient", lambda *a, **k: mongomock.MongoClient())
    assert database.get_db() is not None        # MongoDB came back
    database.reset_connection()
