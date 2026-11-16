"""
Database Module
Single place for the MongoDB connection and collection handles.

The connection is lazy: nothing is opened at import time, so parsers and tests
can be used without a running MongoDB. Tests inject a fake database with set_db().
"""

import os
import time
from typing import Optional

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "soc_dashboard")

LOGS_COLLECTION = "logs"
BATCHES_COLLECTION = "log_batches"
ALERTS_COLLECTION = "alerts"

_client: Optional[MongoClient] = None
_db = None
_failed_at: Optional[float] = None
RETRY_SECONDS = 10  # wait before trying an unreachable MongoDB again


def _ensure_indexes(db) -> None:
    logs = db[LOGS_COLLECTION]
    logs.create_index([("timestamp", DESCENDING)])
    logs.create_index([("log_source", ASCENDING), ("timestamp", DESCENDING)])
    logs.create_index([("event_type", ASCENDING), ("timestamp", DESCENDING)])
    logs.create_index([("source_ip", ASCENDING), ("timestamp", DESCENDING)])
    logs.create_index([("username", ASCENDING), ("timestamp", DESCENDING)])
    logs.create_index([("batch_id", ASCENDING), ("batch_seq", ASCENDING)])
    db[BATCHES_COLLECTION].create_index([("created_at", DESCENDING)])
    db[ALERTS_COLLECTION].create_index([("timestamp", DESCENDING)])


def get_db():
    """Return the database handle, or None when MongoDB is unreachable."""
    global _client, _db, _failed_at
    if _db is not None:
        return _db
    if _failed_at is not None and time.monotonic() - _failed_at < RETRY_SECONDS:
        return None
    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000, tz_aware=True)
        _client.admin.command("ping")
        _db = _client[MONGO_DB]
        _ensure_indexes(_db)
        _failed_at = None
        print(f"✓ Connected to MongoDB: {MONGO_URI}")
    except PyMongoError as e:
        print(f"✗ Failed to connect to MongoDB: {e}")
        _failed_at = time.monotonic()
        _db = None
    return _db


def set_db(db) -> None:
    """Inject a database handle (used by tests with mongomock)."""
    global _db, _failed_at
    _db = db
    _failed_at = None
    if db is not None:
        _ensure_indexes(db)


def reset_connection() -> None:
    """Forget the cached connection so the next get_db() retries."""
    global _client, _db, _failed_at
    if _client is not None:
        _client.close()
    _client = None
    _db = None
    _failed_at = None


def get_collection(name: str):
    db = get_db()
    return None if db is None else db[name]


def is_connected() -> bool:
    return get_db() is not None
