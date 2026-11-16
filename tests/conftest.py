"""Shared pytest fixtures. MongoDB is replaced by an in-memory mongomock database."""

import sys
from pathlib import Path

import mongomock
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import database  # noqa: E402


@pytest.fixture
def db():
    """Fresh in-memory database injected into backend.database."""
    mock_db = mongomock.MongoClient().soc_test
    database.set_db(mock_db)
    yield mock_db
    database.set_db(None)
    database.reset_connection()


@pytest.fixture
def no_db(monkeypatch):
    """Simulate an unreachable MongoDB."""
    monkeypatch.setattr(database, "get_db", lambda: None)
