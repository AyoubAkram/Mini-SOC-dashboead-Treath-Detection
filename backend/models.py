"""
Data Models
Shared schema for the ARGUS pipeline (see API contract in the project summary).

LogEntry is the unified, ECS-inspired schema every parser normalizes to.
Alert is the shared model used by both rule-based and ML detection.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class LogSource(str, Enum):
    LINUX_AUTH = "linux_auth"
    WINDOWS_EVENT = "windows_event"
    FIREWALL = "firewall"
    IDS = "ids"
    WEB = "web"
    CLOUDTRAIL = "cloudtrail"
    ZEEK = "zeek"
    SYSLOG = "syslog"


class EventType(str, Enum):
    """Normalized event vocabulary shared by all parsers and detection rules."""
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    INVALID_USER = "invalid_user"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    SUDO_COMMAND = "sudo_command"
    SUDO_FAILED = "sudo_failed"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_LOCKED = "account_locked"
    PRIVILEGE_ASSIGNED = "privilege_assigned"
    EXPLICIT_CREDENTIAL_LOGON = "explicit_credential_logon"
    FIREWALL_DROP = "firewall_drop"
    FIREWALL_ACCEPT = "firewall_accept"
    IDS_ALERT = "ids_alert"
    HTTP_REQUEST = "http_request"
    CLOUD_API_CALL = "cloud_api_call"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    SYSLOG_MESSAGE = "syslog_message"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionType(str, Enum):
    RULE_BASED = "rule-based"
    ML_DETECTED = "ml-detected"


def _new_id() -> str:
    return uuid4().hex


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LogEntry(BaseModel):
    """Unified log schema. The first eight fields are the agreed API contract."""
    id: str = Field(default_factory=_new_id)
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: EventType = EventType.UNKNOWN
    log_source: LogSource
    message: str = ""
    raw: str = ""

    # ECS-inspired optional fields
    host: Optional[str] = None
    process: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    # Source-specific fields that do not fit the common schema
    extra: Dict[str, Any] = Field(default_factory=dict)

    # Set by the ingestion pipeline
    batch_id: Optional[str] = None
    batch_seq: Optional[int] = None
    ingested_at: Optional[datetime] = None

    def to_document(self) -> Dict[str, Any]:
        """Convert to a MongoDB document (id becomes _id)."""
        doc = self.model_dump(mode="python")
        doc["_id"] = doc.pop("id")
        doc["event_type"] = self.event_type.value
        doc["log_source"] = self.log_source.value
        return doc


class LogBatch(BaseModel):
    """Integrity record: SHA-256 over the raw lines of one ingested batch."""
    id: str = Field(default_factory=_new_id)
    log_source: LogSource
    sha256: str
    count: int
    parse_errors: int = 0
    created_at: datetime = Field(default_factory=_utcnow)

    def to_document(self) -> Dict[str, Any]:
        doc = self.model_dump(mode="python")
        doc["_id"] = doc.pop("id")
        doc["log_source"] = self.log_source.value
        return doc


class Alert(BaseModel):
    """Shared alert model (API contract)."""
    id: str = Field(default_factory=_new_id)
    timestamp: datetime = Field(default_factory=_utcnow)
    source_ip: Optional[str] = None
    rule_name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    detection_type: DetectionType = DetectionType.RULE_BASED
    anomaly_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    resolved: bool = False

    def to_document(self) -> Dict[str, Any]:
        doc = self.model_dump(mode="python")
        doc["_id"] = doc.pop("id")
        doc["severity"] = self.severity.value
        doc["detection_type"] = self.detection_type.value
        return doc


def document_to_api(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a MongoDB document back to the API shape (_id becomes id)."""
    out = dict(doc)
    if "_id" in out:
        out["id"] = str(out.pop("_id"))
    for key, value in list(out.items()):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            out[key] = value.isoformat()
    return out
