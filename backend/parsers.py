"""
Log Parsers
One parser per log source. Every parser takes a single raw line and returns a
LogEntry in the unified schema, or None when the line is not recognised.

Sources: Linux auth.log, Windows Event Logs (JSON), iptables firewall,
Snort / Suricata IDS, Apache / Nginx web logs, AWS CloudTrail, Zeek, Syslog
(RFC 5424 with RFC 3164 fallback). journald JSON is also supported because the
journalctl collector produces it.
"""

import json
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from .models import EventType, LogEntry, LogSource
    from . import utils
except ImportError:  # running with backend/ on sys.path (python backend/main.py)
    from models import EventType, LogEntry, LogSource
    import utils


# ---------------------------------------------------------------------------
# Shared pieces
# ---------------------------------------------------------------------------

_TS_BSD = r"[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
_TS_ISO = r"\d{4}-\d{2}-\d{2}T\S+"

# "Jun 14 15:16:01 host process[pid]: message" (timestamp may also be ISO 8601)
_SYSLOG_HEADER = re.compile(
    rf"^(?:<(?P<pri>\d{{1,3}})>)?(?P<ts>{_TS_BSD}|{_TS_ISO})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

AUTH_PROCESSES = {"sshd", "sudo", "su", "login", "useradd", "adduser", "systemd-logind", "passwd"}


def _parse_header_timestamp(text: str) -> datetime:
    if text[0].isdigit():
        return utils.parse_iso_timestamp(text)
    return utils.parse_bsd_timestamp(text)


def _load_json(line: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _split_endpoint(value: str) -> Tuple[Optional[str], Optional[int]]:
    """Split 'ip:port' (or a bare ip) into its parts."""
    ip = utils.clean_ip(value)
    if ip:
        return ip, None
    head, _, tail = value.rpartition(":")
    return utils.clean_ip(head), utils.to_int(tail)


# ---------------------------------------------------------------------------
# 1. Linux auth.log
# ---------------------------------------------------------------------------

_SSH_FAILED = re.compile(
    r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_PAM_SESSION = re.compile(
    r"pam_unix\((?P<service>[^:)]+):session\): session (?P<state>opened|closed) "
    r"for user (?P<user>[^\s(]+)"
)
_PAM_AUTH_FAIL = re.compile(r"pam_unix\((?P<service>[^:)]+):auth\): authentication failure")
_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<fail>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$"
)
_NEW_USER = re.compile(r"new user: name=(?P<user>[^,\s]+)(?:, UID=(?P<uid>\d+))?")
_KV_USER = re.compile(r"(?<![a-z])user=(?P<user>\S+)")
_KV_RHOST = re.compile(r"rhost=(?P<ip>\S+)")
# "Received disconnect from 1.2.3.4 port 22", "Connection closed by [invalid user x] 1.2.3.4 port 22"
_FROM_IP = re.compile(
    r"\b(?:from|by)(?: (?:authenticating|invalid) user \S+)? (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
)


def classify_auth_message(process: str, msg: str) -> Dict[str, Any]:
    """
    Classify the message part of an authentication log line.
    Returns the normalized fields it could extract (event_type always present).
    """
    out: Dict[str, Any] = {"event_type": EventType.UNKNOWN, "extra": {}}

    m = _SSH_FAILED.search(msg)
    if m:
        out.update(event_type=EventType.LOGIN_FAILED, username=m["user"] or None,
                   source_ip=utils.clean_ip(m["ip"]), source_port=int(m["port"]))
        out["extra"] = {"auth_method": m["method"], "invalid_user": bool(m["invalid"])}
        return out

    m = _SSH_ACCEPTED.search(msg)
    if m:
        out.update(event_type=EventType.LOGIN_SUCCESS, username=m["user"],
                   source_ip=utils.clean_ip(m["ip"]), source_port=int(m["port"]))
        out["extra"] = {"auth_method": m["method"]}
        return out

    m = _SSH_INVALID.search(msg)
    if m:
        out.update(event_type=EventType.INVALID_USER, username=m["user"] or None,
                   source_ip=utils.clean_ip(m["ip"]), source_port=utils.to_int(m["port"]))
        return out

    m = _SUDO.match(msg)
    if m:
        failed = bool(m["fail"])
        out.update(event_type=EventType.SUDO_FAILED if failed else EventType.SUDO_COMMAND,
                   username=m["user"])
        out["extra"] = {"tty": m["tty"], "pwd": m["pwd"], "target_user": m["target"],
                        "command": m["cmd"]}
        if failed:
            out["extra"]["reason"] = m["fail"].strip()
        return out

    m = _PAM_SESSION.search(msg)
    if m:
        opened = m["state"] == "opened"
        out.update(event_type=EventType.SESSION_OPENED if opened else EventType.SESSION_CLOSED,
                   username=m["user"])
        out["extra"] = {"pam_service": m["service"]}
        return out

    m = _PAM_AUTH_FAIL.search(msg)
    if m:
        service = m["service"]
        user = _KV_USER.search(msg)
        rhost = _KV_RHOST.search(msg)
        out["username"] = user["user"] if user else None
        out["source_ip"] = utils.clean_ip(rhost["ip"]) if rhost else None
        out["extra"] = {"pam_service": service}
        if service == "sudo":
            out["event_type"] = EventType.SUDO_FAILED
        elif service != "sshd":
            # sshd already logs its own "Failed password" line for the same
            # attempt; counting the PAM line too would double every failure.
            out["event_type"] = EventType.LOGIN_FAILED
        return out

    m = _NEW_USER.search(msg)
    if m:
        out.update(event_type=EventType.ACCOUNT_CREATED, username=m["user"])
        if m["uid"]:
            out["extra"] = {"uid": int(m["uid"])}
        return out

    m = _FROM_IP.search(msg)
    if m:
        out.update(source_ip=utils.clean_ip(m["ip"]), source_port=utils.to_int(m["port"]))
    return out


def parse_linux_auth(line: str) -> Optional[LogEntry]:
    m = _SYSLOG_HEADER.match(line.strip())
    if not m:
        return None
    try:
        timestamp = _parse_header_timestamp(m["ts"])
    except (ValueError, KeyError):
        return None
    fields = classify_auth_message(m["proc"], m["msg"])
    extra = fields.pop("extra")
    if m["pid"]:
        extra["pid"] = int(m["pid"])
    return LogEntry(timestamp=timestamp, log_source=LogSource.LINUX_AUTH, host=m["host"],
                    process=m["proc"], message=m["msg"], raw=line, extra=extra, **fields)


# ---------------------------------------------------------------------------
# 2. Windows Event Logs (JSON export: flat Get-WinEvent style or winlogbeat)
# ---------------------------------------------------------------------------

WINDOWS_EVENTS = {
    4624: EventType.LOGIN_SUCCESS,
    4625: EventType.LOGIN_FAILED,
    4648: EventType.EXPLICIT_CREDENTIAL_LOGON,
    4672: EventType.PRIVILEGE_ASSIGNED,
    4720: EventType.ACCOUNT_CREATED,
    4740: EventType.ACCOUNT_LOCKED,
}
_WINDOWS_DESCRIPTIONS = {
    4624: "An account was successfully logged on",
    4625: "An account failed to log on",
    4648: "A logon was attempted using explicit credentials",
    4672: "Special privileges assigned to new logon",
    4720: "A user account was created",
    4740: "A user account was locked out",
}
# Events where the acting account (Subject) is the interesting user
_WINDOWS_SUBJECT_EVENTS = {4648, 4672}
_DOTNET_DATE = re.compile(r"/Date\((\d+)\)/")


def _windows_timestamp(value) -> datetime:
    m = _DOTNET_DATE.match(str(value))
    if m:
        return utils.parse_epoch(int(m[1]) / 1000)
    return utils.parse_any_timestamp(value)


def parse_windows_event(line: str) -> Optional[LogEntry]:
    data = _load_json(line)
    if data is None:
        return None

    winlog = data.get("winlog")
    if isinstance(winlog, dict):  # winlogbeat layout
        event_id = winlog.get("event_id")
        fields = winlog.get("event_data") or {}
        host = winlog.get("computer_name")
        ts_value = data.get("@timestamp")
    else:  # flat layout
        event_id = data.get("EventID", data.get("Id"))
        fields = data.get("EventData") if isinstance(data.get("EventData"), dict) else data
        host = data.get("Computer", data.get("MachineName"))
        ts_value = data.get("TimeCreated", data.get("@timestamp"))

    event_id = utils.to_int(event_id)
    if event_id is None or ts_value is None:
        return None
    try:
        timestamp = _windows_timestamp(ts_value)
    except (ValueError, TypeError, OverflowError):
        return None

    def clean(value):
        return None if value in (None, "", "-") else str(value)

    target = clean(fields.get("TargetUserName"))
    subject = clean(fields.get("SubjectUserName"))
    username = (subject or target) if event_id in _WINDOWS_SUBJECT_EVENTS else (target or subject)

    extra: Dict[str, Any] = {"event_id": event_id}
    for key, name in (("LogonType", "logon_type"), ("WorkstationName", "workstation"),
                      ("TargetDomainName", "domain"), ("Status", "status"),
                      ("PrivilegeList", "privileges"), ("TargetServerName", "target_server")):
        if clean(fields.get(key)) is not None:
            extra[name] = fields[key]
    if subject and subject != username:
        extra["subject_user"] = subject
    if target and target != username:
        extra["target_user"] = target

    description = _WINDOWS_DESCRIPTIONS.get(event_id, f"Windows event {event_id}")
    return LogEntry(
        timestamp=timestamp, log_source=LogSource.WINDOWS_EVENT,
        event_type=WINDOWS_EVENTS.get(event_id, EventType.UNKNOWN),
        source_ip=utils.clean_ip(fields.get("IpAddress")),
        source_port=utils.to_int(fields.get("IpPort")),
        username=username, host=clean(host),
        message=f"{event_id}: {description}", raw=line, extra=extra,
    )


# ---------------------------------------------------------------------------
# 3. iptables / UFW firewall
# ---------------------------------------------------------------------------

_KV = re.compile(r"\b([A-Z]+)=(\S*)")
_UPTIME = re.compile(r"^\[\s*\d+\.\d+\]\s*")
_DROP_WORDS = ("DROP", "DENY", "REJECT", "BLOCK")
_ACCEPT_WORDS = ("ACCEPT", "ALLOW")
_TCP_FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG")


def parse_firewall(line: str) -> Optional[LogEntry]:
    m = _SYSLOG_HEADER.match(line.strip())
    if not m:
        return None
    msg = _UPTIME.sub("", m["msg"])
    kv = dict(_KV.findall(msg))
    if "SRC" not in kv or "DST" not in kv:
        return None
    try:
        timestamp = _parse_header_timestamp(m["ts"])
    except (ValueError, KeyError):
        return None

    prefix = msg.split("IN=", 1)[0].strip().rstrip(":").strip()
    upper = prefix.upper()
    if any(word in upper for word in _DROP_WORDS):
        event_type = EventType.FIREWALL_DROP
    elif any(word in upper for word in _ACCEPT_WORDS):
        event_type = EventType.FIREWALL_ACCEPT
    else:
        event_type = EventType.UNKNOWN

    tail = msg.split("PROTO=", 1)[-1].split()
    extra: Dict[str, Any] = {"prefix": prefix, "in_interface": kv.get("IN") or None,
                             "out_interface": kv.get("OUT") or None,
                             "length": utils.to_int(kv.get("LEN")),
                             "ttl": utils.to_int(kv.get("TTL")),
                             "tcp_flags": [flag for flag in _TCP_FLAGS if flag in tail]}
    return LogEntry(
        timestamp=timestamp, log_source=LogSource.FIREWALL, event_type=event_type,
        source_ip=utils.clean_ip(kv["SRC"]), dest_ip=utils.clean_ip(kv["DST"]),
        source_port=utils.to_int(kv.get("SPT")), dest_port=utils.to_int(kv.get("DPT")),
        protocol=(kv.get("PROTO") or "").lower() or None,
        host=m["host"], process=m["proc"], message=msg, raw=line, extra=extra,
    )


# ---------------------------------------------------------------------------
# 4. IDS: Snort fast alerts and Suricata eve.json
# ---------------------------------------------------------------------------

_SNORT_FAST = re.compile(
    r"^(?P<ts>\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<cls>[^\]]*)\]\s+)?(?:\[Priority:\s*(?P<prio>\d+)\]\s+)?"
    r"\{(?P<proto>[^}]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)\s*$"
)


def _parse_suricata(data: Dict[str, Any], line: str) -> Optional[LogEntry]:
    if "timestamp" not in data:
        return None
    try:
        timestamp = utils.parse_iso_timestamp(data["timestamp"])
    except (ValueError, TypeError):
        return None
    alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    is_alert = data.get("event_type") == "alert"
    extra: Dict[str, Any] = {"eve_type": data.get("event_type")}
    if is_alert:
        extra.update(signature_id=alert.get("signature_id"), classification=alert.get("category"),
                     priority=alert.get("severity"), action=alert.get("action"))
    return LogEntry(
        timestamp=timestamp, log_source=LogSource.IDS,
        event_type=EventType.IDS_ALERT if is_alert else EventType.UNKNOWN,
        source_ip=utils.clean_ip(data.get("src_ip")), dest_ip=utils.clean_ip(data.get("dest_ip")),
        source_port=utils.to_int(data.get("src_port")), dest_port=utils.to_int(data.get("dest_port")),
        protocol=str(data["proto"]).lower() if data.get("proto") else None,
        host=data.get("host"), message=alert.get("signature") or str(data.get("event_type", "")),
        raw=line, extra=extra,
    )


def parse_ids(line: str) -> Optional[LogEntry]:
    stripped = line.strip()
    if stripped.startswith("{"):
        data = _load_json(stripped)
        return _parse_suricata(data, line) if data else None

    m = _SNORT_FAST.match(stripped)
    if not m:
        return None
    try:
        timestamp = utils.parse_snort_timestamp(m["ts"])
    except (ValueError, KeyError):
        return None
    source_ip, source_port = _split_endpoint(m["src"])
    dest_ip, dest_port = _split_endpoint(m["dst"])
    extra = {"signature_id": int(m["sid"]), "generator_id": int(m["gid"]), "revision": int(m["rev"]),
             "classification": m["cls"], "priority": utils.to_int(m["prio"])}
    return LogEntry(
        timestamp=timestamp, log_source=LogSource.IDS, event_type=EventType.IDS_ALERT,
        source_ip=source_ip, dest_ip=dest_ip, source_port=source_port, dest_port=dest_port,
        protocol=m["proto"].lower(), message=m["msg"], raw=line, extra=extra,
    )


# ---------------------------------------------------------------------------
# 5. Apache / Nginx (common and combined log format)
# ---------------------------------------------------------------------------

_WEB = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)


def parse_web(line: str) -> Optional[LogEntry]:
    m = _WEB.match(line.strip())
    if not m:
        return None
    try:
        timestamp = utils.parse_apache_timestamp(m["ts"])
    except ValueError:
        return None
    parts = m["req"].split(" ")
    if len(parts) == 3:
        method, path, http_version = parts
    else:  # malformed request line (scanners, TLS on a plain port, ...)
        method, path, http_version = None, m["req"], None
    extra = {"method": method, "path": path, "http_version": http_version,
             "status": int(m["status"]), "bytes": utils.to_int(m["size"]) or 0,
             "referrer": None if m["ref"] in (None, "-") else m["ref"],
             "user_agent": None if m["ua"] in (None, "-") else m["ua"]}
    return LogEntry(
        timestamp=timestamp, log_source=LogSource.WEB, event_type=EventType.HTTP_REQUEST,
        source_ip=utils.clean_ip(m["ip"]), username=None if m["user"] == "-" else m["user"],
        message=f'{m["req"]} -> {m["status"]}', raw=line, extra=extra,
    )


# ---------------------------------------------------------------------------
# 6. AWS CloudTrail (one JSON record per line)
# ---------------------------------------------------------------------------

_CLOUDTRAIL_PRIVILEGE_EVENTS = {
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy",
    "PutRolePolicy", "AddUserToGroup", "CreateAccessKey", "UpdateAssumeRolePolicy",
}


def parse_cloudtrail(line: str) -> Optional[LogEntry]:
    data = _load_json(line)
    if data is None or "eventName" not in data or "eventTime" not in data:
        return None
    try:
        timestamp = utils.parse_iso_timestamp(data["eventTime"])
    except (ValueError, TypeError):
        return None

    identity = data.get("userIdentity") or {}
    username = identity.get("userName")
    if not username and identity.get("arn"):
        username = str(identity["arn"]).rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    if not username:
        username = identity.get("type")

    event_name = data["eventName"]
    response = data.get("responseElements") or {}
    params = data.get("requestParameters") or {}
    error = data.get("errorCode")

    if event_name == "ConsoleLogin":
        failed = response.get("ConsoleLogin") == "Failure" or bool(error)
        event_type = EventType.LOGIN_FAILED if failed else EventType.LOGIN_SUCCESS
    elif event_name == "CreateUser":
        event_type = EventType.ACCOUNT_CREATED
    elif event_name in _CLOUDTRAIL_PRIVILEGE_EVENTS:
        event_type = EventType.PRIVILEGE_ASSIGNED
    else:
        event_type = EventType.CLOUD_API_CALL

    extra = {"event_name": event_name, "event_source": data.get("eventSource"),
             "aws_region": data.get("awsRegion"), "error_code": error,
             "user_agent": data.get("userAgent"), "identity_type": identity.get("type"),
             "request_parameters": params or None}
    if params.get("userName") and params["userName"] != username:
        extra["target_user"] = params["userName"]

    message = f'{data.get("eventSource", "aws")}:{event_name}'
    if error:
        message += f" ({error})"
    return LogEntry(
        timestamp=timestamp, log_source=LogSource.CLOUDTRAIL, event_type=event_type,
        source_ip=utils.clean_ip(data.get("sourceIPAddress")), username=username,
        host=data.get("recipientAccountId"), message=message, raw=line, extra=extra,
    )


# ---------------------------------------------------------------------------
# 7. Zeek (JSON logs, or TSV with a '#fields' header)
# ---------------------------------------------------------------------------

ZEEK_CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
    "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
    "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
]
# TSV logs describe their columns in a '#fields' header line. The last header
# seen is remembered so the following data lines can be decoded, which means
# TSV files must be parsed one at a time (JSON logs have no such limit).
_zeek_fields: List[str] = list(ZEEK_CONN_FIELDS)


def _zeek_number(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_zeek(line: str) -> Optional[LogEntry]:
    global _zeek_fields
    stripped = line.rstrip("\r\n")
    if stripped.startswith("#"):
        if stripped.startswith("#fields"):
            _zeek_fields = stripped.split("\t")[1:]
        return None

    if stripped.lstrip().startswith("{"):
        data = _load_json(stripped)
        if data is None:
            return None
    else:
        values = stripped.split("\t")
        if len(values) < 6 or len(values) != len(_zeek_fields):
            return None
        data = {k: (None if v in ("-", "(empty)") else v) for k, v in zip(_zeek_fields, values)}

    if data.get("ts") is None or data.get("id.orig_h") is None:
        return None
    try:
        timestamp = utils.parse_any_timestamp(data["ts"])
    except (ValueError, TypeError, OverflowError):
        return None

    extra: Dict[str, Any] = {"uid": data.get("uid")}
    if data.get("query") is not None:
        event_type = EventType.DNS_QUERY
        message = f'DNS {data.get("qtype_name") or "query"} {data["query"]}'
        extra.update(query=data["query"], qtype=data.get("qtype_name"),
                     rcode=data.get("rcode_name"), answers=data.get("answers"))
    elif data.get("method") is not None and data.get("uri") is not None:
        event_type = EventType.HTTP_REQUEST
        message = f'{data["method"]} {data.get("host") or ""}{data["uri"]}'
        extra.update(method=data["method"], path=data["uri"], http_host=data.get("host"),
                     status=utils.to_int(data.get("status_code")),
                     user_agent=data.get("user_agent"))
    else:
        event_type = EventType.NETWORK_CONNECTION
        message = (f'{data.get("proto") or "conn"} {data["id.orig_h"]} -> '
                   f'{data.get("id.resp_h")}:{data.get("id.resp_p")} '
                   f'{data.get("conn_state") or ""}').strip()
        extra.update(service=data.get("service"), duration=_zeek_number(data.get("duration")),
                     orig_bytes=utils.to_int(data.get("orig_bytes")),
                     resp_bytes=utils.to_int(data.get("resp_bytes")),
                     conn_state=data.get("conn_state"))

    return LogEntry(
        timestamp=timestamp, log_source=LogSource.ZEEK, event_type=event_type,
        source_ip=utils.clean_ip(data["id.orig_h"]), dest_ip=utils.clean_ip(data.get("id.resp_h")),
        source_port=utils.to_int(data.get("id.orig_p")), dest_port=utils.to_int(data.get("id.resp_p")),
        protocol=data.get("proto"), message=message, raw=line, extra=extra,
    )


# ---------------------------------------------------------------------------
# 8. Syslog (RFC 5424, falling back to RFC 3164 / BSD)
# ---------------------------------------------------------------------------

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$",
    re.DOTALL,
)
_FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
               "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
               "local3", "local4", "local5", "local6", "local7"]
_SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def _nil(value: Optional[str]) -> Optional[str]:
    return None if value in (None, "-") else value


def _decode_pri(pri: Optional[str]) -> Dict[str, Any]:
    value = utils.to_int(pri)
    if value is None or not 0 <= value <= 191:
        return {}
    return {"facility": _FACILITIES[value >> 3], "severity": _SEVERITIES[value & 7]}


def _syslog_entry(line: str, timestamp: datetime, host: Optional[str], app: Optional[str],
                  msg: str, extra: Dict[str, Any]) -> LogEntry:
    fields: Dict[str, Any] = {"event_type": EventType.SYSLOG_MESSAGE}
    if app in AUTH_PROCESSES:
        # Authentication daemons forwarded over syslog keep their meaning
        auth = classify_auth_message(app, msg)
        auth_extra = auth.pop("extra")
        if auth["event_type"] != EventType.UNKNOWN:
            fields = auth
            extra.update(auth_extra)
        else:
            fields.update({k: v for k, v in auth.items() if k != "event_type"})
    return LogEntry(timestamp=timestamp, log_source=LogSource.SYSLOG, host=host, process=app,
                    message=msg, raw=line, extra=extra, **fields)


def parse_syslog(line: str) -> Optional[LogEntry]:
    stripped = line.strip()
    m = _RFC5424.match(stripped)
    if m:
        try:
            timestamp = utils.parse_iso_timestamp(m["ts"])
        except ValueError:
            return None
        extra = _decode_pri(m["pri"])
        extra["format"] = "rfc5424"
        if _nil(m["msgid"]):
            extra["msgid"] = m["msgid"]
        if _nil(m["procid"]):
            extra["pid"] = utils.to_int(m["procid"]) or m["procid"]
        if _nil(m["sd"]):
            extra["structured_data"] = m["sd"]
        msg = (m["msg"] or "").lstrip("\ufeff")
        return _syslog_entry(line, timestamp, _nil(m["host"]), _nil(m["app"]), msg, extra)

    m = _SYSLOG_HEADER.match(stripped)
    if not m:
        return None
    try:
        timestamp = _parse_header_timestamp(m["ts"])
    except (ValueError, KeyError):
        return None
    extra = _decode_pri(m["pri"])
    extra["format"] = "rfc3164"
    if m["pid"]:
        extra["pid"] = int(m["pid"])
    return _syslog_entry(line, timestamp, m["host"], m["proc"], m["msg"], extra)


# ---------------------------------------------------------------------------
# journald JSON (journalctl -o json), produced by collector/journalLogs.py
# ---------------------------------------------------------------------------

def parse_journald(line: str) -> Optional[LogEntry]:
    data = _load_json(line)
    if data is None or "MESSAGE" not in data:
        return None
    try:
        timestamp = utils.parse_epoch(int(data["__REALTIME_TIMESTAMP"]) / 1_000_000)
    except (KeyError, ValueError, TypeError):
        timestamp = utils.utcnow()

    message = data["MESSAGE"]
    if isinstance(message, list):  # journald encodes non-UTF-8 messages as byte arrays
        message = bytes(b for b in message if isinstance(b, int)).decode("utf-8", errors="replace")
    message = "" if message is None else str(message)

    process = data.get("SYSLOG_IDENTIFIER") or data.get("_COMM")
    extra: Dict[str, Any] = {"journald": True, "unit": data.get("_SYSTEMD_UNIT"),
                             "pid": utils.to_int(data.get("_PID"))}
    priority = utils.to_int(data.get("PRIORITY"))
    if priority is not None and 0 <= priority <= 7:
        extra["severity"] = _SEVERITIES[priority]

    if process in AUTH_PROCESSES:
        fields = classify_auth_message(process, message)
        extra.update(fields.pop("extra"))
        log_source = LogSource.LINUX_AUTH
    else:
        fields = {"event_type": EventType.SYSLOG_MESSAGE}
        log_source = LogSource.SYSLOG
    return LogEntry(timestamp=timestamp, log_source=log_source, host=data.get("_HOSTNAME"),
                    process=process, message=message, raw=line, extra=extra, **fields)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PARSERS: Dict[LogSource, Callable[[str], Optional[LogEntry]]] = {
    LogSource.LINUX_AUTH: parse_linux_auth,
    LogSource.WINDOWS_EVENT: parse_windows_event,
    LogSource.FIREWALL: parse_firewall,
    LogSource.IDS: parse_ids,
    LogSource.WEB: parse_web,
    LogSource.CLOUDTRAIL: parse_cloudtrail,
    LogSource.ZEEK: parse_zeek,
    LogSource.SYSLOG: parse_syslog,
}


def parse_line(log_source, line: str) -> Optional[LogEntry]:
    """Parse one raw line from the given source into the unified schema."""
    return PARSERS[LogSource(log_source)](line)


def is_ignorable(log_source, line: str) -> bool:
    """Lines that carry no event (blank lines, Zeek '#' header lines)."""
    if not line.strip():
        return True
    return LogSource(log_source) == LogSource.ZEEK and line.startswith("#")


def split_records(log_source, text: str) -> List[str]:
    """
    Split the content of a log file into one raw record per item.
    Handles line-based logs, JSON arrays and the CloudTrail {"Records": [...]} wrapper.
    """
    stripped = text.lstrip()
    if LogSource(log_source) in (LogSource.CLOUDTRAIL, LogSource.WINDOWS_EVENT) and stripped[:1] in ("{", "["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None  # JSON Lines: fall through to line splitting
        if isinstance(data, dict) and isinstance(data.get("Records"), list):
            data = data["Records"]
        if isinstance(data, list):
            return [json.dumps(record, separators=(",", ":")) for record in data]
    return text.splitlines()
