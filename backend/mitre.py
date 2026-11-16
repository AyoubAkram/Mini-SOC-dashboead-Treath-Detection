"""
MITRE ATT&CK mapping

Tags alerts with an ATT&CK tactic and technique, builds the coverage matrix and
turns the alerts of one entity into an ordered attack story.

This is a provisional mapping for the event-based alerts and the ML alerts.
Detection rules should set mitre_technique / mitre_tactic themselves; anything
already tagged is left as it is.
"""

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from . import utils
except ImportError:  # running with backend/ on sys.path (python backend/main.py)
    import utils

# Enterprise tactics in kill-chain order
TACTICS: List[Tuple[str, str]] = [
    ("TA0043", "Reconnaissance"), ("TA0042", "Resource Development"), ("TA0001", "Initial Access"),
    ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
TACTIC_ORDER = {name: index for index, (_, name) in enumerate(TACTICS)}

# technique id -> (name, tactic). Techniques that belong to several tactics are
# listed under the one that matches how they are detected here.
TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1136": ("Create Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1548.003": ("Abuse Elevation Control: Sudo", "Privilege Escalation"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1071.001": ("Application Layer Protocol: Web", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
}

EVENT_TECHNIQUES = {
    "login_failed": "T1110", "invalid_user": "T1110", "account_locked": "T1110",
    "account_created": "T1136", "privilege_assigned": "T1098", "sudo_failed": "T1548.003",
    "explicit_credential_logon": "T1021",
}

# ML feature that explains an anomaly -> technique
FEATURE_TECHNIQUES = {
    "login_failed": "T1110", "fail_ratio": "T1110", "distinct_users": "T1110",
    "distinct_dest_ports": "T1046", "firewall_drops": "T1046", "distinct_dest_ips": "T1046",
    "http_requests": "T1190", "http_error_ratio": "T1190",
    "dns_queries": "T1071.004", "avg_dns_length": "T1071.004",
    "conn_regularity": "T1071.001", "bytes_out": "T1041", "distinct_hosts": "T1021",
    "privileged_events": "T1098", "sudo_failed": "T1548.003",
}

# IDS signature keyword -> technique (first match wins)
SIGNATURE_TECHNIQUES = [
    ("sql injection", "T1190"), ("sqli", "T1190"), ("web_server", "T1190"), ("exploit", "T1190"),
    ("ssh scan", "T1110"), ("brute", "T1110"),
    ("scan", "T1595"), ("nmap", "T1595"),
    ("dns", "T1071.004"), ("trojan", "T1071.001"), ("c2", "T1071.001"), ("cnc", "T1071.001"),
]

# Which detection can raise each technique today (for the coverage matrix)
RULE_TECHNIQUES = set(EVENT_TECHNIQUES.values()) | {technique for _, technique in SIGNATURE_TECHNIQUES}
ML_TECHNIQUES = set(FEATURE_TECHNIQUES.values()) | {"T1595"}


def describe(technique: Optional[str]) -> Dict[str, Optional[str]]:
    if technique not in TECHNIQUES:
        return {"mitre_technique": None, "mitre_tactic": None, "mitre_name": None}
    name, tactic = TECHNIQUES[technique]
    return {"mitre_technique": technique, "mitre_tactic": tactic, "mitre_name": name}


def technique_for_signature(message: Optional[str]) -> Optional[str]:
    text = (message or "").lower()
    for keyword, technique in SIGNATURE_TECHNIQUES:
        if keyword in text:
            return technique
    return None


def technique_for_event(log: Dict[str, Any]) -> Optional[str]:
    """Technique for a log shown as an alert."""
    if log.get("event_type") == "ids_alert":
        return technique_for_signature(log.get("message"))
    return EVENT_TECHNIQUES.get(log.get("event_type"))


def technique_for_anomaly(explanation: Iterable[Dict[str, Any]], entity: Optional[str] = None) -> Optional[str]:
    """Technique for an ML alert, from the feature that explains it best."""
    for reason in explanation:
        technique = FEATURE_TECHNIQUES.get(reason.get("feature"))
        if technique == "T1046" and entity and not utils.is_private_ip(entity):
            return "T1595"  # scanning from outside the network is reconnaissance
        if technique:
            return technique
    return None


def build_matrix(rule_counts: Dict[str, int], ml_counts: Dict[str, int]) -> List[Dict[str, Any]]:
    """
    Coverage matrix: every tactic with the techniques that can be detected, how
    (rules / ml) and how many alerts each produced.
    """
    matrix = []
    for tactic_id, tactic in TACTICS:
        techniques = []
        for technique, (name, owner) in TECHNIQUES.items():
            if owner != tactic:
                continue
            techniques.append({
                "id": technique, "name": name,
                "rules": technique in RULE_TECHNIQUES, "ml": technique in ML_TECHNIQUES,
                "rule_alerts": rule_counts.get(technique, 0), "ml_alerts": ml_counts.get(technique, 0),
            })
        matrix.append({"id": tactic_id, "name": tactic, "techniques": techniques,
                       "alerts": sum(t["rule_alerts"] + t["ml_alerts"] for t in techniques)})
    return matrix


def _time(value) -> datetime:
    return utils.to_utc(value if isinstance(value, datetime) else utils.parse_iso_timestamp(value))


def build_story(events: Iterable[Dict[str, Any]], gap_minutes: float = 30) -> Dict[str, Any]:
    """
    Turn tagged alerts into an attack story: stages in time order, where a stage
    is a run of alerts with the same technique (a pause longer than gap_minutes
    starts a new stage).

    Each event needs: timestamp, mitre_technique, detection ('rule' or 'ml'),
    severity, description. Untagged events are ignored.
    """
    tagged = sorted((e for e in events if e.get("mitre_technique") in TECHNIQUES),
                    key=lambda e: _time(e["timestamp"]))
    stages: List[Dict[str, Any]] = []
    rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    for event in tagged:
        when, technique = _time(event["timestamp"]), event["mitre_technique"]
        severity = str(event.get("severity", "low")).lower()
        last = stages[-1] if stages else None
        if (last and last["technique"] == technique
                and (when - last["last_seen"]).total_seconds() <= gap_minutes * 60):
            last["count"] += 1
            last["last_seen"] = when
            if event.get("detection") not in last["detections"]:
                last["detections"].append(event.get("detection"))
            if rank.get(severity, 0) > rank.get(last["severity"], 0):
                last["severity"] = severity
            continue
        name, tactic = TECHNIQUES[technique]
        stages.append({"technique": technique, "name": name, "tactic": tactic, "count": 1,
                       "first_seen": when, "last_seen": when, "severity": severity,
                       "detections": [event.get("detection")],
                       "example": event.get("description", "")})
    tactics = sorted({stage["tactic"] for stage in stages}, key=TACTIC_ORDER.get)
    return {"stages": stages, "tactics": tactics, "alerts": len(tagged),
            "first_seen": stages[0]["first_seen"] if stages else None,
            "last_seen": max((s["last_seen"] for s in stages), default=None)}
