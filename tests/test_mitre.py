"""MITRE ATT&CK tagging, coverage matrix, attack story and the PDF incident report."""

from datetime import datetime, timedelta, timezone

from backend import mitre, report

T0 = datetime(2026, 6, 14, 15, 0, tzinfo=timezone.utc)


def event(minute, technique, detection="rule", severity="medium", description="x"):
    return {"timestamp": T0 + timedelta(minutes=minute), "mitre_technique": technique,
            "detection": detection, "severity": severity, "description": description}


def test_every_mapped_technique_is_defined_with_a_known_tactic():
    tactics = {name for _, name in mitre.TACTICS}
    assert len(mitre.TACTICS) == 14
    for technique, (name, tactic) in mitre.TECHNIQUES.items():
        assert technique.startswith("T") and name and tactic in tactics
    used = set(mitre.EVENT_TECHNIQUES.values()) | set(mitre.FEATURE_TECHNIQUES.values())
    used |= {technique for _, technique in mitre.SIGNATURE_TECHNIQUES}
    assert used <= set(mitre.TECHNIQUES)


def test_event_and_signature_tagging():
    assert mitre.technique_for_event({"event_type": "login_failed"}) == "T1110"
    assert mitre.technique_for_event({"event_type": "account_created"}) == "T1136"
    assert mitre.technique_for_event({"event_type": "sudo_failed"}) == "T1548.003"
    assert mitre.technique_for_event({"event_type": "http_request"}) is None
    ids = lambda message: mitre.technique_for_event({"event_type": "ids_alert", "message": message})
    assert ids("ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT") == "T1190"
    assert ids("ET SCAN NMAP -sS window 1024") == "T1595"
    assert ids("ET SCAN Potential SSH Scan") == "T1110"       # more specific keyword wins
    assert ids("GPL ICMP_INFO PING *NIX") is None and ids(None) is None
    assert mitre.describe("T1110") == {"mitre_technique": "T1110", "mitre_tactic": "Credential Access",
                                      "mitre_name": "Brute Force"}
    assert mitre.describe(None)["mitre_technique"] is None and mitre.describe("T9999")["mitre_tactic"] is None


def test_anomaly_tagging_uses_the_strongest_reason():
    reasons = lambda *features: [{"feature": f} for f in features]
    assert mitre.technique_for_anomaly(reasons("events", "login_failed")) == "T1110"
    assert mitre.technique_for_anomaly(reasons("bytes_out", "events")) == "T1041"
    assert mitre.technique_for_anomaly(reasons("conn_regularity")) == "T1071.001"
    assert mitre.technique_for_anomaly(reasons("avg_dns_length")) == "T1071.004"
    # scanning from outside is reconnaissance, from inside it is discovery
    assert mitre.technique_for_anomaly(reasons("distinct_dest_ports"), "203.0.113.9") == "T1595"
    assert mitre.technique_for_anomaly(reasons("distinct_dest_ports"), "10.0.0.9") == "T1046"
    assert mitre.technique_for_anomaly(reasons("events")) is None and mitre.technique_for_anomaly([]) is None


def test_matrix():
    matrix = mitre.build_matrix({"T1110": 40, "T1190": 2}, {"T1110": 3, "T1041": 1})
    assert [t["name"] for t in matrix] == [name for _, name in mitre.TACTICS]
    by_name = {t["name"]: t for t in matrix}
    brute = by_name["Credential Access"]["techniques"][0]
    assert brute == {"id": "T1110", "name": "Brute Force", "rules": True, "ml": True,
                     "rule_alerts": 40, "ml_alerts": 3}
    assert by_name["Credential Access"]["alerts"] == 43 and by_name["Exfiltration"]["alerts"] == 1
    exfil = by_name["Exfiltration"]["techniques"][0]
    assert exfil["ml"] and not exfil["rules"]              # only the model can see it
    assert by_name["Execution"]["techniques"] == [] and by_name["Execution"]["alerts"] == 0
    assert sum(len(t["techniques"]) for t in matrix) == len(mitre.TECHNIQUES)


def test_story_groups_runs_into_ordered_stages():
    events = [
        event(30, "T1136", severity="high", description="new user: name=backdoor"),
        event(0, "T1595", description="ET SCAN NMAP"),
        event(5, "T1110"), event(6, "T1110", detection="ml", severity="critical"), event(7, "T1110"),
        event(2, None), event(3, "T0000"),                 # untagged and unknown are ignored
        event(120, "T1110"),                               # after a long pause: a new stage
        {"timestamp": (T0 + timedelta(minutes=121)).isoformat(), "mitre_technique": "T1110",
         "detection": "rule", "severity": "low", "description": "iso string timestamps work too"},
    ]
    story = mitre.build_story(events)
    assert [(s["technique"], s["count"]) for s in story["stages"]] == [
        ("T1595", 1), ("T1110", 3), ("T1136", 1), ("T1110", 2)]
    brute = story["stages"][1]
    assert brute["severity"] == "critical" and brute["detections"] == ["rule", "ml"]
    assert brute["first_seen"] == T0 + timedelta(minutes=5) and brute["last_seen"] == T0 + timedelta(minutes=7)
    assert brute["tactic"] == "Credential Access" and brute["name"] == "Brute Force"
    assert story["stages"][2]["example"] == "new user: name=backdoor"
    assert story["tactics"] == ["Reconnaissance", "Persistence", "Credential Access"]  # kill-chain order
    assert story["alerts"] == 7 and story["first_seen"] == T0 and story["last_seen"] == T0 + timedelta(minutes=121)
    empty = mitre.build_story([event(1, None)])
    assert empty == {"stages": [], "tactics": [], "alerts": 0, "first_seen": None, "last_seen": None}


PROFILE = {
    "entity_type": "ip", "entity": "203.0.113.7", "total_logs": 321,
    "risk": {"risk_score": 71.4, "components": {"ml": 0.99, "baseline": 0.2, "rules": 0.6, "coordinated": 1.0}},
    "anomalies": [{"timestamp": T0.isoformat(), "anomaly_score": 0.994, "severity": "CRITICAL",
                   "explanation": [{"label": "failed logins", "value": 51.0, "typical": 0.0}]}],
    "recent_logs": [{"timestamp": T0.isoformat(), "log_source": "linux_auth", "event_type": "login_failed",
                     "message": "Failed password for <root> & \"friends\" from 203.0.113.7 port 22 ssh2"}] * 30,
}


def test_pdf_report():
    story = mitre.build_story([event(0, "T1595"), event(5, "T1110", severity="high", description="<b>not markup</b> & more")])
    pdf = report.build_entity_report(PROFILE, story)
    assert pdf[:5] == b"%PDF-" and pdf.rstrip().endswith(b"%%EOF") and len(pdf) > 3000
    assert b"ARGUS incident report - 203.0.113.7" in pdf      # document title metadata


def test_pdf_report_for_an_entity_with_nothing_known():
    bare = {"entity_type": "user", "entity": "nobody", "total_logs": 0, "risk": None,
            "anomalies": [], "recent_logs": []}
    pdf = report.build_entity_report(bare, mitre.build_story([]))
    assert pdf[:5] == b"%PDF-" and len(pdf) > 1500
