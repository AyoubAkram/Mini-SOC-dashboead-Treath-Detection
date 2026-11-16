"""
Incident report (PDF)
Builds a printable report for one entity: risk score, attack story mapped to
MITRE ATT&CK, ML findings and the most recent evidence.
"""

from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

try:
    from . import utils
except ImportError:  # running with backend/ on sys.path (python backend/main.py)
    import utils

INK = colors.HexColor("#141a26")
MUTED = colors.HexColor("#5d6679")
LINE = colors.HexColor("#d9dee8")
SEVERITY_COLORS = {"critical": "#c8334a", "high": "#c96f14", "medium": "#9a7b00", "low": "#1f8a61"}


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["BodyText"]
    body = ParagraphStyle("body", parent=base, fontName="Helvetica", fontSize=9.5, leading=13, textColor=INK)
    return {
        "body": body,
        "small": ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=MUTED),
        "title": ParagraphStyle("title", parent=body, fontName="Helvetica-Bold", fontSize=20, leading=24),
        "h2": ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=12, leading=16,
                             spaceBefore=14, spaceAfter=6),
        "cell": ParagraphStyle("cell", parent=body, fontSize=8.5, leading=11),
    }


def _when(value) -> str:
    if not value:
        return "-"
    if not isinstance(value, datetime):
        value = utils.parse_iso_timestamp(value)
    return utils.to_utc(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def _table(rows: List[List[Any]], widths: List[float]) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED), ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def build_entity_report(profile: Dict[str, Any], story: Dict[str, Any]) -> bytes:
    """
    profile: the entity profile served by GET /api/entities/{type}/{id}
    story:   mitre.build_story() output for the same entity
    Returns the PDF file content.
    """
    styles = _styles()
    para = lambda text, style="cell": Paragraph(escape(str(text)), styles[style])
    kind = "IP address" if profile["entity_type"] == "ip" else "User"
    plural = lambda items: "" if len(items) == 1 else "s"
    risk = profile.get("risk") or {}
    flow: List[Any] = [
        Paragraph("ARGUS incident report", styles["small"]),
        Paragraph(f"{kind} {escape(profile['entity'])}", styles["title"]),
        Paragraph(f"Generated {_when(utils.utcnow())} · {profile.get('total_logs', 0)} logs on record",
                  styles["small"]),
    ]

    # Summary
    flow.append(Paragraph("Summary", styles["h2"]))
    score = risk.get("risk_score")
    components = risk.get("components") or {}
    summary = [
        ["Risk score", f"{score:.0f} / 100" if score is not None else "not scored yet"],
        ["Attack stages", f"{len(story['stages'])} stage{plural(story['stages'])} across "
                          f"{len(story['tactics'])} ATT&CK tactic{plural(story['tactics'])}"
         if story["stages"] else "none identified"],
        ["Activity window", f"{_when(story['first_seen'])} to {_when(story['last_seen'])}"
         if story["stages"] else "-"],
        ["Tagged alerts", str(story["alerts"])],
    ]
    if components:
        summary.append(["Score components",
                        f"ML {100 * components.get('ml', 0):.0f}% · own baseline "
                        f"{100 * components.get('baseline', 0):.0f}% · rules "
                        f"{100 * components.get('rules', 0):.0f}% · coordinated "
                        f"{'yes' if components.get('coordinated') else 'no'}"])
    flow.append(_table([["Item", "Value"]] + [[para(a), para(b)] for a, b in summary], [42 * mm, 128 * mm]))

    # Attack story
    flow.append(Paragraph("Attack story (MITRE ATT&CK)", styles["h2"]))
    if story["stages"]:
        rows = [["#", "Tactic / technique", "When", "Alerts", "Severity", "Example"]]
        for index, stage in enumerate(story["stages"], 1):
            color = SEVERITY_COLORS.get(stage["severity"], "#141a26")
            rows.append([
                str(index),
                Paragraph(f"<b>{escape(stage['tactic'])}</b><br/>{escape(stage['technique'])} "
                          f"{escape(stage['name'])}", styles["cell"]),
                para(_when(stage["first_seen"])),
                f"{stage['count']} ({', '.join(d for d in stage['detections'] if d)})",
                Paragraph(f'<font color="{color}"><b>{stage["severity"].upper()}</b></font>', styles["cell"]),
                para(stage["example"][:220]),
            ])
        flow.append(_table(rows, [7 * mm, 42 * mm, 30 * mm, 20 * mm, 18 * mm, 53 * mm]))
    else:
        flow.append(Paragraph("No alert on this entity could be mapped to an ATT&CK technique.", styles["body"]))

    # ML findings
    anomalies = profile.get("anomalies") or []
    flow.append(Paragraph("Behavioral anomalies (ML)", styles["h2"]))
    if anomalies:
        rows = [["Window", "Score", "Severity", "What stood out"]]
        for anomaly in anomalies[:12]:
            reasons = ", ".join(f"{r['label']} {r['value']:g} (typical {r['typical']:g})"
                                for r in anomaly.get("explanation") or []) or "unusual combination"
            rows.append([para(_when(anomaly["timestamp"])), f"{anomaly.get('anomaly_score', 0):.2f}",
                         str(anomaly.get("severity", "")), para(reasons)])
        flow.append(_table(rows, [38 * mm, 14 * mm, 20 * mm, 98 * mm]))
    else:
        flow.append(Paragraph("The model has not flagged this entity.", styles["body"]))

    # Evidence
    logs = profile.get("recent_logs") or []
    flow.append(Paragraph("Most recent evidence", styles["h2"]))
    if logs:
        rows = [["Time", "Source", "Event", "Message"]]
        for log in logs[:20]:
            rows.append([para(_when(log["timestamp"])), para(log.get("log_source", "")),
                         para(str(log.get("event_type", "")).replace("_", " ")),
                         para(str(log.get("message", ""))[:260])])
        flow.append(_table(rows, [38 * mm, 22 * mm, 28 * mm, 82 * mm]))
    else:
        flow.append(Paragraph("No logs.", styles["body"]))

    flow.append(Spacer(1, 10))
    flow.append(Paragraph(
        "ATT&CK tags are assigned automatically from event types, IDS signatures and the features "
        "behind each ML anomaly. They are a starting point for the analyst, not a verdict.",
        styles["small"]))

    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                                 topMargin=18 * mm, bottomMargin=18 * mm,
                                 title=f"ARGUS incident report - {profile['entity']}", author="ARGUS")
    document.build(flow)
    return buffer.getvalue()
