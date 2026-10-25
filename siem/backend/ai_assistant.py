"""
AI Investigation Assistant for the SIEM backend.

Deterministic, evidence-based assistant. It answers questions strictly from
the collected logs, alerts and incidents stored in the database — it never
invents evidence and never takes disruptive actions (e.g. it recommends
containment steps but does not disable accounts itself).

A paid LLM API can be dropped in later behind the same interface.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from models import Alert, Incident, SecurityEvent


# ── Helpers ───────────────────────────────────────────────────────────────────

def _loads(value) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def _fmt(ts) -> str:
    if not ts:
        return "unknown"
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def _alert_to_dict(alert: Alert) -> Dict[str, Any]:
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "description": alert.description,
        "evidence": _loads(alert.evidence),
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique_id": alert.mitre_technique_id,
        "mitre_technique_name": alert.mitre_technique_name,
        "status": alert.status,
        "created_at": alert.created_at,
        "event_ids": _loads(alert.event_ids) or [],
    }


def _incident_to_dict(incident: Incident) -> Dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "alert_ids": _loads(incident.alert_ids) or [],
        "timeline": _loads(incident.timeline) or [],
        "mitre_techniques": _loads(incident.mitre_techniques) or [],
        "investigation_notes": incident.investigation_notes,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
    }


def _get_events(db, event_ids: List[int]) -> List[SecurityEvent]:
    if not event_ids:
        return []
    return db.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids)).all()


# ── Intent routing ────────────────────────────────────────────────────────────

def _detect_intent(question: str) -> str:
    q = question.lower()
    if any(w in q for w in ["why", "trigger", "cause", "reason", "what happened"]):
        return "why"
    if any(w in q for w in ["next", "investigate", "what should i do", "recommend"]):
        return "investigate"
    if any(w in q for w in ["contain", "stop", "containment", "mitigate"]):
        return "contain"
    if any(w in q for w in ["summar", "summary", "overview"]):
        return "summary"
    if any(w in q for w in ["report", "write a report"]):
        return "report"
    if any(w in q for w in ["evidence", "proof", "what evidence"]):
        return "evidence"
    if any(w in q for w in ["mitre", "att&ck", "technique", "tactic"]):
        return "mitre"
    return "general"


# ── Context loaders ───────────────────────────────────────────────────────────

def _load_context(db, context_type: str, context_id: int) -> Optional[Dict[str, Any]]:
    if context_type == "alert":
        alert = db.get(Alert, context_id)
        if alert is None:
            return None
        return {"type": "alert", "data": _alert_to_dict(alert)}
    if context_type == "incident":
        incident = db.get(Incident, context_id)
        if incident is None:
            return None
        return {"type": "incident", "data": _incident_to_dict(incident)}
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def answer_question(db, question: str, context_type: str, context_id: int) -> Dict[str, Any]:
    """Answer a free-form question about an alert or incident."""
    context = _load_context(db, context_type, context_id)
    intent = _detect_intent(question)

    if context is None:
        return {
            "answer": (
                "I don't have a selected alert or incident to analyze. "
                "Choose an alert or incident from the context panel first."
            ),
            "sections": [],
        }

    if context["type"] == "alert":
        return _answer_about_alert(db, context["data"], intent, question)
    return _answer_about_incident(db, context["data"], intent, question)


def summarize(db, context_type: str, context_id: int) -> Dict[str, Any]:
    """Generate a structured summary of an alert or incident."""
    context = _load_context(db, context_type, context_id)
    if context is None:
        return {"answer": "Context not found.", "sections": []}
    if context["type"] == "alert":
        return _answer_about_alert(db, context["data"], "summary", "Summarize this alert.")
    return _answer_about_incident(db, context["data"], "summary", "Summarize this incident.")


def generate_report(db, incident_id: int) -> Dict[str, Any]:
    """Generate a draft incident report (markdown)."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        return {"report": "Incident not found.", "sections": []}

    data = _incident_to_dict(incident)
    alert_ids = data["alert_ids"]
    alerts = [db.get(Alert, aid) for aid in alert_ids]
    alerts = [a for a in alerts if a is not None]

    event_ids: List[int] = []
    for a in alerts:
        event_ids.extend(_loads(a.event_ids) or [])
    events = _get_events(db, event_ids)

    techniques = data["mitre_techniques"]
    tech_summary = ", ".join(
        f"{t.get('id', '?')} {t.get('name', '')}".strip() for t in techniques
    ) if techniques else "None mapped"

    lines = [
        "# Incident Report",
        "",
        f"**Incident ID:** INC-{incident.id}",
        f"**Title:** {data['title']}",
        f"**Severity:** {data['severity']}",
        f"**Status:** {data['status']}",
        f"**Created:** {_fmt(incident.created_at)}",
        f"**MITRE ATT&CK:** {tech_summary}",
        "",
        "## Summary",
        "",
        data["description"],
        "",
        f"## Linked Alerts ({len(alerts)})",
        "",
    ]
    for a in alerts:
        lines.append(f"- **{a.rule_name}** (sev={a.severity}, conf={round(a.confidence * 100)}%): {a.description[:120]}")
    lines.append("")
    lines.append(f"## Related Events ({len(events)})")
    lines.append("")
    for e in sorted(events, key=lambda x: x.timestamp)[:25]:
        lines.append(
            f"- [{_fmt(e.timestamp)}] Event ID {e.event_id} "
            f"({e.event_type}) account={e.account} computer={e.computer_name}"
        )
    lines.append("")
    lines.append("## Recommended Next Steps")
    lines.append("")
    lines.append("1. Confirm the alert evidence against the raw log entries above.")
    lines.append("2. For each mapped MITRE technique, follow the investigation guidance.")
    lines.append("3. Apply containment and coordinate with the account owner.")
    lines.append("4. Record findings in the incident investigation notes.")
    lines.append("")
    lines.append("> Generated by SENTINEL SIEM. This is a draft and must be reviewed by an analyst.")

    return {"report": "\n".join(lines), "sections": []}


# ── Alert answers ─────────────────────────────────────────────────────────────

def _answer_about_alert(db, alert: Dict[str, Any], intent: str, question: str) -> Dict[str, Any]:
    evidence = alert["evidence"] or {}
    event_ids = alert["event_ids"] or []
    events = _get_events(db, event_ids)
    account = evidence.get("account") or (events[0].account if events else "unknown")

    if intent == "why":
        return {
            "answer": (
                f"Alert #{alert['id']} ('{alert['rule_name']}') triggered because the "
                f"detection rule '{alert['rule_id']}' matched logged events for account "
                f"'{account}'. Confidence is {round(alert['confidence'] * 100)}% based on "
                f"{len(events)} supporting log event(s)."
            ),
            "sections": [
                {"title": "Detection", "content": alert["description"]},
                {"title": "Evidence", "content": json.dumps(evidence, indent=2)},
                {"title": "Supporting events", "content": (
                    "; ".join(
                        f"{_fmt(e.timestamp)} Event {e.event_id} {e.event_type} ({e.computer_name})"
                        for e in events[:10]
                    ) or "none"
                )},
            ],
        }
    if intent == "evidence":
        return {
            "answer": f"Evidence for alert #{alert['id']}: {len(events)} supporting event(s) were evaluated.",
            "sections": [
                {"title": "Evidence", "content": json.dumps(evidence, indent=2)},
                {"title": "Supporting events", "content": (
                    "; ".join(
                        f"{_fmt(e.timestamp)} Event {e.event_id} account={e.account} ip={e.source_ip or 'n/a'} ({e.computer_name})"
                        for e in events[:15]
                    ) or "none"
                )},
            ],
        }
    if intent == "investigate":
        return {
            "answer": (
                f"For alert #{alert['id']} (technique {alert['mitre_technique_id']} — "
                f"{alert['mitre_technique_name']}), start with the evidence above. "
                f"Validate the supporting events, then follow the MITRE investigation "
                f"steps for {alert['mitre_technique_id']}."
            ),
            "sections": [
                {"title": "Suggested checklist", "content": "\n".join(
                    f"- {s}" for s in _mitre_investigation_steps(alert["mitre_technique_id"])
                )},
            ],
        }
    if intent == "contain":
        return {
            "answer": (
                "Containment must be performed by an analyst — this assistant does not "
                "take disruptive actions. Recommended containment steps are listed below."
            ),
            "sections": [
                {"title": "Recommended containment", "content": "\n".join(
                    f"- {s}" for s in _mitre_containment(alert["mitre_technique_id"])
                )},
            ],
        }
    if intent == "mitre":
        return {
            "answer": (
                f"This alert maps to MITRE ATT&CK technique {alert['mitre_technique_id']} "
                f"('{alert['mitre_technique_name']}') under tactic {alert['mitre_tactic']}."
            ),
            "sections": [
                {"title": "Technique", "content": _mitre_technique(alert["mitre_technique_id"])},
            ],
        }
    if intent == "summary":
        return {
            "answer": (
                f"Alert #{alert['id']}: {alert['rule_name']} (severity {alert['severity']}, "
                f"confidence {round(alert['confidence'] * 100)}%). Account: {account}. "
                f"Technique: {alert['mitre_technique_id']}. Status: {alert['status']}."
            ),
            "sections": [
                {"title": "Description", "content": alert["description"]},
                {"title": "MITRE", "content": f"{alert['mitre_technique_id']} — {alert['mitre_technique_name']} ({alert['mitre_tactic']})"},
            ],
        }
    # general
    return {
        "answer": (
            f"Alert #{alert['id']} — {alert['rule_name']}. Account '{account}', severity "
            f"{alert['severity']}, confidence {round(alert['confidence'] * 100)}%, "
            f"status {alert['status']}. Technique {alert['mitre_technique_id']}. "
            f"{len(events)} supporting event(s)."
        ),
        "sections": [
            {"title": "Description", "content": alert["description"]},
            {"title": "Evidence", "content": json.dumps(evidence, indent=2)},
        ],
    }


# ── Incident answers ──────────────────────────────────────────────────────────

def _answer_about_incident(db, incident: Dict[str, Any], intent: str, question: str) -> Dict[str, Any]:
    alert_ids = incident["alert_ids"]
    alerts = [db.get(Alert, aid) for aid in alert_ids]
    alerts = [a for a in alerts if a is not None]
    techniques = incident["mitre_techniques"]

    if intent == "why":
        return {
            "answer": (
                f"Incident INC-{incident['id']} ('{incident['title']}') was opened by the "
                f"correlation engine: {len(alerts)} alert(s) were grouped because they share "
                f"related activity and form a coherent attack chain. Severity is "
                f"{incident['severity']}."
            ),
            "sections": [
                {"title": "Description", "content": incident["description"]},
                {"title": "Linked alerts", "content": "\n".join(
                    f"- {a.rule_name} (sev {a.severity}): {a.description[:100]}"
                    for a in alerts
                )},
            ],
        }
    if intent == "investigate":
        steps: List[str] = []
        for t in techniques:
            steps.extend(_mitre_investigation_steps(t.get("id", "")))
        return {
            "answer": (
                f"Investigate incident INC-{incident['id']} by validating each linked alert "
                f"({len(alerts)} alerts, {len(techniques)} techniques) against raw events, "
                f"then following the steps below."
            ),
            "sections": [
                {"title": "Investigation checklist", "content": "\n".join(f"- {s}" for s in steps)},
            ],
        }
    if intent == "contain":
        steps: List[str] = []
        for t in techniques:
            steps.extend(_mitre_containment(t.get("id", "")))
        return {
            "answer": (
                "Containment is analyst-driven; this assistant only recommends steps and "
                "never disables accounts or systems automatically."
            ),
            "sections": [
                {"title": "Recommended containment", "content": "\n".join(f"- {s}" for s in steps)},
            ],
        }
    if intent == "report":
        return generate_report(db, incident["id"])
    if intent == "summary":
        return {
            "answer": (
                f"Incident INC-{incident['id']}: {incident['title']}. Severity "
                f"{incident['severity']}, status {incident['status']}, "
                f"{len(alerts)} linked alert(s), {len(techniques)} MITRE technique(s)."
            ),
            "sections": [
                {"title": "Timeline", "content": "\n".join(
                    f"- {t['time']} — {t['rule']}" for t in incident["timeline"][:10]
                ) or "No timeline"},
            ],
        }
    return {
        "answer": (
            f"Incident INC-{incident['id']} — {incident['title']} ({incident['severity']}, "
            f"{incident['status']}). {len(alerts)} linked alert(s)."
        ),
        "sections": [
            {"title": "Description", "content": incident["description"]},
        ],
    }


# ── MITRE guidance (bundled copy to keep the AI module self-contained) ────────

from mitre_attack import get_technique  # noqa: E402


def _mitre_technique(technique_id: str) -> str:
    t = get_technique(technique_id)
    if not t:
        return "Technique not found in local MITRE database."
    return f"{t['name']} ({t['tactic']}): {t['description']}"


def _mitre_investigation_steps(technique_id: str) -> List[str]:
    t = get_technique(technique_id)
    return t["investigation_steps"] if t else ["Review the alert evidence and raw log events."]


def _mitre_containment(technique_id: str) -> List[str]:
    t = get_technique(technique_id)
    return t["recommended_response"] if t else ["Isolate affected systems and reset credentials."]
