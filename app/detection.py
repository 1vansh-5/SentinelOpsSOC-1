"""Small defensive demo detector. All events are synthetic unless explicitly sent by an authorized sensor."""
from collections import Counter

def classify_alert(event_type: str, details: str, severity: str) -> dict:
    text = (details or "").lower()
    signals = []
    if event_type == "failed_login":
        signals.append("failed login event")
    if event_type == "successful_login":
        signals.append("successful login event")
    if event_type == "sql_injection" or any(x in text for x in ("' or 1=1", "union select", "sql injection")):
        signals.append("possible SQL injection indicator")
    if event_type == "port_scan":
        signals.append("port scan indicator")
    if event_type == "malware_indicator":
        signals.append("malware indicator reported")
    if severity in ("high", "critical"):
        signals.append(f"reported severity is {severity}")
    return {"signals": signals, "needs_review": bool(signals), "severity": severity}

def assess(alert: dict) -> dict:
    """Evidence-based starter assessment; not a replacement for a production detection engine."""
    event_type = alert["event_type"]
    details = alert["details"].lower()
    if event_type == "successful_login" and ("after_failures=true" in details or "after_failures: true" in details):
        return {
            "assessment": "POSSIBLE_COMPROMISE",
            "confidence": "medium",
            "evidence": ["A successful login was reported after failed attempts; verify account and session logs."]
        }
    if event_type in ("sql_injection", "malware_indicator", "port_scan"):
        return {
            "assessment": "SUSPICIOUS_ACTIVITY",
            "confidence": "medium",
            "evidence": [f"Sensor reported event type: {event_type}. This alone does not prove successful compromise."]
        }
    if event_type == "failed_login":
        return {
            "assessment": "ATTEMPT_DETECTED",
            "confidence": "low",
            "evidence": ["Failed login attempts do not by themselves prove account compromise."]
        }
    return {
        "assessment": "INCONCLUSIVE",
        "confidence": "low",
        "evidence": ["Insufficient evidence to conclude whether an attack succeeded."]
    }
