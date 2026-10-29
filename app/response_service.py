"""Fail-closed, incident-linked simulated response request service.

No firewall operations. A request remains PENDING for analyst approval.
The registry is supplied by trusted server-side code, never by an API caller.
"""

import json
import sqlite3
from contextlib import closing
from ipaddress import ip_address

from .database import connect
from .response_policy import evaluate_response
from .authenticated_evidence_service import load_verified_incident_evidence


def create_response_request(incident_id: int, registry=None) -> dict:
    """Propose a simulated block only for confirmed, authenticated incidents."""
    if type(incident_id) is not int or incident_id <= 0:
        return {"status": "REJECTED", "reason": "Invalid incident ID"}

    # Do not create response requests when the trusted server registry is absent.
    if registry is None:
        return {"status": "REJECTED", "reason": "Collector registry unavailable"}

    try:
        with closing(connect()) as conn:
            with conn:
                # IMMEDIATE serializes response-request creation in this database.
                conn.execute("BEGIN IMMEDIATE")
                incident = conn.execute(
                    """SELECT i.id, i.assessment, i.evidence, a.source_ip
                       FROM incidents AS i JOIN alerts AS a ON a.id = i.alert_id
                       WHERE i.id = ?""", (incident_id,)
                ).fetchone()
                if incident is None:
                    return {"status": "REJECTED", "reason": "Incident not found"}

                try:
                    evidence = json.loads(incident["evidence"])
                except (ValueError, TypeError):
                    return {"status": "REJECTED", "reason": "Invalid incident evidence"}
                if not isinstance(evidence, dict):
                    return {"status": "REJECTED", "reason": "Unsupported incident evidence"}

                outcome = evidence.get("outcome")
                if not isinstance(outcome, dict) or (
                    incident["assessment"] != "ATTACK_CONFIRMED"
                    or outcome.get("assessment") != "ATTACK_CONFIRMED"
                    or outcome.get("ai_status") not in (
                        "gemini", "gemini_overridden", "fallback_rules"
                    )
                ):
                    return {"status": "REJECTED", "reason": "Attack is not confirmed by validated outcome"}

                # The original synthetic-only investigation cannot become trusted
                # just because an unrelated signed collector envelope was attached.
                investigation = evidence.get("investigation")
                if not isinstance(investigation, dict):
                    return {"status": "REJECTED", "reason": "Missing investigation"}
                trace = investigation.get("trace")
                if not isinstance(trace, list) or not trace:
                    return {"status": "REJECTED", "reason": "Missing investigation trace"}
                for step in trace:
                    if not isinstance(step, dict) or not isinstance(step.get("result"), dict):
                        return {"status": "REJECTED", "reason": "Malformed investigation trace"}
                    result = step["result"]
                    if result.get("source") in ("synthetic_scenario", "synthetic_placeholder"):
                        return {"status": "REJECTED", "reason": "Synthetic investigation cannot authorize response"}
                    if result.get("status") != "completed":
                        return {"status": "REJECTED", "reason": "Incomplete investigation"}

                verified = load_verified_incident_evidence(incident_id, registry)
                if verified.get("trusted") is not True:
                    return {"status": "REJECTED", "reason": "Verified collector evidence required: " + verified.get("reason", "Unavailable")}

                # The stored trace must refer to the exact authenticated envelopes.
                # Otherwise arbitrary unverified tool results could justify a block.
                from .evidence_integrity import canonicalize_evidence
                stored = set()
                for envelope in verified["envelopes"]:
                    stored.add(canonicalize_evidence(envelope))
                for step in trace:
                    result = step["result"]
                    envelope = result.get("signed_evidence")
                    if not isinstance(envelope, dict):
                        return {"status": "REJECTED", "reason": "Investigation step lacks signed evidence"}
                    try:
                        if canonicalize_evidence(envelope) not in stored:
                            return {"status": "REJECTED", "reason": "Investigation evidence not in verified store"}
                    except (TypeError, ValueError, OverflowError):
                        return {"status": "REJECTED", "reason": "Invalid investigation evidence"}

                try:
                    source_ip = str(ip_address(incident["source_ip"]))
                except ValueError:
                    return {"status": "REJECTED", "reason": "Invalid source IP"}
                policy = evaluate_response({"assessment": incident["assessment"]}, source_ip)
                if policy.get("action") != "PROPOSE_SIMULATED_BLOCK":
                    return {"status": "REJECTED", "reason": policy.get("reason", "Response policy rejected")}

                existing = conn.execute(
                    """SELECT id, status FROM response_requests
                       WHERE incident_id = ? ORDER BY id DESC LIMIT 1""",
                    (incident_id,),
                ).fetchone()
                if existing:
                    return {"status": existing["status"], "request_id": existing["id"],
                            "reason": "Response request already exists"}

                cursor = conn.execute(
                    """INSERT INTO response_requests
                       (incident_id, source_ip, action, status)
                       VALUES (?, ?, 'SIMULATED_BLOCK', 'PENDING')""",
                    (incident_id, source_ip),
                )
                request_id = cursor.lastrowid
                conn.execute(
                    """INSERT INTO response_audit
                       (response_request_id, incident_id, action, actor, details)
                       VALUES (?, ?, 'REQUEST_CREATED', 'system', ?)""",
                    (request_id, incident_id, json.dumps(policy)),
                )
                return {"status": "PENDING", "request_id": request_id,
                        "incident_id": incident_id, "source_ip": source_ip,
                        "requires_approval": True}
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return {"status": "REJECTED", "reason": "Response authorization unavailable"}
