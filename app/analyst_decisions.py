
"""Persistent analyst rejection with SQLite audit logging."""

import json

from .database import connect
from .evidence_provenance import validate_evidence_provenance


def reject_response_request(
    request_id: int,
    analyst_id: str,
    reason: str,
) -> dict:
    """Reject a pending simulated response request."""

    if not isinstance(analyst_id, str) or not analyst_id.strip():
        return {
            "status": "REJECTED_INPUT",
            "reason": "Analyst identity is required",
        }

    if not isinstance(reason, str) or not reason.strip():
        return {
            "status": "REJECTED_INPUT",
            "reason": "Rejection reason is required",
        }

    with connect() as conn:
        # Atomically claim only a pending request.
        updated = conn.execute(
            """
            UPDATE response_requests
            SET status = 'REJECTED',
                decided_at = datetime('now'),
                decided_by = ?
            WHERE id = ? AND status = 'PENDING'
            """,
            (analyst_id.strip(), request_id),
        )

        if updated.rowcount != 1:
            return {
                "status": "NOT_UPDATED",
                "reason": "Request not found or no longer pending",
            }

        request = conn.execute(
            """
            SELECT incident_id
            FROM response_requests
            WHERE id = ?
            """,
            (request_id,),
        ).fetchone()

        conn.execute(
            """
            INSERT INTO response_audit
            (
                response_request_id,
                incident_id,
                action,
                actor,
                details
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                request_id,
                request["incident_id"],
                "REQUEST_REJECTED",
                analyst_id.strip(),
                json.dumps({"reason": reason.strip()}),
            ),
        )

    return {
        "status": "REJECTED",
        "request_id": request_id,
        "decided_by": analyst_id.strip(),
        "reason": reason.strip(),
        "mode": "SIMULATION_ONLY",
    }

def check_approval_eligibility(request_id: int) -> dict:
    """Check whether a simulated block request is eligible."""

    with connect() as conn:
        request = conn.execute(
            """
            SELECT
                r.id,
                r.incident_id,
                r.source_ip,
                r.action,
                r.status,
                i.assessment,
                i.evidence
            FROM response_requests AS r
            JOIN incidents AS i
                ON i.id = r.incident_id
            WHERE r.id = ?
            """,
            (request_id,),
        ).fetchone()

    if request is None:
        return {
            "eligible": False,
            "reason": "Response request not found",
        }

    if request["status"] != "PENDING":
        return {
            "eligible": False,
            "reason": "Response request is not pending",
        }

    if request["action"] != "SIMULATED_BLOCK":
        return {
            "eligible": False,
            "reason": "Unsupported response action",
        }

    if request["assessment"] != "ATTACK_CONFIRMED":
        return {
            "eligible": False,
            "reason": "Incident is not confirmed",
        }

    try:
        evidence = json.loads(request["evidence"])
    except (ValueError, TypeError):
        return {
            "eligible": False,
            "reason": "Invalid incident evidence",
        }

    if not isinstance(evidence, dict):
        return {
            "eligible": False,
            "reason": "Unsupported evidence format",
        }

    outcome = evidence.get("outcome")

    if not isinstance(outcome, dict):
        return {
            "eligible": False,
            "reason": "Missing validated outcome",
        }

    if outcome.get("assessment") != "ATTACK_CONFIRMED":
        return {
            "eligible": False,
            "reason": "Outcome does not confirm attack",
        }

    # Current synthetic scenarios must never authorize blocking.
    # This is intentionally conservative until we add a trusted
    # evidence provenance system.
    
    # Validate the origin and integrity of investigation evidence.
    provenance = validate_evidence_provenance(evidence)

    if not provenance["trusted"]:
        return {
            "eligible": False,
            "reason": provenance["reason"],
        }

    # Additional approval safeguards will be required
    # before enabling simulated block execution.
    return {
        "eligible": False,
        "reason": "Approval execution is not yet enabled",
    }

