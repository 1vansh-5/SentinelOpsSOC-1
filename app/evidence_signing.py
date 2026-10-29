
"""Authenticated evidence signing for SentinelOps SOC."""

import hashlib
import hmac
import json
from datetime import datetime, timezone

from .evidence_integrity import canonicalize_evidence
# Reuse the same record validation rules when signing and verifying.
from .evidence_record_validation import validate_evidence_record


def create_signed_evidence(
    incident_id: int,
    collector_id: str,
    evidence: dict,
    signing_key: str,
) -> dict:
    """Create an authenticated evidence envelope."""

    if incident_id <= 0:
        raise ValueError("Invalid incident ID")

    if not collector_id or not collector_id.strip():
        raise ValueError("Collector identity is required")

    if not signing_key or len(signing_key) < 32:
        raise ValueError("A strong signing key is required")

    record = {
        "incident_id": incident_id,
        "collector_id": collector_id,
        "collected_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "evidence": evidence,
    }
    # Validate the complete record before generating its signature.
    # Invalid evidence must never receive a trusted signature.
    if not validate_evidence_record(record):
        raise ValueError("Invalid evidence record")
    signature = hmac.new(
        signing_key.encode("utf-8"),
        canonicalize_evidence(record),
        hashlib.sha256,
    ).hexdigest()

    return {
        "record": record,
        "signature": signature,
        "algorithm": "HMAC-SHA256",
    }


def verify_signed_evidence(
    signed_evidence: dict,
    signing_key: str,
    expected_incident_id: int,
    expected_collector_id: str,
) -> bool:
    """Verify signature and expected record identity."""

    if not isinstance(signed_evidence, dict):
        return False

    if not signing_key:
        return False

    if signed_evidence.get("algorithm") != "HMAC-SHA256":
        return False

    record = signed_evidence.get("record")
    signature = signed_evidence.get("signature")

    # Check all required fields, types, and permitted lengths.
    # Reject invalid records before HMAC verification.
    if not validate_evidence_record(record):
        return False

    if not isinstance(signature, str):
        return False

    if record.get("incident_id") != expected_incident_id:
        return False

    if record.get("collector_id") != expected_collector_id:
        return False

    try:
        timestamp = datetime.fromisoformat(
            record["collected_at"]
        )

        if timestamp.tzinfo is None:
            return False

        if not isinstance(record["evidence"], dict):
            return False

        expected_signature = hmac.new(
            signing_key.encode("utf-8"),
            canonicalize_evidence(record),
            hashlib.sha256,
        ).hexdigest()

    except (KeyError, TypeError, ValueError):
        return False

    return hmac.compare_digest(
        expected_signature,
        signature,
    )