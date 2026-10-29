
"""Evidence integrity utilities for SentinelOps SOC."""

import hashlib
import hmac
import json


def canonicalize_evidence(evidence: dict) -> bytes:
    """Convert evidence into a consistent byte representation."""
    if not isinstance(evidence, dict):
        raise ValueError("Evidence must be a dictionary")

    return json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_evidence_hash(evidence: dict) -> str:
    """Calculate the SHA-256 digest of evidence."""
    data = canonicalize_evidence(evidence)
    return hashlib.sha256(data).hexdigest()


def verify_evidence_hash(
    evidence: dict,
    expected_hash: str,
) -> bool:
    """Check evidence against a previously recorded digest."""
    if not isinstance(expected_hash, str):
        return False

    actual_hash = calculate_evidence_hash(evidence)

    return hmac.compare_digest(
        actual_hash,
        expected_hash,
    )