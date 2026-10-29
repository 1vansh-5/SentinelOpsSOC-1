
"""Validate the structure of signed evidence records."""

from datetime import datetime

from .evidence_integrity import canonicalize_evidence


# These are proposed safety limits for the evidence envelope.
# They can be adjusted if existing collector requirements differ.
MAX_COLLECTOR_ID_LENGTH = 128
MAX_TIMESTAMP_LENGTH = 64
MAX_EVIDENCE_BYTES = 65536


def validate_evidence_record(record: dict) -> bool:
    """Return True only when required record fields are valid."""

    # A record must be a dictionary.
    if not isinstance(record, dict):
        return False

    incident_id = record.get("incident_id")

    # type() rejects booleans, which Python otherwise treats as integers.
    if type(incident_id) is not int or incident_id <= 0:
        return False

    collector_id = record.get("collector_id")

    # Require a nonempty collector identity within the length limit.
    if (
        not isinstance(collector_id, str)
        or not collector_id.strip()
        or len(collector_id) > MAX_COLLECTOR_ID_LENGTH
    ):
        return False

    timestamp = record.get("collected_at")

    # Check the timestamp type and length before parsing it.
    if (
        not isinstance(timestamp, str)
        or not timestamp
        or len(timestamp) > MAX_TIMESTAMP_LENGTH
    ):
        return False

    try:
        # ISO 8601 parsing checks the timestamp's structure.
        parsed_timestamp = datetime.fromisoformat(timestamp)

        # Require timezone information to prevent ambiguous times.
        if parsed_timestamp.tzinfo is None:
            return False

    except ValueError:
        return False

    evidence = record.get("evidence")

    # Evidence must contain at least one field.
    if not isinstance(evidence, dict) or not evidence:
        return False

    try:
        # Measure the serialized evidence, not just the number of fields.
        # This catches oversized nested dictionaries and long strings.
        evidence_bytes = canonicalize_evidence(evidence)

    except (TypeError, ValueError, UnicodeError):
        # Reject objects that cannot be represented as valid JSON.
        return False

    if len(evidence_bytes) > MAX_EVIDENCE_BYTES:
        return False

    return True
