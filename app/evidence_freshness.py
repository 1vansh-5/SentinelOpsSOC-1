
"""Evidence timestamp freshness validation."""

from datetime import datetime, timedelta, timezone


def validate_evidence_freshness(
    signed_evidence: dict,
    max_age_minutes: int = 10,
    max_future_seconds: int = 30,
) -> dict:
    if max_age_minutes <= 0 or max_future_seconds < 0:
        raise ValueError("Invalid freshness policy")

    if not isinstance(signed_evidence, dict):
        return {"fresh": False, "reason": "Invalid submission"}

    record = signed_evidence.get("record")

    if not isinstance(record, dict):
        return {"fresh": False, "reason": "Invalid record"}

    timestamp = record.get("collected_at")

    if not isinstance(timestamp, str):
        return {"fresh": False, "reason": "Missing timestamp"}

    try:
        collected_at = datetime.fromisoformat(timestamp)
    except ValueError:
        return {"fresh": False, "reason": "Invalid timestamp"}

    if collected_at.tzinfo is None:
        return {"fresh": False, "reason": "Timezone is required"}

    now = datetime.now(timezone.utc)
    collected_at = collected_at.astimezone(timezone.utc)

    if collected_at > now + timedelta(seconds=max_future_seconds):
        return {"fresh": False, "reason": "Future timestamp rejected"}

    if collected_at < now - timedelta(minutes=max_age_minutes):
        return {"fresh": False, "reason": "Evidence is too old"}

    return {"fresh": True, "reason": "Timestamp accepted"}
