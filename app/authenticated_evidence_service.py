"""Registry-backed incident evidence ingestion for SentinelOps SOC.

SIMULATION ONLY. No firewall actions or automatic incident conclusions.
The caller must supply a server-owned PersistentCollectorRegistry, never one
constructed from request parameters or caller-supplied signing keys.
"""

from .incident_evidence_store import (
    init_incident_evidence_store,
    load_incident_evidence,
    store_incident_evidence,
)


def ingest_authenticated_evidence(incident_id: int, envelope: dict, registry) -> dict:
    """Accept through the collector registry before storing the envelope.

    If storage fails after registry acceptance, ingestion fails closed. Do not
    retry the same signature: replay protection intentionally remains active.
    """
    if type(incident_id) is not int or incident_id <= 0:
        return {"accepted": False, "stored": False, "reason": "Invalid incident ID"}
    if registry is None or not callable(getattr(registry, "verify_submission", None)):
        return {"accepted": False, "stored": False, "reason": "Collector registry unavailable"}

    # A missing incident can result in an accepted-but-unstored signature.
    # The caller must create the incident before submitting evidence.
    try:
        init_incident_evidence_store()
        result = registry.verify_submission(envelope, incident_id)
    except (ValueError, TypeError, OSError) as exc:
        return {"accepted": False, "stored": False, "reason": "Evidence ingestion unavailable"}

    if not isinstance(result, dict) or result.get("accepted") is not True:
        return {"accepted": False, "stored": False,
                "reason": result.get("reason", "Collector verification failed") if isinstance(result, dict)
                else "Collector verification failed"}

    # Recheck current registry authorization immediately before storage.
    # Response authorization will independently recheck it later.
    if not registry.verify_accepted_evidence(envelope, incident_id):
        return {"accepted": False, "stored": False,
                "reason": "Accepted evidence is no longer authorized"}

    stored = store_incident_evidence(incident_id, envelope)
    if not stored.get("stored"):
        return {"accepted": False, "stored": False,
                "reason": stored.get("reason", "Evidence storage failed")}
    return {"accepted": True, "stored": True, "evidence_id": stored["evidence_id"],
            "incident_id": incident_id}


def load_verified_incident_evidence(incident_id: int, registry) -> dict:
    """Reverify *every* stored envelope against registry state, fail closed.

    Never trust a stored flag. One invalid envelope rejects the entire set.
    """
    if type(incident_id) is not int or incident_id <= 0:
        return {"trusted": False, "reason": "Invalid incident ID", "envelopes": []}
    if registry is None or not callable(getattr(registry, "verify_accepted_evidence", None)):
        return {"trusted": False, "reason": "Collector registry unavailable", "envelopes": []}
    # Ensure the table exists even before the first successful ingestion.
    # An empty, initialized store must fail closed rather than raise SQL errors.
    try:
        init_incident_evidence_store()
        envelopes = load_incident_evidence(incident_id)
    except Exception:
        return {"trusted": False, "reason": "Evidence store unavailable", "envelopes": []}
    if not envelopes:
        return {"trusted": False, "reason": "No stored collector evidence", "envelopes": []}
    for envelope in envelopes:
        if not registry.verify_accepted_evidence(envelope, incident_id):
            return {"trusted": False, "reason": "Stored evidence failed registry verification",
                    "envelopes": []}
    return {"trusted": True, "reason": "Registry-verified stored evidence", "envelopes": envelopes}
