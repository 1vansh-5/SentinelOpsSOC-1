
"""Evidence trust and provenance assessment for SentinelOps SOC 2.0.

SIMULATION / DEVELOPMENT ONLY.

Evidence is trusted only when its authenticated envelope
matches an accepted submission in the collector registry.
"""

def validate_evidence_provenance(
    evidence: dict,
    registry=None,
    expected_incident_id=None,
) -> dict:
    """Classify evidence using registry-backed verification."""

    if not isinstance(evidence, dict):
        return {
            "trusted": False,
            "status": "REJECTED",
            "reason": "Unsupported evidence format",
        }

    investigation = evidence.get("investigation")

    if not isinstance(investigation, dict):
        return {
            "trusted": False,
            "status": "REJECTED",
            "reason": "Missing investigation record",
        }

    trace = investigation.get("trace")

    if not isinstance(trace, list) or not trace:
        return {
            "trusted": False,
            "status": "UNVERIFIED",
            "reason": "Missing investigation trace",
        }

    for step in trace:
        if not isinstance(step, dict):
            return {
                "trusted": False,
                "status": "REJECTED",
                "reason": "Invalid investigation step",
            }

        result = step.get("result")

        if not isinstance(result, dict):
            return {
                "trusted": False,
                "status": "REJECTED",
                "reason": "Invalid evidence result",
            }

        if result.get("source") == "synthetic_scenario":
            return {
                "trusted": False,
                "status": "UNVERIFIED",
                "reason": "Synthetic scenario evidence is not trusted",
            }

        if result.get("source") == "synthetic_placeholder":
            return {
                "trusted": False,
                "status": "UNVERIFIED",
                "reason": "Synthetic placeholder is not verified evidence",
            }

        if result.get("status") != "completed":
            return {
                "trusted": False,
                "status": "UNVERIFIED",
                "reason": "Evidence collection is incomplete",
            }

        if (
            registry is None
            or type(expected_incident_id) is not int
            or expected_incident_id <= 0
        ):
            return {
                "trusted": False,
                "status": "UNVERIFIED",
                "reason": "Authenticated collector provenance is not linked",
            }

        envelope = result.get("signed_evidence")

        if not isinstance(envelope, dict):
            return {
                "trusted": False,
                "status": "UNVERIFIED",
                "reason": "Missing authenticated evidence envelope",
            }

        # A registry verification is required for each trace item.
        # No caller-provided trusted flag is considered.
        if not registry.verify_accepted_evidence(
            envelope,
            expected_incident_id,
        ):
            return {
                "trusted": False,
                "status": "REJECTED",
                "reason": "Evidence failed registry verification",
            }

    return {
        "trusted": True,
        "status": "VERIFIED",
        "reason": "All evidence verified against collector registry",
    }
