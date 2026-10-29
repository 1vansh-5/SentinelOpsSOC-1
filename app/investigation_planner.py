
"""Bounded read-only investigation planner with evidence provenance."""

from .evidence_tools import ALLOWED_TOOLS, retrieve_evidence
from .evidence_provenance import validate_evidence_provenance


def investigate_evidence(
    alert: dict,
    max_steps: int = 4,
) -> dict:
    """Retrieve permitted evidence and assess its trust status."""

    if (
        type(max_steps) is not int
        or not 1 <= max_steps <= 4
    ):
        raise ValueError("max_steps must be between 1 and 4")

    event_type = alert.get("event_type")

    if event_type in ("failed_login", "successful_login"):
        priority = [
            "authentication_logs",
            "asset_inventory",
            "vulnerability_lookup",
            "application_logs",
        ]
    else:
        priority = [
            "application_logs",
            "asset_inventory",
            "vulnerability_lookup",
            "authentication_logs",
        ]

    trace = []

    for tool_name in priority[:max_steps]:
        if tool_name not in ALLOWED_TOOLS:
            continue

        result = retrieve_evidence(tool_name, alert)

        trace.append({
            "step": len(trace) + 1,
            "tool": tool_name,
            "result": result,
        })

    investigation = {
        "investigation_status": "evidence_collection_completed",
        "steps_taken": len(trace),
        "trace": trace,
        "conclusion": "INCONCLUSIVE",
        "note": (
            "Synthetic placeholders are not independent proof "
            "of attack success or failure."
        ),
    }

    provenance = validate_evidence_provenance({
        "investigation": investigation
    })

    investigation["provenance"] = provenance
    investigation["evidence_trusted"] = provenance["trusted"]

    return investigation
