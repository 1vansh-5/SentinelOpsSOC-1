
"""Read-only synthetic evidence tools for SentinelOps SOC."""

from ipaddress import ip_address

ALLOWED_TOOLS = (
    "asset_inventory",
    "authentication_logs",
    "application_logs",
    "vulnerability_lookup",
)



"""Read-only evidence tools for SentinelOps SOC."""

from ipaddress import ip_address
from .synthetic_evidence import get_synthetic_evidence

ALLOWED_TOOLS = (
    "asset_inventory",
    "authentication_logs",
    "application_logs",
    "vulnerability_lookup",
)

VALID_SCENARIOS = (
    "attack_succeeded",
    "attack_failed",
    "inconclusive",
)


def retrieve_evidence(
    tool_name: str,
    alert: dict,
    scenario: str | None = None,
) -> dict:
    """Retrieve only approved synthetic evidence."""

    if tool_name not in ALLOWED_TOOLS:
        raise ValueError("Evidence tool is not allowed")

    source_ip = str(alert.get("source_ip", ""))

    try:
        ip_address(source_ip)
    except ValueError:
        return {
            "tool": tool_name,
            "status": "invalid_input",
            "evidence": {},
        }

    if scenario is not None:
        if scenario not in VALID_SCENARIOS:
            raise ValueError("Invalid simulation scenario")

        result = get_synthetic_evidence(
            scenario,
            tool_name,
        )

        # Do not expose the scenario's answer label
        # to the reasoning model.
        return {
            "tool": tool_name,
            "status": "completed",
            "source": "synthetic_scenario",
            "evidence": result["evidence"],
        }

    return {
        "tool": tool_name,
        "status": "no_evidence",
        "source": "synthetic_placeholder",
        "evidence": {},
    }
