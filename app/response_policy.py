
"""Safe simulated response policy for SentinelOps SOC."""

from ipaddress import ip_address


def evaluate_response(incident: dict, source_ip: str) -> dict:
    """Evaluate a simulated response without changing any firewall."""

    assessment = incident.get("assessment", "INCONCLUSIVE")

    try:
        address = ip_address(source_ip)
    except ValueError:
        return {
            "action": "NO_ACTION",
            "reason": "Invalid source IP address",
            "requires_approval": False,
        }

    # Only globally routable IPs are eligible for block proposals.
    # Never propose blocking localhost, private, or special-use IPs.
    if not address.is_global:
        return {
            "action": "NO_ACTION",
            "reason": "Source IP is not globally routable",
            "requires_approval": False,
        }

    if assessment == "ATTACK_CONFIRMED":
        return {
            "action": "PROPOSE_SIMULATED_BLOCK",
            "reason": "Confirmed attack requires analyst review",
            "requires_approval": True,
        }

    if assessment == "ATTACK_FAILED":
        return {
            "action": "MONITOR",
            "reason": "Attack attempt failed; continue monitoring",
            "requires_approval": False,
        }

    return {
        "action": "REVIEW",
        "reason": "Insufficient evidence for automated blocking",
        "requires_approval": False,
    }
