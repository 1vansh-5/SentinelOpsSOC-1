
"""In-memory simulated firewall. No real network changes."""

from datetime import datetime, timezone
from ipaddress import ip_address

# Demonstration-only state; resets when Python restarts.
BLOCKED_IPS = set()
AUDIT_LOG = []


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def apply_block(source_ip: str, approved: bool) -> dict:
    """Apply a simulated block only after explicit approval."""

    try:
        address = ip_address(source_ip)
    except ValueError:
        return {
            "status": "REJECTED",
            "reason": "Invalid IP address",
        }

    if not address.is_global:
        return {
            "status": "REJECTED",
            "reason": "Special-use or private IP addresses are not eligible",
        }

    if approved is not True:
        return {
            "status": "PENDING_APPROVAL",
            "reason": "Analyst approval is required",
        }

    BLOCKED_IPS.add(str(address))

    event = {
        "timestamp": _timestamp(),
        "action": "SIMULATED_BLOCK",
        "source_ip": str(address),
        "status": "APPLIED",
    }

    AUDIT_LOG.append(event)

    return event


def remove_block(source_ip: str) -> dict:
    """Reverse a simulated block."""

    BLOCKED_IPS.discard(source_ip)

    event = {
        "timestamp": _timestamp(),
        "action": "SIMULATED_UNBLOCK",
        "source_ip": source_ip,
        "status": "APPLIED",
    }

    AUDIT_LOG.append(event)

    return event


def verify_block(source_ip: str) -> dict:
    """Check the in-memory simulated firewall state."""

    return {
        "source_ip": source_ip,
        "blocked": source_ip in BLOCKED_IPS,
        "mode": "SIMULATION_ONLY",
    }
