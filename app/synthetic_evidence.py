
"""Explicitly synthetic SOC evidence for safe testing."""

SCENARIOS = {
    "attack_succeeded": {
        "authentication_logs": {
            "login_attempts": 12,
            "failed_logins": 11,
            "successful_login": True,
            "session_created": True,
        },
        "asset_inventory": {
            "asset": "demo-login",
            "criticality": "high",
            "environment": "simulation",
        },
        "vulnerability_lookup": {
            "vulnerability_status": "not_assessed",
        },
        "application_logs": {
            "unauthorized_access_observed": True,
            "http_status": 200,
        },
    },
    "attack_failed": {
        "authentication_logs": {
            "login_attempts": 12,
            "failed_logins": 12,
            "successful_login": False,
            "session_created": False,
        },
        "asset_inventory": {
            "asset": "demo-login",
            "criticality": "high",
            "environment": "simulation",
        },
        "vulnerability_lookup": {
            "vulnerability_status": "not_assessed",
        },
        "application_logs": {
            "unauthorized_access_observed": False,
            "http_status": 403,
        },
    },
    "inconclusive": {
        "authentication_logs": {
            "login_attempts": 12,
            "failed_logins": 11,
            "successful_login": None,
            "session_created": None,
        },
        "asset_inventory": {
            "asset": "demo-login",
            "criticality": "unknown",
            "environment": "simulation",
        },
        "vulnerability_lookup": {
            "vulnerability_status": "unknown",
        },
        "application_logs": {
            "unauthorized_access_observed": None,
            "http_status": None,
        },
    },
}


def get_synthetic_evidence(scenario: str, tool_name: str) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError("Unknown simulation scenario")

    if tool_name not in SCENARIOS[scenario]:
        raise ValueError("Unknown evidence tool")

    return {
        "tool": tool_name,
        "source": "synthetic_scenario",
        "scenario": scenario,
        "evidence": SCENARIOS[scenario][tool_name],
    }
