
"""Authentication for SentinelOps analyst operations."""

import os
import secrets

from fastapi import HTTPException


def require_analyst_key(
    supplied_key: str | None,
) -> str:
    """Validate an analyst API key.

    Returns a server-assigned identity, not a client-supplied name.
    """

    expected_key = os.getenv(
        "SENTINELOPS_ANALYST_API_KEY"
    )

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="Analyst authentication is not configured",
        )

    if (
        not supplied_key
        or not secrets.compare_digest(
            supplied_key,
            expected_key,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid analyst credentials",
        )

    return "authenticated-analyst"