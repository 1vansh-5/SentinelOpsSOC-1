"""Incident-linked evidence envelope storage for SentinelOps SOC.

Storage is NOT a trust decision. A stored envelope must be reverified against
its collector registry before use in an investigation or response decision.
"""

import json
import sqlite3
from contextlib import closing

from .database import connect
from .evidence_record_validation import validate_evidence_record
from .evidence_integrity import canonicalize_evidence


def init_incident_evidence_store() -> None:
    """Create the incident evidence table; safe to call repeatedly."""
    with closing(connect()) as conn:
        # Normal reads must not attempt schema writes while a response service
        # holds BEGIN IMMEDIATE on another connection. Startup creates both.
        existing = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE name IN ('incident_evidence','idx_incident_evidence_incident')"
        )}
        if len(existing) == 2:
            return
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    collector_id TEXT NOT NULL,
                    signature TEXT NOT NULL UNIQUE,
                    envelope_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident
                ON incident_evidence(incident_id)
            """)


def store_incident_evidence(incident_id: int, envelope: dict) -> dict:
    """Store an envelope only after a registry has accepted it.

    This function does not authenticate a submission. Call the registry's
    verify_submission first, then store its accepted envelope. The response
    gate must independently reverify stored envelopes before granting trust.
    """
    if type(incident_id) is not int or incident_id <= 0:
        return {"stored": False, "reason": "Invalid incident ID"}
    if not isinstance(envelope, dict):
        return {"stored": False, "reason": "Invalid envelope"}
    record = envelope.get("record")
    signature = envelope.get("signature")
    if (
        envelope.get("algorithm") != "HMAC-SHA256"
        or not validate_evidence_record(record)
        or record.get("incident_id") != incident_id
        or not isinstance(signature, str)
        or len(signature) != 64
        or any(c not in "0123456789abcdef" for c in signature)
    ):
        return {"stored": False, "reason": "Invalid or mismatched envelope"}
    try:
        serialized = canonicalize_evidence(envelope).decode("utf-8")
    except (ValueError, TypeError, OverflowError):
        return {"stored": False, "reason": "Envelope cannot be serialized"}
    with closing(connect()) as conn:
        with conn:
            # Explicit existence check works even if legacy DBs disabled FK checks.
            incident = conn.execute(
                "SELECT id FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if incident is None:
                return {"stored": False, "reason": "Incident not found"}
            try:
                cursor = conn.execute("""
                    INSERT INTO incident_evidence
                    (incident_id, collector_id, signature, envelope_json)
                    VALUES (?, ?, ?, ?)
                """, (incident_id, record["collector_id"], signature, serialized))
            except sqlite3.IntegrityError:
                return {"stored": False, "reason": "Duplicate evidence signature"}
            return {"stored": True, "evidence_id": cursor.lastrowid}


def load_incident_evidence(incident_id: int) -> list[dict]:
    """Return stored envelopes, WITHOUT granting trusted status."""
    if type(incident_id) is not int or incident_id <= 0:
        return []
    with closing(connect()) as conn:
        rows = conn.execute("""
            SELECT envelope_json FROM incident_evidence
            WHERE incident_id = ? ORDER BY id
        """, (incident_id,)).fetchall()
    envelopes = []
    for row in rows:
        try:
            value = json.loads(row["envelope_json"])
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            envelopes.append(value)
    return envelopes
