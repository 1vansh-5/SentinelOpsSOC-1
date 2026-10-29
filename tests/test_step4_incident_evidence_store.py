"""Isolated Windows-compatible Step 4 incident evidence storage test."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import os
import secrets
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app.evidence_signing import create_signed_evidence
from app.incident_evidence_store import (
    init_incident_evidence_store,
    store_incident_evidence,
    load_incident_evidence,
)


def run():
    with tempfile.TemporaryDirectory() as directory:
        db_path = str(Path(directory) / "incidents.db")

        def test_connect():
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            return conn

        with closing(test_connect()) as conn:
            with conn:
                conn.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY)")
                conn.execute("INSERT INTO incidents (id) VALUES (101)")

        with patch("app.incident_evidence_store.connect", side_effect=test_connect):
            init_incident_evidence_store()
            init_incident_evidence_store()
            print("Repeatable table initialization: PASSED")

            envelope = create_signed_evidence(
                101, "test-collector", {"event": "synthetic-test"},
                secrets.token_hex(32),
            )
            assert not store_incident_evidence(102, envelope)["stored"]
            print("Wrong incident binding rejected: PASSED")

            assert not store_incident_evidence(101, {"trusted": True})["stored"]
            print("Forged trust flag rejected: PASSED")

            assert not store_incident_evidence(102, create_signed_evidence(
                102, "test-collector", {"event": "other"},
                secrets.token_hex(32),
            ))["stored"]
            print("Unknown incident rejected: PASSED")

            assert store_incident_evidence(101, envelope)["stored"]
            print("Envelope stored: PASSED")
            assert not store_incident_evidence(101, envelope)["stored"]
            print("Duplicate signature rejected: PASSED")

            records = load_incident_evidence(101)
            assert len(records) == 1 and records[0] == envelope
            assert "trusted" not in records[0]
            print("Stored envelope remains untrusted: PASSED")

            assert load_incident_evidence(102) == []
            print("Incident isolation: PASSED")

    print("Windows SQLite cleanup: PASSED")
    print("STEP 4 INCIDENT EVIDENCE STORAGE TEST: PASSED")


if __name__ == "__main__":
    run()
