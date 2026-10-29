"""Step 4 Part 2: real registry + incident storage, no API/firewall calls."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import copy
import secrets
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app.evidence_signing import create_signed_evidence
from app.persistent_collector_registry import PersistentCollectorRegistry
from app.authenticated_evidence_service import (
    ingest_authenticated_evidence,
    load_verified_incident_evidence,
)
from app.incident_evidence_store import store_incident_evidence


def run():
    with tempfile.TemporaryDirectory() as directory:
        incident_db = str(Path(directory) / "incidents.db")
        registry_db = str(Path(directory) / "registry.db")

        def test_connect():
            conn = sqlite3.connect(incident_db)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            return conn

        with closing(test_connect()) as conn:
            with conn:
                conn.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY)")
                conn.execute("INSERT INTO incidents (id) VALUES (101)")

        registry = PersistentCollectorRegistry(registry_db)
        key = secrets.token_hex(32)
        collector_id = "step4-part2-collector"
        registry.register_collector(collector_id, key)

        with patch("app.incident_evidence_store.connect", side_effect=test_connect):
            envelope = create_signed_evidence(101, collector_id, {"event": "simulated-test"}, key)
            assert not load_verified_incident_evidence(101, registry)["trusted"]
            print("No evidence fails closed: PASSED")

            assert not ingest_authenticated_evidence(102, envelope, registry)["accepted"]
            print("Wrong incident rejected: PASSED")

            forged = copy.deepcopy(envelope)
            forged["record"]["evidence"]["event"] = "tampered"
            assert not ingest_authenticated_evidence(101, forged, registry)["accepted"]
            print("Tampered signature rejected: PASSED")

            assert not ingest_authenticated_evidence(101, {"trusted": True}, registry)["accepted"]
            print("Forged trust flag rejected: PASSED")

            accepted = ingest_authenticated_evidence(101, envelope, registry)
            assert accepted["accepted"] and accepted["stored"], accepted
            print("Registry acceptance and storage: PASSED")

            verified = load_verified_incident_evidence(101, registry)
            assert verified["trusted"] and verified["envelopes"] == [envelope]
            print("Stored envelope independently verified: PASSED")

            assert not ingest_authenticated_evidence(101, envelope, registry)["accepted"]
            print("Replay blocked: PASSED")

            assert not load_verified_incident_evidence(102, registry)["trusted"]
            print("Incident isolation: PASSED")

            # Direct storage is not authentication; an unsigned registry history
            # must never become trusted merely by appearing in the storage table.
            other = create_signed_evidence(101, collector_id, {"event": "not-accepted"}, key)
            assert store_incident_evidence(101, other)["stored"]
            assert not load_verified_incident_evidence(101, registry)["trusted"]
            print("Direct storage cannot forge trust: PASSED")

            # Existing accepted evidence loses current authorization on revocation.
            registry.revoke_collector(collector_id)
            assert not registry.verify_accepted_evidence(envelope, 101)
            assert not load_verified_incident_evidence(101, registry)["trusted"]
            print("Revocation fails closed: PASSED")

    print("Windows SQLite cleanup: PASSED")
    print("STEP 4 REGISTRY-TO-STORAGE INTEGRATION TEST: PASSED")


if __name__ == "__main__":
    run()
