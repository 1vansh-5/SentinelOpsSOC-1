"""Step 4 Part 3 API ingestion regression test. Requires fastapi and httpx."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import copy
import os
import secrets
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import database
from app.main import app
from app.evidence_signing import create_signed_evidence
from app.persistent_collector_registry import PersistentCollectorRegistry
from app.authenticated_evidence_service import load_verified_incident_evidence


def run():
    with tempfile.TemporaryDirectory() as tmp:
        incident_db = str(Path(tmp) / "incidents.db")
        registry_db = str(Path(tmp) / "registry.db")
        key = secrets.token_hex(32)
        api_key = secrets.token_hex(24)
        collector_id = "api-test-collector"
        registry = PersistentCollectorRegistry(registry_db)
        registry.register_collector(collector_id, key)
        env = {
            "SENTINELOPS_DB": incident_db,
            "SENTINELOPS_REGISTRY_DB": registry_db,
            "SENTINELOPS_COLLECTOR_ID": collector_id,
            "SENTINELOPS_COLLECTOR_KEY": key,
            "SENTINELOPS_API_KEY": api_key,
        }
        with patch.dict(os.environ, env), patch.object(database, "DB_PATH", incident_db):
            # main.py and incident_evidence_store.py import connect from database;
            # the function reads database.DB_PATH at call time.
            with TestClient(app) as client:
                headers = {"X-API-Key": api_key}
                assert client.get("/health").status_code == 200
                print("Existing health endpoint: PASSED")
                with closing(database.connect()) as conn:
                    with conn:
                        conn.execute("""INSERT INTO alerts
                            (source_ip,event_type,target,details,severity,status)
                            VALUES ('8.8.8.8','failed_login','test','test','high','new')""")
                        conn.execute("""INSERT INTO incidents
                            (alert_id,assessment,confidence,evidence,response_action,response_status)
                            VALUES (1,'INCONCLUSIVE','low','{}','NO_AUTOMATIC_ACTION','SIMULATED_ONLY')""")
                endpoint = "/incidents/1/evidence/submit"
                envelope = create_signed_evidence(1, collector_id, {"event": "simulated"}, key)
                assert client.post(endpoint, json={"envelope": envelope}).status_code == 401
                print("Missing API key rejected: PASSED")
                assert client.post(endpoint, headers={"X-API-Key": "wrong"}, json={"envelope": envelope}).status_code == 401
                print("Incorrect API key rejected: PASSED")
                assert client.post("/incidents/999/evidence/submit", headers=headers,
                                   json={"envelope": envelope}).status_code == 404
                print("Missing incident rejected before acceptance: PASSED")
                bad = copy.deepcopy(envelope)
                bad["record"]["evidence"]["event"] = "tampered"
                assert client.post(endpoint, headers=headers, json={"envelope": bad}).status_code == 409
                print("Tampered submission rejected: PASSED")
                result = client.post(endpoint, headers=headers, json={"envelope": envelope})
                assert result.status_code == 200, result.text
                assert result.json()["stored"] is True
                print("Authenticated API ingestion: PASSED")
                assert client.post(endpoint, headers=headers, json={"envelope": envelope}).status_code == 409
                print("Replay rejected: PASSED")
                verified = load_verified_incident_evidence(1, app.state.collector_registry)
                assert verified["trusted"] is True
                print("Stored evidence independently verified: PASSED")
                with closing(database.connect()) as conn:
                    incident = conn.execute("SELECT assessment FROM incidents WHERE id=1").fetchone()
                    count = conn.execute("SELECT count(*) FROM response_requests").fetchone()[0]
                    assert incident["assessment"] == "INCONCLUSIVE" and count == 0
                print("No automatic assessment or response: PASSED")
    print("Windows SQLite cleanup: PASSED")
    print("STEP 4 PART 3 API INGESTION TEST: PASSED")


if __name__ == "__main__":
    run()
