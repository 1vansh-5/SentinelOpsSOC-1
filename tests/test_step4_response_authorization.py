"""Step 4 Part 4: end-to-end simulated response authorization tests."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import secrets
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app.evidence_signing import create_signed_evidence
from app.persistent_collector_registry import PersistentCollectorRegistry
from app.incident_evidence_store import init_incident_evidence_store
from app.authenticated_evidence_service import ingest_authenticated_evidence
from app.response_service import create_response_request


def passed(message):
    print(message + ': PASSED')


def run():
    with tempfile.TemporaryDirectory() as temp:
        db = str(Path(temp) / 'incidents.db')
        registry_db = str(Path(temp) / 'registry.db')

        def connection():
            conn = sqlite3.connect(db, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn

        # Patch the shared DB connection where it is imported by the modules.
        with patch('app.incident_evidence_store.connect', side_effect=connection), \
             patch('app.response_service.connect', side_effect=connection):
            with closing(connection()) as conn:
                with conn:
                    conn.executescript('''
                        CREATE TABLE alerts (id INTEGER PRIMARY KEY, source_ip TEXT);
                        CREATE TABLE incidents (
                            id INTEGER PRIMARY KEY, alert_id INTEGER,
                            assessment TEXT, evidence TEXT);
                        CREATE TABLE response_requests (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            incident_id INTEGER, source_ip TEXT, action TEXT,
                            status TEXT DEFAULT 'PENDING');
                        CREATE TABLE response_audit (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            response_request_id INTEGER, incident_id INTEGER,
                            action TEXT, actor TEXT, details TEXT);
                    ''')
                    conn.execute('INSERT INTO alerts VALUES (1, ?)', ('8.8.8.8',))
                    conn.execute('INSERT INTO incidents VALUES (101, 1, ?, ?)',
                                 ('ATTACK_CONFIRMED', '{}'))

            init_incident_evidence_store()
            registry = PersistentCollectorRegistry(registry_db)
            key = secrets.token_hex(32)
            registry.register_collector('collector-part4', key)
            envelope = create_signed_evidence(101, 'collector-part4',
                                               {'event': 'simulated-verified-log'}, key)
            result = ingest_authenticated_evidence(101, envelope, registry)
            assert result['accepted'] and result['stored'], result
            passed('Authenticated incident evidence stored')

            # A confirmed outcome without a verified trace must never suffice.
            outcome = {'assessment': 'ATTACK_CONFIRMED', 'ai_status': 'fallback_rules'}
            synthetic = {'outcome': outcome, 'investigation': {'trace': [
                {'result': {'status': 'completed', 'source': 'synthetic_scenario'}}]}}
            with closing(connection()) as conn:
                with conn:
                    conn.execute('UPDATE incidents SET evidence=? WHERE id=101',
                                 (json.dumps(synthetic),))
            assert create_response_request(101, registry)['status'] == 'REJECTED'
            passed('Synthetic trace rejected despite signed attachment')

            verified = {'outcome': outcome, 'investigation': {'trace': [
                {'result': {'status': 'completed', 'source': 'authenticated_collector',
                            'signed_evidence': envelope}}]}}
            with closing(connection()) as conn:
                with conn:
                    conn.execute('UPDATE incidents SET evidence=? WHERE id=101',
                                 (json.dumps(verified),))
            assert create_response_request(101)['status'] == 'REJECTED'
            passed('Missing trusted registry rejected')

            forged = json.loads(json.dumps(verified))
            forged['investigation']['trace'][0]['result']['signed_evidence']['record']['evidence']['event'] = 'forged'
            with closing(connection()) as conn:
                with conn:
                    conn.execute('UPDATE incidents SET evidence=? WHERE id=101',
                                 (json.dumps(forged),))
            assert create_response_request(101, registry)['status'] == 'REJECTED'
            passed('Unstored or tampered trace rejected')

            with closing(connection()) as conn:
                with conn:
                    conn.execute('UPDATE incidents SET evidence=? WHERE id=101',
                                 (json.dumps(verified),))
            accepted = create_response_request(101, registry)
            assert accepted['status'] == 'PENDING' and accepted['requires_approval'] is True, accepted
            passed('Verified incident creates pending request')

            again = create_response_request(101, registry)
            assert again['request_id'] == accepted['request_id']
            passed('Duplicate response request prevented')

            with closing(connection()) as conn:
                count = conn.execute('SELECT COUNT(*) FROM response_requests').fetchone()[0]
                audit = conn.execute('SELECT COUNT(*) FROM response_audit').fetchone()[0]
                assert count == 1 and audit == 1
            passed('One request and one audit record')

            # Revocation must prevent *new* requests; previously created requests
            # are not automatically canceled here and require Step 5 handling.
            with closing(connection()) as conn:
                with conn:
                    conn.execute('DELETE FROM response_requests')
            registry.revoke_collector('collector-part4')
            assert create_response_request(101, registry)['status'] == 'REJECTED'
            passed('Revoked collector blocks new authorization')

    passed('Windows SQLite cleanup')
    print('STEP 4 PART 4 RESPONSE AUTHORIZATION TEST: PASSED')


if __name__ == '__main__':
    run()
