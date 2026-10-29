"""Integration security regression; creates only isolated temporary SQLite data."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from contextlib import closing
from unittest.mock import patch

from app.analyst_identity import AnalystIdentityStore
from app.response_approval import decide_response


def run():
    with tempfile.TemporaryDirectory() as directory:
        db = str(Path(directory) / 'responses.sqlite')
        identities = AnalystIdentityStore(str(Path(directory) / 'analysts.sqlite'))
        admin = identities.create_analyst('admin_01', 'admin')
        analyst = identities.create_analyst('analyst_01', 'analyst')
        viewer = identities.create_analyst('viewer_01', 'viewer')
        with closing(sqlite3.connect(db)) as conn, conn:
            conn.executescript('''CREATE TABLE alerts (id INTEGER PRIMARY KEY, source_ip TEXT);
            CREATE TABLE incidents (id INTEGER PRIMARY KEY, alert_id INTEGER, assessment TEXT, evidence TEXT);
            CREATE TABLE response_requests (id INTEGER PRIMARY KEY, incident_id INTEGER,
                source_ip TEXT, action TEXT, status TEXT, decided_at TEXT, decided_by TEXT);
            CREATE TABLE response_audit (id INTEGER PRIMARY KEY, response_request_id INTEGER,
                incident_id INTEGER, action TEXT, actor TEXT, details TEXT);
            CREATE TABLE simulated_blocks (source_ip TEXT PRIMARY KEY);''')
            conn.execute('INSERT INTO alerts VALUES (1, ?)', ('8.8.8.8',))
            conn.execute('INSERT INTO incidents VALUES (1, 1, ?, ?)',
                         ('ATTACK_CONFIRMED', json.dumps({'outcome': {'assessment':'ATTACK_CONFIRMED', 'ai_status':'gemini'}, 'investigation': {'trace':[{'result':{'status':'completed','signed_evidence':{'id':'signed'}}}]}})))
            for idx in range(1, 6):
                conn.execute('INSERT INTO response_requests VALUES (?, 1, ?, ?, ?, NULL, NULL)',
                             (idx, '8.8.8.8', 'SIMULATED_BLOCK', 'PENDING'))
        import app.database as database
        original = database.DB_PATH
        database.DB_PATH = db
        try:
            def decide(i, d, who, key, reg=object()):
                return decide_response(i, d, who, key, identities, reg, 'Reviewed evidence')
            assert decide(1, 'APPROVED', 'viewer_01', viewer['token'])['status'] == 'DENIED'
            print('Viewer denied: PASSED')
            assert decide(1, 'APPROVED', 'analyst_01', 'x'*64)['status'] == 'DENIED'
            print('Wrong token denied: PASSED')
            assert decide(1, 'APPROVED', 'analyst_01', analyst['token'], None)['status'] == 'DENIED'
            print('Missing registry denied: PASSED')
            assert decide(1, 'APPROVED', 'analyst_01', analyst['token'])['status'] == 'DENIED'
            print('Unverified evidence denied: PASSED')
            with patch('app.response_approval.load_verified_incident_evidence', return_value={'trusted':True,'envelopes':[{'id':'signed'}]}):
                assert decide(1, 'APPROVED', 'analyst_01', analyst['token'])['status'] == 'APPROVED'
                print('Verified approval: PASSED')
                assert decide(1, 'REJECTED', 'admin_01', admin['token'])['status'] == 'DENIED'
                print('Duplicate decision denied: PASSED')
                assert decide(2, 'REJECTED', 'admin_01', admin['token'])['status'] == 'REJECTED'
                print('Authorized rejection: PASSED')
                identities.change_role('analyst_01', 'viewer')
                assert decide(3, 'REJECTED', 'analyst_01', analyst['token'])['status'] == 'DENIED'
                print('Role downgrade enforced: PASSED')
                identities.disable_analyst('admin_01')
                assert decide(3, 'REJECTED', 'admin_01', admin['token'])['status'] == 'DENIED'
                print('Revocation enforced: PASSED')
            with closing(sqlite3.connect(db)) as conn:
                assert conn.execute('SELECT COUNT(*) FROM response_audit').fetchone()[0] == 2
                assert conn.execute('SELECT COUNT(*) FROM simulated_blocks').fetchone()[0] == 0
                assert conn.execute("SELECT COUNT(*) FROM response_requests WHERE status='PENDING'").fetchone()[0] == 3
            print('Audit exact-once and no execution: PASSED')
        finally:
            database.DB_PATH = original
    print('Windows SQLite cleanup: PASSED')
    print('STEP 5 INTEGRATED TEST: PASSED')

if __name__ == '__main__':
    run()
