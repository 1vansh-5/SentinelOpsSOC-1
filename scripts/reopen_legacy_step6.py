"""Local operator utility: reopen ONE unbound legacy approval for fresh review.

Never approves or executes. Stop the API first, then review again using Step 5.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
import json
from contextlib import closing
from app.database import connect, init_db
from app.response_execution import init_execution_store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request_id',type=int)
    parser.add_argument('--reason',required=True)
    args = parser.parse_args()
    if args.request_id <= 0 or not 3 <= len(args.reason.strip()) <= 500:
        raise SystemExit('Positive request ID and reason of 3–500 characters required')
    init_db()
    init_execution_store()
    with closing(connect()) as conn,conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute("SELECT * FROM response_requests WHERE id=? AND status='APPROVED'",(args.request_id,)).fetchone()
        binding = conn.execute('SELECT 1 FROM response_approval_bindings WHERE request_id=?',(args.request_id,)).fetchone()
        if row is None or binding:
            raise SystemExit('Only unbound legacy APPROVED requests can be reopened; no changes made')
        conn.execute("UPDATE response_requests SET status='PENDING',decided_at=NULL,decided_by=NULL WHERE id=?",(args.request_id,))
        conn.execute("INSERT INTO response_audit (response_request_id,incident_id,action,actor,details) VALUES (?,?,'LEGACY_APPROVAL_REOPENED','local_operator',?)",
                     (args.request_id,row['incident_id'],json.dumps({'reason':args.reason.strip(),'previous_decided_by':row['decided_by']})))
    print('Request reopened for fresh authenticated Step 5 review. No execution occurred.')


if __name__ == '__main__':
    main()
