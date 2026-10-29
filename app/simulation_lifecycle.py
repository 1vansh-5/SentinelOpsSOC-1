"""SQLite simulation effect verification and authorized rollback. No OS adapters."""
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .database import connect
from .analyst_identity import AnalystIdentityStore

MODE = 'SIMULATION_ONLY'


def init_lifecycle(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS simulation_effects (
        request_id INTEGER PRIMARY KEY, source_ip TEXT NOT NULL, state TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS simulation_telemetry (
        id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL, operation TEXT NOT NULL,
        expected_blocked INTEGER NOT NULL, observed_blocked INTEGER NOT NULL,
        matched INTEGER NOT NULL, source TEXT NOT NULL DEFAULT 'synthetic_sqlite_probe',
        created_at TEXT NOT NULL DEFAULT (datetime('now')))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS response_rollbacks (
        request_id INTEGER PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
        result_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))''')
    # Existing Step 6 receipts are NOT retrospectively labeled verified.
    conn.execute('''INSERT OR IGNORE INTO simulation_effects (request_id,source_ip,state)
        SELECT r.id,r.source_ip,'LEGACY_UNVERIFIED' FROM response_requests r
        JOIN response_executions e ON e.request_id=r.id
        WHERE r.status='SIMULATED_EXECUTED' ''')


def audit(conn, row, action, actor, details):
    conn.execute('''INSERT INTO response_audit
        (response_request_id,incident_id,action,actor,details) VALUES (?,?,?,?,?)''',
        (row['id'],row['incident_id'],action,actor,json.dumps(details,sort_keys=True)))


def _probe(conn, source_ip, expected):
    """Synthetic telemetry inspects only the simulated table, never network traffic."""
    observed = conn.execute('SELECT 1 FROM simulated_blocks WHERE source_ip=?',(source_ip,)).fetchone() is not None
    return {'source':'synthetic_sqlite_probe','expected_blocked':expected,
            'observed_blocked':observed,'matched':observed == expected}


def telemetry(conn, row, operation, expected):
    report = _probe(conn,row['source_ip'],expected)
    conn.execute('''INSERT INTO simulation_telemetry
        (request_id,operation,expected_blocked,observed_blocked,matched)
        VALUES (?,?,?,?,?)''',(row['id'],operation,int(expected),
                               int(report['observed_blocked']),int(report['matched'])))
    return report


def record_execution_start(conn, row, actor):
    audit(conn,row,'SIMULATION_EXECUTING',actor,{'state':'EXECUTING','mode':MODE})


def verify_execution(conn, row, result):
    report = telemetry(conn,row,'EXECUTION',True)
    state = 'VERIFIED' if report['matched'] else 'FAILED'
    if state == 'FAILED':
        if result['block_created']:
            conn.execute('DELETE FROM simulated_blocks WHERE source_ip=? AND response_request_id=?',
                         (row['source_ip'],row['id']))
        result.update(status='SIMULATION_FAILED',executed=False,
                      compensated=bool(result['block_created']))
    conn.execute('INSERT INTO simulation_effects (request_id,source_ip,state) VALUES (?,?,?)',
                 (row['id'],row['source_ip'],state))
    result.update(verification_status=state,telemetry=report)
    return result


def valid_key(value):
    return (isinstance(value,str) and 16 <= len(value) <= 128 and value.isascii()
            and all(c.isalnum() or c in '-_' for c in value))


def _operator_action(request_id, analyst_id, token, identities, *, key=None, reason=None, rollback=False):
    if type(request_id) is not int or request_id <= 0:
        return {'status':'DENIED','reason':'Invalid request ID'}
    if rollback and (not valid_key(key) or not isinstance(reason,str) or not 3 <= len(reason.strip()) <= 500):
        return {'status':'DENIED','reason':'Valid rollback key and reason required'}
    if type(identities) is not AnalystIdentityStore:
        return {'status':'DENIED','reason':'Authorization unavailable'}
    try:
        with closing(connect()) as conn, closing(identities._connect()) as guard:
            database_file = conn.execute('PRAGMA database_list').fetchone()[2]
            if not database_file or Path(database_file).resolve() == Path(identities.database_path).resolve():
                return {'status':'DENIED','reason':'Separate persistent databases required'}
            guard.execute('BEGIN IMMEDIATE')
            with conn:
                conn.execute('BEGIN IMMEDIATE')
                actor = identities.authorize(analyst_id,token,'decide')
                if actor is None:
                    return {'status':'DENIED','reason':'Analyst not authorized'}
                row = conn.execute('SELECT * FROM response_requests WHERE id=?',(request_id,)).fetchone()
                effect = conn.execute('SELECT * FROM simulation_effects WHERE request_id=?',(request_id,)).fetchone()
                if row is None or effect is None:
                    return {'status':'DENIED','reason':'Executed simulation required'}
                if not rollback:
                    if effect['state'] in ('ROLLED_BACK','FAILED'):
                        return {'status':'DENIED','reason':'Active simulation required'}
                    report = telemetry(conn,row,'VERIFY',True)
                    state = 'VERIFIED' if report['matched'] else 'VERIFICATION_FAILED'
                    conn.execute("UPDATE simulation_effects SET state=?,updated_at=datetime('now') WHERE request_id=?",(state,request_id))
                    result = {'status':'SIMULATION_VERIFIED' if report['matched'] else 'SIMULATION_VERIFICATION_FAILED',
                              'request_id':request_id,'mode':MODE,'verification_status':state,'telemetry':report}
                    audit(conn,row,result['status'],actor['analyst_id'],result)
                    return result
                previous = conn.execute('SELECT * FROM response_rollbacks WHERE request_id=? OR idempotency_key=?',(request_id,key)).fetchall()
                if previous:
                    if len(previous)==1 and previous[0]['request_id']==request_id and previous[0]['idempotency_key']==key:
                        return dict(json.loads(previous[0]['result_json']),replayed=True)
                    return {'status':'DENIED','reason':'Idempotency conflict'}
                if effect['state'] not in ('VERIFIED','LEGACY_UNVERIFIED','VERIFICATION_FAILED'):
                    return {'status':'DENIED','reason':'Active simulation required'}
                audit(conn,row,'SIMULATION_ROLLING_BACK',actor['analyst_id'],{'state':'ROLLING_BACK','reason':reason.strip(),'mode':MODE})
                conn.execute("UPDATE simulation_effects SET state='ROLLING_BACK' WHERE request_id=?",(request_id,))
                other = conn.execute("SELECT 1 FROM simulation_effects WHERE source_ip=? AND request_id<>? AND state IN ('VERIFIED','LEGACY_UNVERIFIED','VERIFICATION_FAILED','ROLLING_BACK') LIMIT 1",(row['source_ip'],request_id)).fetchone()
                block = conn.execute('SELECT response_request_id FROM simulated_blocks WHERE source_ip=?',(row['source_ip'],)).fetchone()
                known_owner = block and conn.execute('SELECT 1 FROM simulation_effects WHERE request_id=?',(block[0],)).fetchone()
                # Retain shared effects and blocks whose origin cannot be established.
                retained = bool(other or (block and not known_owner))
                if not retained:
                    conn.execute('DELETE FROM simulated_blocks WHERE source_ip=?',(row['source_ip'],))
                report = telemetry(conn,row,'ROLLBACK',retained)
                if not report['matched']:
                    raise ValueError('Simulation rollback verification failed')
                conn.execute("UPDATE simulation_effects SET state='ROLLED_BACK',updated_at=datetime('now') WHERE request_id=?",(request_id,))
                conn.execute("UPDATE response_requests SET status='SIMULATED_ROLLED_BACK' WHERE id=?",(request_id,))
                conn.execute("UPDATE incidents SET response_status='SIMULATED_ROLLED_BACK' WHERE id=?",(row['incident_id'],))
                result = {'status':'SIMULATED_ROLLED_BACK','request_id':request_id,'mode':MODE,
                          'rolled_back_by':actor['analyst_id'],'reason':reason.strip(),
                          'block_retained':retained,'verification_status':'VERIFIED','telemetry':report}
                serialized = json.dumps(result,sort_keys=True)
                conn.execute('INSERT INTO response_rollbacks (request_id,idempotency_key,result_json) VALUES (?,?,?)',(request_id,key,serialized))
                audit(conn,row,'SIMULATED_ROLLED_BACK',actor['analyst_id'],result)
                return dict(result,replayed=False)
    except (sqlite3.Error,OSError,ValueError,TypeError,KeyError):
        return {'status':'DENIED','reason':'Simulation lifecycle unavailable; transaction rolled back'}


def rollback_response(request_id, key, analyst_id, token, identities, reason):
    result = _operator_action(request_id,analyst_id,token,identities,key=key,reason=reason,rollback=True)
    if result['status']=='DENIED':
        try:
            actor = identities.authorize(analyst_id,token,'decide') if type(identities) is AnalystIdentityStore else None
            if actor and type(request_id) is int and 0 < request_id < 2**63:
                with closing(connect()) as conn,conn:
                    row = conn.execute('SELECT * FROM response_requests WHERE id=?',(request_id,)).fetchone()
                    if row:
                        audit(conn,row,'SIMULATION_ROLLBACK_DENIED',actor['analyst_id'],
                              {'reason':str(reason)[:500],'outcome':result['reason'],'mode':MODE})
        except (sqlite3.Error,OSError,ValueError,TypeError):
            result['denial_audit_available'] = False
    return result


def verify_response(request_id, analyst_id, token, identities):
    return _operator_action(request_id,analyst_id,token,identities)
