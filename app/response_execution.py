"""Transactional, database-only simulation. No operating-system or network adapter."""
import hashlib
import json
import sqlite3
from contextlib import ExitStack, closing
from pathlib import Path

from .database import connect
from .analyst_identity import AnalystIdentityStore
from .persistent_collector_registry import PersistentCollectorRegistry
from .response_approval import _eligible
from .evidence_freshness import validate_evidence_freshness


def approval_digest(row):
    fields = ('incident_id', 'source_ip', 'action', 'assessment', 'evidence', 'alert_source_ip')
    return hashlib.sha256(json.dumps({k: row[k] for k in fields},
                                   sort_keys=True).encode()).hexdigest()


def init_execution_store():
    with closing(connect()) as conn, conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS response_approval_bindings (
            request_id INTEGER PRIMARY KEY, digest TEXT NOT NULL)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS response_executions (
            request_id INTEGER PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            result_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS response_execution_denials (
            id INTEGER PRIMARY KEY, request_id INTEGER, claimed_analyst TEXT,
            reason TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))''')
        from .simulation_lifecycle import init_lifecycle
        init_lifecycle(conn)


def _execute_response(request_id, idempotency_key, analyst_id, token, identities, registry):
    """Authenticate retries too. One transaction owns result, block, status and audit.

    Registry/identity write reservations serialize revocation with execution. Those
    stores must be separate persistent SQLite files, as in the supplied baseline.
    No historical APPROVED request lacking an approval binding can execute.
    """
    if type(request_id) is not int or request_id <= 0:
        return {'status': 'DENIED', 'reason': 'Invalid request ID'}
    if (not isinstance(idempotency_key, str) or not 16 <= len(idempotency_key) <= 128
            or not idempotency_key.isascii() or not all(c.isalnum() or c in '-_' for c in idempotency_key)):
        return {'status': 'DENIED', 'reason': 'Invalid idempotency key'}
    if type(identities) is not AnalystIdentityStore or type(registry) is not PersistentCollectorRegistry:
        return {'status': 'DENIED', 'reason': 'Authorization dependencies unavailable'}
    try:
        with ExitStack() as stack:
            conn = stack.enter_context(closing(connect()))
            paths = [Path(identities.database_path).resolve(), Path(registry.database_path).resolve()]
            main_path = Path(conn.execute('PRAGMA database_list').fetchone()[2]).resolve()
            if len(set(paths + [main_path])) != 3 or any(str(p).endswith(':memory:') for p in paths):
                return {'status': 'DENIED', 'reason': 'Separate persistent databases required'}
            # Use a consistent order for all execution workers. Reservations do
            # not change these databases; read-only verification uses fresh reads.
            for path in sorted(paths):
                lock = stack.enter_context(closing(sqlite3.connect(str(path), timeout=10)))
                lock.execute('BEGIN IMMEDIATE')
            stack.enter_context(conn)
            conn.execute('BEGIN IMMEDIATE')
            actor = identities.authorize(analyst_id, token, 'decide')
            if actor is None:
                return {'status': 'DENIED', 'reason': 'Analyst not authorized'}
            previous = conn.execute('SELECT * FROM response_executions WHERE request_id=? OR idempotency_key=?',
                                    (request_id, idempotency_key)).fetchall()
            if previous:
                if len(previous) == 1 and previous[0]['request_id'] == request_id and previous[0]['idempotency_key'] == idempotency_key:
                    return dict(json.loads(previous[0]['result_json']), replayed=True)
                return {'status': 'DENIED', 'reason': 'Idempotency conflict'}
            row = conn.execute('''SELECT r.*, i.assessment, i.evidence,
                a.source_ip AS alert_source_ip FROM response_requests r
                JOIN incidents i ON i.id=r.incident_id JOIN alerts a ON a.id=i.alert_id
                WHERE r.id=?''', (request_id,)).fetchone()
            if row is None or row['status'] != 'APPROVED':
                return {'status': 'DENIED', 'reason': 'Approved request required'}
            binding = conn.execute('SELECT digest FROM response_approval_bindings WHERE request_id=?', (request_id,)).fetchone()
            audit = conn.execute("SELECT actor FROM response_audit WHERE response_request_id=? AND action='REQUEST_APPROVED' ORDER BY id DESC LIMIT 1", (request_id,)).fetchall()
            if (binding is None or binding['digest'] != approval_digest(row)
                    or len(audit) != 1 or audit[0]['actor'] != row['decided_by']):
                return {'status': 'DENIED', 'reason': 'Approval binding missing or changed'}
            # Read every row on the transaction connection: malformed rows must
            # never disappear through the legacy evidence loader's skip behavior.
            envelopes = conn.execute('SELECT envelope_json FROM incident_evidence WHERE incident_id=?', (row['incident_id'],)).fetchall()
            if not envelopes:
                return {'status': 'DENIED', 'reason': 'Stored evidence required'}
            verified_envelopes = []
            for item in envelopes:
                envelope = json.loads(item['envelope_json'])
                if (not validate_evidence_freshness(envelope)['fresh']
                        or not registry.verify_accepted_evidence(envelope, row['incident_id'])):
                    return {'status': 'DENIED', 'reason': 'Evidence no longer trusted or fresh'}
                verified_envelopes.append(envelope)
            eligible, why = _eligible(row, registry, {'trusted': True, 'envelopes': verified_envelopes})
            if not eligible:
                return {'status': 'DENIED', 'reason': why}
            from .simulation_lifecycle import record_execution_start, verify_execution
            record_execution_start(conn, row, actor['analyst_id'])
            block = conn.execute('INSERT OR IGNORE INTO simulated_blocks (source_ip,response_request_id) VALUES (?,?)',
                                 (row['source_ip'], request_id))
            result = {'status': 'SIMULATED_EXECUTED', 'request_id': request_id,
                      'incident_id': row['incident_id'], 'source_ip': row['source_ip'],
                      'mode': 'SIMULATION_ONLY', 'executed': True,
                      'block_created': block.rowcount == 1, 'executed_by': actor['analyst_id']}
            result = verify_execution(conn, row, result)
            conn.execute("UPDATE response_requests SET status=? WHERE id=? AND status='APPROVED'", (result['status'],request_id))
            conn.execute("UPDATE incidents SET response_action='SIMULATED_BLOCK', response_status=? WHERE id=?", (result['status'],row['incident_id']))
            serialized = json.dumps(result, sort_keys=True)
            conn.execute('INSERT INTO response_executions (request_id,idempotency_key,result_json) VALUES (?,?,?)', (request_id,idempotency_key,serialized))
            conn.execute('''INSERT INTO response_audit (response_request_id,incident_id,action,actor,details)
                VALUES (?,?,?,?,?)''', (request_id,row['incident_id'],result['status'],actor['analyst_id'],serialized))
            return dict(result, replayed=False)
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, AttributeError):
        return {'status': 'DENIED', 'reason': 'Execution service unavailable'}


def execute_response(request_id, idempotency_key, analyst_id, token, identities, registry):
    result = _execute_response(request_id, idempotency_key, analyst_id, token, identities, registry)
    if result['status'] == 'DENIED':
        try:
            with closing(connect()) as conn, conn:
                conn.execute('''INSERT INTO response_execution_denials
                    (request_id,claimed_analyst,reason) VALUES (?,?,?)''',
                    (request_id if type(request_id) is int and 0 < request_id < 2**63 else None,
                     analyst_id[:64] if isinstance(analyst_id, str) else None, result['reason']))
        except (sqlite3.Error, OSError):
            # An unavailable audit database cannot turn a denial into execution.
            result['denial_audit_available'] = False
    return result
