"""Fail-closed, audited analyst decisions. Never executes firewall or simulated blocks."""
import json
import sqlite3
from contextlib import closing
from ipaddress import ip_address
from .database import connect
from .response_policy import evaluate_response
from .authenticated_evidence_service import load_verified_incident_evidence
from .evidence_integrity import canonicalize_evidence


def _eligible(incident, registry, verified=None):
    if registry is None:
        return False, 'Collector registry unavailable'
    if incident['action'] != 'SIMULATED_BLOCK':
        return False, 'Unsupported response action'
    if incident['assessment'] != 'ATTACK_CONFIRMED':
        return False, 'Attack not confirmed'
    try:
        evidence = json.loads(incident['evidence'])
        outcome = evidence['outcome']
        trace = evidence['investigation']['trace']
        ip = str(ip_address(incident['source_ip']))
        if (not isinstance(outcome, dict) or outcome.get('assessment') != 'ATTACK_CONFIRMED'
                or outcome.get('ai_status') not in ('gemini', 'gemini_overridden', 'fallback_rules')
                or not isinstance(trace, list) or not trace
                or ip != incident['alert_source_ip']):
            return False, 'Incident outcome or source mismatch'
        if evaluate_response({'assessment': incident['assessment']}, ip).get('action') != 'PROPOSE_SIMULATED_BLOCK':
            return False, 'Response policy denied'
        if verified is None:
            verified = load_verified_incident_evidence(incident['incident_id'], registry)
        if verified.get('trusted') is not True:
            return False, 'Collector evidence not trusted'
        stored = {canonicalize_evidence(x) for x in verified['envelopes']}
        for step in trace:
            if not isinstance(step, dict) or not isinstance(step.get('result'), dict):
                return False, 'Malformed trace'
            result = step['result']
            if (result.get('status') != 'completed'
                    or result.get('source') in ('synthetic_scenario', 'synthetic_placeholder')
                    or not isinstance(result.get('signed_evidence'), dict)
                    or canonicalize_evidence(result['signed_evidence']) not in stored):
                return False, 'Trace is not authenticated'
        return True, 'Verified'
    except (KeyError, TypeError, ValueError, OverflowError, sqlite3.Error, OSError):
        return False, 'Evidence verification failed'


def decide_response(request_id, decision, analyst_id, token, identities, registry, reason):
    """Return a decision result. Only PENDING -> APPROVED/REJECTED, atomic and audited."""
    if type(request_id) is not int or request_id <= 0:
        return {'status': 'DENIED', 'reason': 'Invalid request ID'}
    if decision not in ('APPROVED', 'REJECTED'):
        return {'status': 'DENIED', 'reason': 'Invalid decision'}
    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 500:
        return {'status': 'DENIED', 'reason': 'Reason must be 3 to 500 characters'}
    if identities is None or registry is None:
        return {'status': 'DENIED', 'reason': 'Authorization dependencies unavailable'}
    try:
        with closing(connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            # Authenticate while holding decision lock to prevent competing decisions.
            actor = identities.authorize(analyst_id, token, 'decide')
            if actor is None:
                return {'status': 'DENIED', 'reason': 'Analyst not authorized'}
            request = conn.execute('''SELECT r.id, r.incident_id, r.source_ip, r.action, r.status,
                i.assessment, i.evidence, a.source_ip AS alert_source_ip
                FROM response_requests r JOIN incidents i ON i.id=r.incident_id
                JOIN alerts a ON a.id=i.alert_id WHERE r.id=?''', (request_id,)).fetchone()
            if request is None:
                return {'status': 'DENIED', 'reason': 'Request not found'}
            if request['status'] != 'PENDING':
                return {'status': 'DENIED', 'reason': 'Request already decided'}
            # Both approvals and rejections require an authorized analyst. Only approvals
            # need trusted evidence; analysts must be able to reject unsafe proposals.
            if decision == 'APPROVED':
                eligible, why = _eligible(request, registry)
                if not eligible:
                    return {'status': 'DENIED', 'reason': why}
            if decision == 'APPROVED':
                from .response_execution import approval_digest
                conn.execute('CREATE TABLE IF NOT EXISTS response_approval_bindings (request_id INTEGER PRIMARY KEY, digest TEXT NOT NULL)')
                conn.execute('INSERT INTO response_approval_bindings VALUES (?,?)',
                             (request_id, approval_digest(request)))
            result = conn.execute('''UPDATE response_requests SET status=?, decided_at=datetime('now'),
                decided_by=? WHERE id=? AND status='PENDING' ''',
                (decision, actor['analyst_id'], request_id))
            if result.rowcount != 1:
                return {'status': 'DENIED', 'reason': 'Concurrent decision detected'}
            conn.execute('''INSERT INTO response_audit
                (response_request_id, incident_id, action, actor, details)
                VALUES (?, ?, ?, ?, ?)''', (request_id, request['incident_id'],
                'REQUEST_' + decision, actor['analyst_id'], json.dumps({'reason': reason.strip()})))
            return {'status': decision, 'request_id': request_id,
                    'incident_id': request['incident_id'], 'decided_by': actor['analyst_id'],
                    'executed': False}
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return {'status': 'DENIED', 'reason': 'Decision service unavailable'}
