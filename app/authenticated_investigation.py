"""Deterministic incident assessment from exact currently authenticated records.

Collector data is data, never instructions. AI output alone cannot authorize action.
"""
import json
from contextlib import closing
from ipaddress import ip_address
from fastapi import HTTPException
from .database import connect
from .api_contracts import CollectorObservation, AuthObservations, AppObservations
from .outcome_reasoner import verified_outcome


def investigate_authenticated(incident_id,registry,actor):
    if registry is None:
        raise HTTPException(status_code=503,detail='Collector registry unavailable')
    with closing(connect()) as conn,conn:
        conn.execute('BEGIN IMMEDIATE')
        incident = conn.execute('SELECT i.*,a.source_ip FROM incidents i JOIN alerts a ON a.id=i.alert_id WHERE i.id=?',(incident_id,)).fetchone()
        if incident is None:
            raise HTTPException(status_code=404,detail='Incident not found')
        if conn.execute('SELECT 1 FROM response_requests WHERE incident_id=?',(incident_id,)).fetchone():
            raise HTTPException(status_code=409,detail='Response proposal already exists; investigation is frozen')
        rows = conn.execute('SELECT envelope_json FROM incident_evidence WHERE incident_id=? ORDER BY id',(incident_id,)).fetchall()
        observations = {}
        trace = []
        try:
            for row in rows:
                envelope = json.loads(row['envelope_json'])
                if not registry.verify_accepted_evidence(envelope,incident_id):
                    raise ValueError('Untrusted record')
                record = CollectorObservation.model_validate(envelope['record']['evidence'])
                if record.source_ip != str(ip_address(incident['source_ip'])) or record.tool in observations:
                    raise ValueError('Binding or tool mismatch')
                model = AuthObservations if record.tool=='authentication_logs' else AppObservations
                obs = model.model_validate(record.observations).model_dump()
                if record.tool=='authentication_logs' and obs['failed_logins'] > obs['login_attempts']:
                    raise ValueError('Invalid login counts')
                if record.tool=='authentication_logs' and (
                    (obs['session_created'] and not obs['successful_login'])
                    or (obs['successful_login'] and obs['failed_logins'] >= obs['login_attempts'])
                ):
                    raise ValueError('Contradictory authentication observations')
                observations[record.tool] = obs
                trace.append({'tool':record.tool,'result':{'status':'completed','source':'authenticated_collector',
                                                         'signed_evidence':envelope}})
            if set(observations) != {'authentication_logs','application_logs'}:
                raise ValueError('Corroborating records required')
            assessment = verified_outcome(observations)
        except (ValueError,TypeError,KeyError,OverflowError):
            raise HTTPException(status_code=409,detail='Complete current authenticated observations required') from None
        evidence = {'triage':{'assessment':'REQUIRES_REVIEW','ai_status':'fallback_rules'},
                    'investigation':{'trace':trace,'provenance':'authenticated_current'},
                    'outcome':{'assessment':assessment,'ai_status':'fallback_rules',
                               'reason':'Deterministic assessment of corroborating collector observations',
                               'observations':observations}}
        conn.execute("UPDATE incidents SET assessment=?,evidence=?,response_action='RECOMMEND_ANALYST_REVIEW',response_status='SIMULATED_ONLY' WHERE id=?",
                     (assessment,json.dumps(evidence),incident_id))
        conn.execute("INSERT INTO response_audit (response_request_id,incident_id,action,actor,details) VALUES (NULL,?,'AUTHENTICATED_INVESTIGATION',?,?)",(incident_id,actor,json.dumps({'assessment':assessment,'mode':'SIMULATION_ONLY'})))
    return {'incident_id':incident_id,'assessment':assessment,'ai_status':'fallback_rules',
            'provenance':'authenticated_current','response_action':'RECOMMEND_ANALYST_REVIEW','executed':False}
