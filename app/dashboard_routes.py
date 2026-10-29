"""Read-only dashboard snapshots. All mutations use existing authenticated routes.

Snapshot eligibility is advisory: execution independently rechecks identity,
freshness, the approval binding and idempotency in its existing transaction.
"""
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import Response, RedirectResponse
from pydantic import BaseModel
from .api_contracts import PositiveID, ERRORS
from .api_security import operator
from .database import connect
from .response_approval import _eligible
from .response_execution import approval_digest
from .evidence_freshness import validate_evidence_freshness

ASSETS = Path(__file__).resolve().parent/'dashboard'
SECURITY_HEADERS = {
    'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff',
    'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY',
    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'; object-src 'none'",
}


class DashboardHeaders:
    """Keep snapshots and auth errors out of caches, including exception responses."""
    def __init__(self,app):
        self.app=app

    async def __call__(self,scope,receive,send):
        if scope['type']!='http' or not scope.get('path','').startswith('/dashboard'):
            return await self.app(scope,receive,send)
        async def protected_send(message):
            if message['type']=='http.response.start':
                additions={key.lower().encode():value.encode() for key,value in SECURITY_HEADERS.items()}
                message=dict(message,headers=[(k,v) for k,v in message.get('headers',[]) if k.lower() not in additions]+list(additions.items()))
            await send(message)
        return await self.app(scope,receive,protected_send)


class IdentityOut(BaseModel):
    analyst_id: str
    role: str
    can_decide: bool
    mode: str = 'SIMULATION_ONLY'
    data_context: Literal['project_database','isolated_demo'] = 'project_database'


class OverviewOut(BaseModel):
    checked_at: str
    mode: str = 'SIMULATION_ONLY'
    counts: dict[str,int]
    incidents: list[dict[str,Any]]
    alerts: list[dict[str,Any]]
    has_more: bool
    next_before_id: int | None


class DetailOut(BaseModel):
    checked_at: str
    mode: str = 'SIMULATION_ONLY'
    incident: dict[str,Any]
    alert: dict[str,Any]
    reasoning: dict[str,Any]
    evidence: list[dict[str,Any]]
    evidence_truncated: bool
    request: dict[str,Any] | None
    eligibility: dict[str,Any]
    telemetry: list[dict[str,Any]]
    audit: list[dict[str,Any]]
    audit_has_more: bool
    timeline: list[dict[str,Any]]
    block_present: bool


def now():
    return datetime.now(timezone.utc).isoformat()


def object_json(value):
    try:
        result = json.loads(value)
        return result if isinstance(result,dict) else {}
    except (TypeError, ValueError):
        return {}


def text(value, limit=1200):
    return value[:limit] if isinstance(value,str) else ''


def reasoning(value):
    value = value if isinstance(value,dict) else {}
    status = value.get('ai_status')
    # These labels describe the stored result, never current provider availability.
    source = 'gemini' if status=='gemini' else ('fallback_rules' if status in ('fallback_rules','gemini_overridden') else 'unknown')
    return {'source':source, 'ai_status':text(status,80),
            'summary':text(value.get('summary') or value.get('reason')),
            'fallback_reason':text(value.get('fallback_reason'),120),
            'model':text(value.get('model'),100),
            'assessment':text(value.get('assessment'),80)}


def summary(row):
    stored = object_json(row['evidence'])
    return {key:row[key] for key in ('id','alert_id','created_at','assessment','confidence',
            'response_status','source_ip','event_type','target','severity')} | {
            'reasoning_source':reasoning(stored.get('outcome'))['source'],
            'request_status':row['request_status'] if 'request_status' in row.keys() else None}


def safe_observations(record):
    evidence = record.get('evidence')
    if not isinstance(evidence,dict):
        return {'tool':'unknown','observations':{}}
    allowed = {'login_attempts','failed_logins','successful_login','session_created',
               'unauthorized_access_observed','http_status'}
    observations = evidence.get('observations')
    return {'tool':text(evidence.get('tool'),80),
            'observations':{k:v for k,v in observations.items()
                if k in allowed and type(v) in (int,bool)} if isinstance(observations,dict) else {}}


def build_dashboard_router(identities, registry_provider):
    router = APIRouter(tags=['dashboard'],responses=ERRORS)

    def identity(ident,token):
        operator(identities,ident,token)
        actor = identities.authorize(ident,token,'view')
        if actor is None:  # Fail closed on revocation between the two reads.
            raise HTTPException(status_code=403,detail='Analyst not authorized')
        return actor

    def asset(name, media):
        try:
            return Response((ASSETS/name).read_bytes(),media_type=media,headers=SECURITY_HEADERS)
        except OSError:
            raise HTTPException(status_code=503,detail='Dashboard assets unavailable') from None

    @router.get('/',include_in_schema=False)
    def home():
        return RedirectResponse('/dashboard',headers=SECURITY_HEADERS)

    @router.get('/dashboard',include_in_schema=False)
    @router.get('/dashboard/',include_in_schema=False)
    def page():
        return asset('index.html','text/html')

    @router.get('/dashboard/assets/dashboard.css',include_in_schema=False)
    def css():
        return asset('dashboard.css','text/css')

    @router.get('/dashboard/assets/dashboard.js',include_in_schema=False)
    def javascript():
        return asset('dashboard.js','text/javascript')

    @router.get('/dashboard/assets/sample.js',include_in_schema=False)
    def sample():
        return asset('sample.js','text/javascript')

    @router.get('/favicon.ico',include_in_schema=False)
    def favicon():
        return Response(status_code=204,headers=SECURITY_HEADERS)

    @router.get('/dashboard/api/identity',response_model=IdentityOut)
    def whoami(x_analyst_id: str | None = Header(default=None),
               x_analyst_token: str | None = Header(default=None)):
        actor = identity(x_analyst_id,x_analyst_token)
        return dict(actor,can_decide=actor['role'] in ('analyst','admin'),
                    data_context='isolated_demo' if os.getenv('SENTINELOPS_DEMO_MODE')=='1' else 'project_database')

    @router.get('/dashboard/api/overview',response_model=OverviewOut)
    def overview(before_id: int | None = Query(default=None,ge=1,le=9223372036854775807),
                 limit: int = Query(default=30,ge=1,le=50),
                 x_analyst_id: str | None = Header(default=None),
                 x_analyst_token: str | None = Header(default=None)):
        identity(x_analyst_id,x_analyst_token)
        with closing(connect()) as conn:
            conn.execute('BEGIN')
            rows = conn.execute('''SELECT i.*,a.source_ip,a.event_type,a.target,a.severity,r.status AS request_status
                FROM incidents i JOIN alerts a ON a.id=i.alert_id
                LEFT JOIN response_requests r ON r.id=(SELECT MAX(r2.id) FROM response_requests r2 WHERE r2.incident_id=i.id)
                WHERE (? IS NULL OR i.id<?) ORDER BY i.id DESC LIMIT ?''',
                (before_id,before_id,limit+1)).fetchall()
            counts = {
                'incidents':conn.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],
                'pending':conn.execute("SELECT COUNT(*) FROM response_requests WHERE status='PENDING'").fetchone()[0],
                'active_effects':conn.execute("SELECT COUNT(*) FROM simulation_effects WHERE state IN ('VERIFIED','LEGACY_UNVERIFIED','VERIFICATION_FAILED')").fetchone()[0],
                'rollbacks':conn.execute('SELECT COUNT(*) FROM response_rollbacks').fetchone()[0],
            }
            alerts = [dict(row) for row in conn.execute('''SELECT id,created_at,source_ip,event_type,
                target,severity,status FROM alerts ORDER BY id DESC LIMIT 10''')]
        has_more = len(rows)>limit
        rows = rows[:limit]
        return {'checked_at':now(),'counts':counts,'incidents':[summary(r) for r in rows],
                'alerts':alerts,'has_more':has_more,'next_before_id':rows[-1]['id'] if has_more else None}

    @router.get('/dashboard/api/incidents/{incident_id}',response_model=DetailOut)
    def detail(incident_id: PositiveID, x_analyst_id: str | None = Header(default=None),
               x_analyst_token: str | None = Header(default=None)):
        actor = identity(x_analyst_id,x_analyst_token)
        registry = registry_provider()
        with closing(connect()) as conn:
            conn.execute('BEGIN')
            incident = conn.execute('''SELECT i.*,a.source_ip,a.event_type,a.target,a.severity,
                a.created_at AS alert_created,a.details AS alert_details FROM incidents i
                JOIN alerts a ON a.id=i.alert_id WHERE i.id=?''',(incident_id,)).fetchone()
            if incident is None:
                raise HTTPException(status_code=404,detail='Incident not found')
            stored = object_json(incident['evidence'])
            evidence_rows = conn.execute('SELECT * FROM incident_evidence WHERE incident_id=? ORDER BY id LIMIT 101',(incident_id,)).fetchall()
            envelopes = []; evidence = []
            all_trusted = bool(evidence_rows) and len(evidence_rows)<=100
            for row in evidence_rows[:100]:
                envelope = object_json(row['envelope_json'])
                record = envelope.get('record')
                record = record if isinstance(record,dict) else {}
                fresh = validate_evidence_freshness(envelope)['fresh']
                trusted = bool(registry and fresh and registry.verify_accepted_evidence(envelope,incident_id))
                all_trusted = all_trusted and trusted
                if trusted:
                    envelopes.append(envelope)
                evidence.append({'id':row['id'],'collector_id':text(row['collector_id'],128),
                    'collected_at':text(record.get('collected_at'),64),
                    'provenance':'authenticated_current' if trusted else 'untrusted_or_expired',
                    'fresh':fresh,**safe_observations(record)})
            request_row = conn.execute('''SELECT r.*,e.state AS lifecycle_state FROM response_requests r
                LEFT JOIN simulation_effects e ON e.request_id=r.id
                WHERE r.incident_id=? ORDER BY r.id DESC LIMIT 1''',(incident_id,)).fetchone()
            request = {key:request_row[key] for key in ('id','incident_id','source_ip','action',
                'status','requested_at','decided_at','decided_by','lifecycle_state')} if request_row else None
            candidate = {'incident_id':incident_id,'assessment':incident['assessment'],
                'evidence':incident['evidence'],'source_ip':incident['source_ip'],
                'alert_source_ip':incident['source_ip'],'action':'SIMULATED_BLOCK'}
            if request:
                candidate.update(source_ip=request['source_ip'],action=request['action'])
            eligible, why = _eligible(candidate,registry,{'trusted':all_trusted,'envelopes':envelopes})
            allowed = actor['role'] in ('analyst','admin')
            binding_valid = False
            if request and request['status']=='APPROVED':
                candidate.update(source_ip=request['source_ip'],action=request['action'])
                binding = conn.execute('SELECT digest FROM response_approval_bindings WHERE request_id=?',(request['id'],)).fetchone()
                approval = conn.execute("SELECT actor FROM response_audit WHERE response_request_id=? AND action='REQUEST_APPROVED'",(request['id'],)).fetchall()
                binding_valid = bool(binding and binding['digest']==approval_digest(candidate)
                    and len(approval)==1 and approval[0]['actor']==request['decided_by'])
            state = request['lifecycle_state'] if request else None
            status = request['status'] if request else None
            if status=='APPROVED' and eligible and not binding_valid:
                why='Approval binding is missing or changed. Execution is unavailable.'
            elif status=='SIMULATED_ROLLED_BACK':
                why='Historical rollback recorded. This request cannot create another effect.'
            elif status=='REJECTED':
                why='Proposal rejected. No execution is available.'
            elif state in ('VERIFIED','LEGACY_UNVERIFIED','VERIFICATION_FAILED'):
                why='An executed simulation is recorded. Verification and rollback require an authorized analyst.'
            elif status=='PENDING' and eligible:
                why='Current collector evidence is verified. An analyst decision is required.'
            if not allowed:
                why+=' Viewer access is read-only.'
            # Actions are only hints; the existing POST endpoint is authoritative.
            eligibility = {'advisory':True,'reason':why,'evidence_current':all_trusted,
                'can_review':allowed and not request and all_trusted and len(evidence)==2,
                'can_propose':allowed and not request and eligible,
                'can_approve':allowed and status=='PENDING' and eligible,
                'can_reject':allowed and status=='PENDING' and registry is not None,
                'can_execute':allowed and status=='APPROVED' and eligible and binding_valid,
                'can_verify':allowed and state in ('VERIFIED','LEGACY_UNVERIFIED','VERIFICATION_FAILED'),
                'can_rollback':allowed and state in ('VERIFIED','LEGACY_UNVERIFIED','VERIFICATION_FAILED')}
            audit_rows = conn.execute('SELECT * FROM response_audit WHERE incident_id=? ORDER BY id DESC LIMIT 101',(incident_id,)).fetchall()
            audit = []
            for row in reversed(audit_rows[:100]):
                data = object_json(row['details'])
                safe = {key:value for key,value in data.items() if key in (
                    'reason','assessment','status','mode','verification_status','block_retained','replayed')
                    and type(value) in (str,bool,int)}
                audit.append({'id':row['id'],'action':row['action'],'actor':row['actor'],
                    'created_at':row['created_at'],'request_id':row['response_request_id'],'details':safe})
            telemetry = []
            if request:
                for row in conn.execute('SELECT * FROM simulation_telemetry WHERE request_id=? ORDER BY id DESC LIMIT 20',(request['id'],)):
                    telemetry.append({key:row[key] for key in ('id','operation','source','created_at')} |
                        {key:bool(row[key]) for key in ('expected_blocked','observed_blocked','matched')})
            block_present = conn.execute('SELECT 1 FROM simulated_blocks WHERE source_ip=?',(incident['source_ip'],)).fetchone() is not None
        investigation = stored.get('investigation')
        investigation = investigation if isinstance(investigation,dict) else {}
        trace = investigation.get('trace',[])
        steps = []
        for step in trace[:20] if isinstance(trace,list) else []:
            if not isinstance(step,dict):
                continue
            result = step.get('result',{})
            result = result if isinstance(result,dict) else {}
            steps.append({'tool':text(step.get('tool'),80),'status':text(result.get('status'),80),
                'source':text(result.get('source'),80),
                'reasoning_source':text(step.get('reasoning_source'),80)})
        return {'checked_at':now(),'incident':summary(incident) | {'request_status':status},
            'alert':{'id':incident['alert_id'],'created_at':incident['alert_created'],
                'source_ip':incident['source_ip'],'event_type':incident['event_type'],
                'target':incident['target'],'details':text(incident['alert_details'],2000),'severity':incident['severity']},
            'reasoning':{'triage':reasoning(stored.get('triage')),'outcome':reasoning(stored.get('outcome')),'steps':steps},
            'evidence':evidence,'evidence_truncated':len(evidence_rows)>100,'request':request,
            'eligibility':eligibility,'telemetry':telemetry,'audit':audit,'audit_has_more':len(audit_rows)>100,
            'timeline':[{'at':incident['alert_created'],'title':'Alert recorded','detail':incident['event_type']},
                {'at':incident['created_at'],'title':'Investigation recorded','detail':incident['assessment']}] +
                [{'at':a['created_at'],'title':a['action'],'detail':a['actor']} for a in audit],
            'block_present':block_present}

    return router
