from .api_contracts import PositiveID
"""Protected, bounded operational read contracts; evidence is summarized."""
import json
from contextlib import closing
from fastapi import APIRouter, Header, HTTPException, Query
from .api_contracts import ERRORS, RequestOut, AuditOut, EvidenceSummary, BlockOut
from .api_security import operator
from .database import connect


def build_read_router(identities, registry_provider):
    router = APIRouter(tags=['analyst-review'],responses=ERRORS)

    def auth(ident,token):
        operator(identities,ident,token)

    def requests(conn,where='',params=()):
        return conn.execute('''SELECT r.*,e.state AS lifecycle_state FROM response_requests r
            LEFT JOIN simulation_effects e ON e.request_id=r.id '''+where,params).fetchall()

    @router.get('/response-requests',response_model=list[RequestOut])
    def list_requests(after_id: int = Query(default=0,ge=0,le=9223372036854775807),limit: int = Query(default=100,ge=1,le=100),
                      x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
        auth(x_analyst_id,x_analyst_token)
        with closing(connect()) as conn:
            return [dict(r) for r in requests(conn,'WHERE r.id>? ORDER BY r.id LIMIT ?',(after_id,limit))]

    @router.get('/response-requests/{request_id}',response_model=RequestOut)
    def get_request(request_id: PositiveID,
                    x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
        auth(x_analyst_id,x_analyst_token)
        with closing(connect()) as conn:
            rows = requests(conn,'WHERE r.id=?',(request_id,))
        if not rows:
            raise HTTPException(status_code=404,detail='Response request not found')
        return dict(rows[0])

    @router.get('/audit-history',response_model=list[AuditOut])
    def audit_history(after_id: int = Query(default=0,ge=0,le=9223372036854775807),limit: int = Query(default=100,ge=1,le=100),
                      request_id: int | None = Query(default=None,gt=0,le=9223372036854775807),
                      x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
        auth(x_analyst_id,x_analyst_token)
        with closing(connect()) as conn:
            rows = conn.execute('SELECT * FROM response_audit WHERE id>? AND (? IS NULL OR response_request_id=?) ORDER BY id LIMIT ?',
                                (after_id,request_id,request_id,limit)).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            try:
                details = json.loads(item['details'])
                item['details'] = details if isinstance(details,dict) else {'error':'Invalid audit details'}
            except (TypeError,ValueError):
                item['details'] = {'error':'Invalid audit details'}
            output.append(item)
        return output

    @router.get('/incidents/{incident_id}/evidence',response_model=list[EvidenceSummary])
    def evidence_summary(incident_id: PositiveID,
                         x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
        auth(x_analyst_id,x_analyst_token)
        registry = registry_provider()
        with closing(connect()) as conn:
            if not conn.execute('SELECT 1 FROM incidents WHERE id=?',(incident_id,)).fetchone():
                raise HTTPException(status_code=404,detail='Incident not found')
            rows = conn.execute('SELECT * FROM incident_evidence WHERE incident_id=? ORDER BY id LIMIT 100',(incident_id,)).fetchall()
        result = []
        for row in rows:
            item = {'id':row['id'],'incident_id':incident_id,'collector_id':row['collector_id'],
                    'collected_at':None,'provenance':'malformed'}
            try:
                envelope = json.loads(row['envelope_json'])
                timestamp = envelope['record']['collected_at']
                item['collected_at'] = timestamp if isinstance(timestamp,str) else None
                trusted = registry is not None and registry.verify_accepted_evidence(envelope,incident_id)
                item['provenance'] = 'authenticated_current' if trusted else 'untrusted_or_expired'
            except (ValueError,TypeError,KeyError):
                pass
            result.append(item)
        return result

    @router.get('/simulated-blocks',response_model=list[BlockOut])
    def list_blocks(limit: int = Query(default=100,ge=1,le=100),
                    x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
        auth(x_analyst_id,x_analyst_token)
        with closing(connect()) as conn:
            return [dict(r) for r in conn.execute('SELECT * FROM simulated_blocks ORDER BY source_ip LIMIT ?',(limit,))]

    return router
