"""Full production FastAPI app, lifespan and real in-process HTTP transport."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import os
import tempfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import database
from app.evidence_signing import create_signed_evidence
from app.persistent_collector_registry import PersistentCollectorRegistry


def run():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        key = 'c'*64
        registry = PersistentCollectorRegistry(str(root/'registry.sqlite'))
        registry.register_collector('collector_http',key)
        env = {'SENTINELOPS_DB':str(root/'incidents.sqlite'),
               'SENTINELOPS_ANALYST_DB':str(root/'analysts.sqlite'),
               'SENTINELOPS_REGISTRY_DB':str(root/'registry.sqlite'),
               'SENTINELOPS_COLLECTOR_ID':'collector_http', 'SENTINELOPS_COLLECTOR_KEY':key,
               'SENTINELOPS_API_KEY':'test-api-key'}
        with patch.dict(os.environ,env), patch.object(database,'DB_PATH',env['SENTINELOPS_DB']):
            from app.main import app, analyst_store
            actor = analyst_store.create_analyst('http_analyst','analyst')
            headers = {'X-Analyst-Id':actor['analyst_id'],'X-Analyst-Token':actor['token']}
            with TestClient(app) as client:
                assert client.get('/health').status_code == 200
                # The existing synthetic investigation must not authorize a response.
                alert = client.post('/webhook/alert',headers={'X-API-Key':'test-api-key'},json={
                    'source_ip':'8.8.8.8','event_type':'failed_login','target':'http-test',
                    'details':'collector test','severity':'high'})
                assert alert.status_code == 200,alert.text
                with closing(database.connect()) as conn,conn:
                    incident = conn.execute("INSERT INTO incidents (alert_id,assessment,confidence,evidence,response_action,response_status) VALUES (?,'ATTACK_CONFIRMED','high','{}','REVIEW','SIMULATED_ONLY')",(alert.json()['id'],)).lastrowid
                envelope = create_signed_evidence(incident,'collector_http',{'event':'test-verified'},key)
                submitted = client.post(f'/incidents/{incident}/evidence/submit',headers={'X-API-Key':'test-api-key'},json={'envelope':envelope})
                assert submitted.status_code == 200,submitted.text
                outcome = {'outcome':{'assessment':'ATTACK_CONFIRMED','ai_status':'fallback_rules'},'investigation':{'trace':[{'result':{'status':'completed','source':'authenticated_collector','signed_evidence':envelope}}]}}
                with closing(database.connect()) as conn,conn:
                    conn.execute('UPDATE incidents SET evidence=? WHERE id=?',(json.dumps(outcome),incident))
                proposed = client.post(f'/response-requests/for-incident/{incident}',headers=headers)
                assert proposed.status_code == 200,proposed.text
                request = proposed.json()['request_id']
                url = f'/response-requests/{request}'
                assert client.post(url+'/execute').status_code == 401
                assert client.post(url+'/decision',headers=headers,json={'decision':'APPROVED','reason':'x'}).status_code == 422
                approved = client.post(url+'/decision',headers=headers,json={'decision':'APPROVED','reason':'Authenticated incident reviewed'})
                assert approved.status_code == 200 and approved.json()['executed'] is False, approved.text
                assert client.post(url+'/execute',headers=headers).status_code == 403
                execute_headers = dict(headers,**{'Idempotency-Key':'http-execution-0001'})
                first = client.post(url+'/execute',headers=execute_headers)
                assert first.status_code == 200,first.text
                assert first.json()['mode'] == 'SIMULATION_ONLY' and not first.json()['replayed']
                assert client.post(url+'/execute',headers=execute_headers).json()['replayed']
                assert client.post(url+'/execute',headers=dict(headers,**{'Idempotency-Key':'http-execution-0002'})).status_code == 403
                with closing(database.connect()) as conn:
                    assert conn.execute('SELECT COUNT(*) FROM simulated_blocks').fetchone()[0] == 1
                    assert conn.execute("SELECT COUNT(*) FROM response_audit WHERE action='SIMULATED_EXECUTED'").fetchone()[0] == 1
                assert '/response-requests/{request_id}/execute' in client.get('/openapi.json').json()['paths']
                cors = client.options(url+'/execute',headers={'Origin':'http://localhost:5500','Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'x-analyst-id,x-analyst-token,idempotency-key'})
                assert cors.status_code == 200,cors.text
            assert app.state.collector_registry is None
    print('STEP 6 FULL API LIFECYCLE, VALIDATION, EXECUTION, RETRY, CORS AND CLEANUP: PASSED')


if __name__ == '__main__':
    run()
