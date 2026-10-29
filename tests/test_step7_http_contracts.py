"""Production ASGI app: HTTP-only incident workflow and public contract checks."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import database
from app.evidence_signing import create_signed_evidence
from app.persistent_collector_registry import PersistentCollectorRegistry


class Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.TemporaryDirectory()
        cls.identity_env = patch.dict(os.environ,{'SENTINELOPS_ANALYST_DB':str(Path(cls.root.name)/'identities.sqlite')})
        cls.identity_env.start()
        import app.main as main
        cls.main = main
        cls.serial = 0

    @classmethod
    def tearDownClass(cls):
        cls.identity_env.stop()
        cls.root.cleanup()

    def setUp(self):
        type(self).serial += 1
        self.tmp = tempfile.TemporaryDirectory(dir=self.root.name)
        root = Path(self.tmp.name)
        self.key = 'http-collector-test-key-'+'c'*40
        registry = PersistentCollectorRegistry(str(root/'registry.sqlite'))
        registry.register_collector('http_collector',self.key)
        self.registry = registry
        env = {'SENTINELOPS_DB':str(root/'incidents.sqlite'),
               'SENTINELOPS_REGISTRY_DB':str(root/'registry.sqlite'),
               'SENTINELOPS_COLLECTOR_ID':'http_collector','SENTINELOPS_COLLECTOR_KEY':self.key,
               'SENTINELOPS_API_KEY':'step7-private-test-api-key','GEMINI_API_KEY':''}
        self.env = patch.dict(os.environ,env); self.env.start()
        self.db = patch.object(database,'DB_PATH',env['SENTINELOPS_DB']); self.db.start()
        actor = self.main.analyst_store.create_analyst(f'http_actor_{self.serial}','analyst')
        viewer = self.main.analyst_store.create_analyst(f'http_viewer_{self.serial}','viewer')
        self.actor = actor
        self.headers = {'X-Analyst-Id':actor['analyst_id'],'X-Analyst-Token':actor['token']}
        self.viewer = {'X-Analyst-Id':viewer['analyst_id'],'X-Analyst-Token':viewer['token']}
        self.api = {'X-API-Key':env['SENTINELOPS_API_KEY']}
        self.client = TestClient(self.main.app,raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None,None,None)
        self.db.stop(); self.env.stop()
        self.tmp.cleanup()

    def ok(self,response,status=200):
        self.assertEqual(response.status_code,status,response.text)
        return response.json()

    def incident(self):
        alert = self.ok(self.client.post('/webhook/alert',headers=self.api,json={
            'source_ip':'8.8.8.8','event_type':'failed_login','target':'demo-login',
            'details':'Controlled HTTP fixture','severity':'high'}))
        investigated = self.ok(self.client.post(f"/alerts/{alert['id']}/investigate",headers=self.api))
        self.assertNotEqual(investigated['assessment'],'ATTACK_CONFIRMED')
        return investigated['incident_id']

    def submit(self,incident,tool,observations,source_ip='8.8.8.8'):
        envelope = create_signed_evidence(incident,'http_collector',{
            'source_ip':source_ip,'tool':tool,'observations':observations},self.key)
        response = self.client.post(f'/incidents/{incident}/evidence/submit',headers=self.api,json={'envelope':envelope})
        self.ok(response)
        return envelope

    def authenticated_incident(self):
        incident = self.incident()
        self.submit(incident,'authentication_logs',{'login_attempts':5,'failed_logins':4,'successful_login':True,'session_created':True})
        self.submit(incident,'application_logs',{'unauthorized_access_observed':True,'http_status':200})
        result = self.ok(self.client.post(f'/incidents/{incident}/investigate-authenticated',headers=self.headers))
        self.assertEqual(result['assessment'],'ATTACK_CONFIRMED')
        self.assertFalse(result['executed'])
        return incident

    def approved(self):
        incident = self.authenticated_incident()
        proposal = self.ok(self.client.post(f'/response-requests/for-incident/{incident}',headers=self.headers))
        request = proposal['request_id']
        approval = self.ok(self.client.post(f'/response-requests/{request}/decision',headers=self.headers,json={'decision':'APPROVED','reason':'Authenticated observations reviewed'}))
        self.assertFalse(approval['executed'])
        return incident,request

    def executed(self):
        incident,request = self.approved()
        result = self.ok(self.client.post(f'/response-requests/{request}/execute',headers=dict(self.headers,**{'Idempotency-Key':'http-execution-0001'})))
        self.assertEqual(result['verification_status'],'VERIFIED')
        self.assertEqual(result['telemetry']['source'],'synthetic_sqlite_probe')
        return incident,request

    def test_entire_http_flow_verify_rollback_and_audit(self):
        incident,request = self.executed()
        self.ok(self.client.post(f'/response-requests/{request}/verify',headers=self.headers))
        read = self.ok(self.client.get(f'/response-requests/{request}',headers=self.viewer))
        self.assertEqual(read['lifecycle_state'],'VERIFIED')
        rollback_headers = dict(self.headers,**{'Idempotency-Key':'http-rollback-0001'})
        endpoint = f'/response-requests/{request}/rollback'
        rolled = self.ok(self.client.post(endpoint,headers=rollback_headers,json={'reason':'Demo complete; restore simulation'}))
        self.assertFalse(rolled['block_retained'])
        self.assertTrue(rolled['telemetry']['matched'])
        retry = self.ok(self.client.post(endpoint,headers=rollback_headers,json={'reason':'Safe retry of same operation'}))
        self.assertTrue(retry['replayed'])
        self.assertEqual(retry['reason'],rolled['reason'])
        self.assertEqual(self.ok(self.client.get('/simulated-blocks',headers=self.viewer)),[])
        actions = self.ok(self.client.get('/audit-history',headers=self.viewer,params={'request_id':request}))
        self.assertEqual(sum(r['action']=='SIMULATED_ROLLED_BACK' for r in actions),1)
        self.assertTrue(any(r['action']=='SIMULATION_EXECUTING' for r in actions))
        self.assertTrue(any(r['action']=='REQUEST_APPROVED' for r in actions))
        self.assertEqual(self.ok(self.client.get(f'/response-requests/{request}',headers=self.viewer))['lifecycle_state'],'ROLLED_BACK')

    def test_protected_reads_and_viewer_mutation_denial(self):
        for path in ['/alerts','/incidents','/response-requests','/audit-history','/simulated-blocks']:
            self.ok(self.client.get(path),401)
            self.ok(self.client.get(path,headers=self.viewer))
        for suffix,payload in [('decision',{'decision':'REJECTED','reason':'Viewer denied'}),('execute',None),('verify',None),('rollback',{'reason':'Viewer denied'})]:
            response = self.client.post('/response-requests/1/'+suffix,headers=dict(self.viewer,**{'Idempotency-Key':'viewer-denial-0001'}),json=payload)
            self.ok(response,403)
        self.ok(self.client.post('/analysts',headers=self.headers,json={}),404)
        self.ok(self.client.post('/collectors',headers=self.headers,json={}),404)

    def test_synthetic_or_incomplete_evidence_cannot_authorize(self):
        incident = self.incident()
        self.ok(self.client.post(f'/response-requests/for-incident/{incident}',headers=self.headers),403)
        self.ok(self.client.post(f'/incidents/{incident}/investigate-authenticated',headers=self.headers),409)
        self.submit(incident,'authentication_logs',{'login_attempts':5,'failed_logins':4,'successful_login':True,'session_created':True})
        self.ok(self.client.post(f'/incidents/{incident}/investigate-authenticated',headers=self.headers),409)
        self.assertEqual(self.ok(self.client.get('/response-requests',headers=self.headers)),[])

    def test_source_mismatch_and_strict_observation_types(self):
        incident = self.incident()
        self.submit(incident,'authentication_logs',{'login_attempts':5,'failed_logins':4,'successful_login':True,'session_created':True},source_ip='1.1.1.1')
        self.submit(incident,'application_logs',{'unauthorized_access_observed':True,'http_status':200})
        self.ok(self.client.post(f'/incidents/{incident}/investigate-authenticated',headers=self.headers),409)
        other = self.incident()
        self.submit(other,'authentication_logs',{'login_attempts':5,'failed_logins':4,'successful_login':'true','session_created':True})
        self.submit(other,'application_logs',{'unauthorized_access_observed':True,'http_status':200})
        self.ok(self.client.post(f'/incidents/{other}/investigate-authenticated',headers=self.headers),409)

    def test_collector_revocation_between_ingestion_and_assessment(self):
        incident = self.incident()
        self.submit(incident,'authentication_logs',{'login_attempts':5,'failed_logins':4,'successful_login':True,'session_created':True})
        self.submit(incident,'application_logs',{'unauthorized_access_observed':True,'http_status':200})
        self.registry.revoke_collector('http_collector')
        self.ok(self.client.post(f'/incidents/{incident}/investigate-authenticated',headers=self.headers),409)
        summaries = self.ok(self.client.get(f'/incidents/{incident}/evidence',headers=self.headers))
        self.assertTrue(all(r['provenance']=='untrusted_or_expired' for r in summaries))

    def test_predictable_safe_error_contracts(self):
        self.assertEqual(self.ok(self.client.post('/webhook/alert',json={}),422)['code'],'INVALID_INPUT')
        invalid = self.client.post('/webhook/alert',headers=self.api,json={'source_ip':'bad-ip','token':self.actor['token']})
        error = self.ok(invalid,422)
        self.assertEqual(set(error),{'detail','code'})
        self.assertNotIn(self.actor['token'],invalid.text)
        self.assertEqual(self.ok(self.client.get('/unknown'),404)['code'],'NOT_FOUND')
        self.assertEqual(self.ok(self.client.get('/alerts'),401)['code'],'AUTHENTICATION_REQUIRED')
        self.assertEqual(self.ok(self.client.get('/alerts?limit=101',headers=self.headers),422)['code'],'INVALID_INPUT')
        with patch.object(self.main,'connect',side_effect=sqlite3.OperationalError('private database path / secret='+self.key)):
            response = self.client.get('/alerts',headers=self.headers)
            self.assertEqual(self.ok(response,503)['code'],'SERVICE_UNAVAILABLE')
            self.assertNotIn(self.key,response.text)
            self.assertNotIn('database path',response.text)
        huge = self.client.post('/webhook/alert',headers=self.api,content=b'x'*131073)
        self.assertEqual(self.ok(huge,413)['code'],'PAYLOAD_TOO_LARGE')

    def test_secrets_and_signatures_not_returned(self):
        incident = self.authenticated_incident()
        for endpoint in ['/incidents',f'/incidents/{incident}/evidence','/audit-history']:
            response = self.client.get(endpoint,headers=self.headers)
            self.ok(response)
            for secret in [self.key,self.api['X-API-Key'],self.actor['token']]:
                self.assertNotIn(secret,response.text)
        with patch.object(self.main,'analyze_alert',return_value={'assessment':'INCONCLUSIVE','api_key':self.key,'reason':self.api['X-API-Key']}):
            alert = self.ok(self.client.post('/simulate/attack',headers=self.api,json={'scenario':'normal_login'}))
            response = self.client.post(f"/alerts/{alert['id']}/investigate",headers=self.api)
            self.ok(response)
            self.assertNotIn(self.key,response.text)
            self.assertNotIn(self.api['X-API-Key'],response.text)
            self.assertIn('[REDACTED]',response.text)

    def test_openapi_models_examples_and_cors(self):
        schema = self.ok(self.client.get('/openapi.json'))
        for path,operations in schema['paths'].items():
            for method,operation in operations.items():
                if method in ('get','post'):
                    response = operation['responses']['200']['content']['application/json']['schema']
                    self.assertTrue(response, path)
                    self.assertIn('503',operation['responses'])
                    self.assertIn('422',operation['responses'])
        self.assertIn('SignedEnvelopeIn',schema['components']['schemas'])
        signature_schema = schema['components']['schemas']['SignedEnvelopeIn']['properties']['signature']
        self.assertIsInstance(signature_schema,dict)
        self.assertEqual(signature_schema['pattern'],'^[a-f0-9]{64}$')
        self.assertIn('RollbackOut',schema['components']['schemas'])
        cors = self.client.options('/response-requests/1/rollback',headers={
            'Origin':'http://localhost:5500','Access-Control-Request-Method':'POST',
            'Access-Control-Request-Headers':'x-analyst-id,x-analyst-token,idempotency-key'})
        self.assertEqual(cors.status_code,200,cors.text)

    def test_existing_proposal_freezes_authenticated_investigation(self):
        incident = self.authenticated_incident()
        self.ok(self.client.post(f'/response-requests/for-incident/{incident}',headers=self.headers))
        self.ok(self.client.post(f'/incidents/{incident}/investigate-authenticated',headers=self.headers),409)


if __name__=='__main__':
    unittest.main(verbosity=2)
