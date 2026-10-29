"""ASGI dashboard contracts, safe snapshots and existing response authorization."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import unittest
from unittest.mock import patch
import test_step7_http_contracts as baseline
from app import database
from app.dashboard_routes import reasoning


class Dashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline.Contracts.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        baseline.Contracts.tearDownClass.__func__(cls)

    setUp=baseline.Contracts.setUp
    tearDown=baseline.Contracts.tearDown
    ok=baseline.Contracts.ok
    incident=baseline.Contracts.incident
    submit=baseline.Contracts.submit
    authenticated_incident=baseline.Contracts.authenticated_incident
    approved=baseline.Contracts.approved
    executed=baseline.Contracts.executed

    def detail(self,incident,headers=None):
        return self.ok(self.client.get(f'/dashboard/api/incidents/{incident}',headers=headers or self.headers))

    def dump(self,path):
        with closing(sqlite3.connect(path)) as connection:
            return '\n'.join(connection.iterdump())

    def test_public_shell_assets_and_security_headers(self):
        for path,content in [('/dashboard','Analyst workspace'),('/dashboard/','SIMULATED / NOT PRODUCTION'),
            ('/dashboard/assets/dashboard.js','same-origin'),('/dashboard/assets/dashboard.css','@media'),
            ('/dashboard/assets/sample.js','sample_only')]:
            response=self.client.get(path)
            self.assertEqual(response.status_code,200,response.text)
            self.assertIn(content,response.text)
            self.assertEqual(response.headers['cache-control'],'no-store')
            self.assertEqual(response.headers['x-content-type-options'],'nosniff')
            self.assertIn("frame-ancestors 'none'",response.headers['content-security-policy'])
            self.assertNotIn('unsafe-inline',response.headers['content-security-policy'])
        self.assertEqual(self.client.get('/dashboard/assets/.env').status_code,404)
        self.assertEqual(self.client.get('/dashboard/assets/dashboard_routes.py').status_code,404)
        self.assertEqual(self.client.get('/').status_code,200)

    def test_snapshots_require_identity_and_never_return_token(self):
        for path in ['/dashboard/api/identity','/dashboard/api/overview','/dashboard/api/incidents/1']:
            response=self.client.get(path)
            self.assertEqual(response.status_code,401)
            self.assertEqual(response.headers['cache-control'],'no-store')
            response=self.client.get(path,headers=dict(self.headers,**{'X-Analyst-Token':'invalid'}))
            self.assertEqual(response.status_code,403)
        actor=self.ok(self.client.get('/dashboard/api/identity',headers=self.headers))
        viewer=self.ok(self.client.get('/dashboard/api/identity',headers=self.viewer))
        self.assertTrue(actor['can_decide']); self.assertFalse(viewer['can_decide'])
        self.assertEqual(set(actor),{'analyst_id','role','can_decide','mode','data_context'})
        self.assertNotIn(self.actor['token'],json.dumps(actor))

    def test_empty_state_pagination_and_request_state(self):
        empty=self.ok(self.client.get('/dashboard/api/overview',headers=self.headers))
        self.assertEqual(empty['counts']['incidents'],0)
        self.assertEqual(empty['incidents'],[])
        ids=[self.incident() for _ in range(3)]
        page=self.ok(self.client.get('/dashboard/api/overview?limit=2',headers=self.headers))
        self.assertEqual([row['id'] for row in page['incidents']],list(reversed(ids))[:2])
        self.assertTrue(page['has_more'])
        next_page=self.ok(self.client.get('/dashboard/api/overview',params={'limit':2,'before_id':page['next_before_id']},headers=self.headers))
        self.assertEqual([r['id'] for r in next_page['incidents']],[ids[0]])
        self.assertFalse(next_page['has_more'])
        self.assertEqual(page['counts']['incidents'],3)
        self.ok(self.client.get('/dashboard/api/overview?limit=51',headers=self.headers),422)
        self.ok(self.client.get('/dashboard/api/incidents/0',headers=self.headers),422)
        self.ok(self.client.get('/dashboard/api/incidents/999999',headers=self.headers),404)

    def test_read_only_gets_preserve_all_three_databases(self):
        incident=self.authenticated_incident()
        paths=[database.DB_PATH,self.registry.database_path,self.main.analyst_store.database_path]
        before=[self.dump(p) for p in paths]
        for path in ['/dashboard','/dashboard/api/identity','/dashboard/api/overview',f'/dashboard/api/incidents/{incident}']:
            self.ok(self.client.get(path,headers=self.headers)) if '/api/' in path else self.client.get(path)
        self.assertEqual(before,[self.dump(p) for p in paths])

    def test_full_authorized_flow_and_telemetry_visible(self):
        incident=self.authenticated_incident()
        first=self.detail(incident)
        self.assertTrue(first['eligibility']['can_propose'])
        self.assertFalse(first['eligibility']['can_execute'])
        request=self.ok(self.client.post(f'/response-requests/for-incident/{incident}',headers=self.headers))['request_id']
        self.assertTrue(self.detail(incident)['eligibility']['can_approve'])
        self.ok(self.client.post(f'/response-requests/{request}/decision',headers=self.headers,json={'decision':'APPROVED','reason':'Dashboard contract test review'}))
        approved=self.detail(incident)
        self.assertTrue(approved['eligibility']['can_execute'])
        self.assertFalse(approved['block_present'])
        self.assertEqual(approved['incident']['request_status'],'APPROVED')
        headers=dict(self.headers,**{'Idempotency-Key':'dashboard-test-execution-0001'})
        self.ok(self.client.post(f'/response-requests/{request}/execute',headers=headers))
        executed=self.detail(incident)
        self.assertTrue(executed['block_present'])
        self.assertTrue(executed['eligibility']['can_rollback'])
        self.assertTrue(executed['telemetry'][0]['matched'])
        self.assertEqual(executed['telemetry'][0]['source'],'synthetic_sqlite_probe')
        self.ok(self.client.post(f'/response-requests/{request}/verify',headers=self.headers))
        self.ok(self.client.post(f'/response-requests/{request}/rollback',headers=dict(self.headers,**{'Idempotency-Key':'dashboard-test-rollback-0001'}),json={'reason':'Dashboard reviewed rollback'}))
        rolled=self.detail(incident)
        self.assertFalse(rolled['block_present'])
        self.assertEqual(rolled['request']['lifecycle_state'],'ROLLED_BACK')
        self.assertFalse(rolled['eligibility']['can_execute'])
        self.assertFalse(rolled['eligibility']['can_rollback'])
        self.assertIn('SIMULATED_ROLLED_BACK',[event['action'] for event in rolled['audit']])
        overview=self.ok(self.client.get('/dashboard/api/overview',headers=self.headers))
        self.assertEqual(overview['counts']['rollbacks'],1)
        self.assertEqual(overview['counts']['active_effects'],0)
        self.assertEqual(overview['incidents'][0]['request_status'],'SIMULATED_ROLLED_BACK')

    def test_viewer_cannot_mutate_even_with_visible_request(self):
        incident,request=self.approved()
        snapshot=self.detail(incident,self.viewer)
        self.assertFalse(any(v for k,v in snapshot['eligibility'].items() if k.startswith('can_')))
        self.ok(self.client.post(f'/response-requests/{request}/execute',headers=dict(self.viewer,**{'Idempotency-Key':'dashboard-viewer-denied-0001'})),403)
        self.assertFalse(self.detail(incident)['block_present'])

    def test_revocation_changes_eligibility_but_not_rollback_permission(self):
        incident,request=self.approved()
        self.assertTrue(self.detail(incident)['eligibility']['can_execute'])
        self.registry.revoke_collector('http_collector')
        snapshot=self.detail(incident)
        self.assertFalse(snapshot['eligibility']['can_execute'])
        self.assertTrue(all(e['provenance']=='untrusted_or_expired' for e in snapshot['evidence']))
        self.ok(self.client.post(f'/response-requests/{request}/execute',headers=dict(self.headers,**{'Idempotency-Key':'dashboard-revoked-execution'})),403)

    def test_malformed_row_and_changed_binding_fail_closed(self):
        incident,request=self.approved()
        with closing(database.connect()) as connection,connection:
            connection.execute("UPDATE response_approval_bindings SET digest='changed' WHERE request_id=?",(request,))
        self.assertFalse(self.detail(incident)['eligibility']['can_execute'])
        with closing(database.connect()) as connection,connection:
            connection.execute("UPDATE incident_evidence SET envelope_json='invalid JSON' WHERE incident_id=?",(incident,))
        snapshot=self.detail(incident)
        self.assertFalse(snapshot['eligibility']['evidence_current'])
        self.assertFalse(snapshot['eligibility']['can_execute'])

    def test_snapshot_never_exports_signatures_credentials_or_arbitrary_observations(self):
        incident=self.authenticated_incident()
        with closing(database.connect()) as connection,connection:
            original=connection.execute('SELECT envelope_json FROM incident_evidence WHERE incident_id=?',(incident,)).fetchone()[0]
            connection.execute('UPDATE alerts SET details=? WHERE id=(SELECT alert_id FROM incidents WHERE id=?)',('<img src=x onerror=alert(1)>',incident))
        response=self.client.get(f'/dashboard/api/incidents/{incident}',headers=self.headers)
        self.ok(response)
        for secret in [json.loads(original)['signature'],self.key,self.actor['token'],self.api['X-API-Key']]:
            self.assertNotIn(secret,response.text)
        data=response.json()
        self.assertIn('<img',data['alert']['details'])  # Browser renders all data via textContent.
        self.assertNotIn('signed_evidence',response.text)
        self.assertNotIn('envelope_json',response.text)
        self.assertNotIn('idempotency_key',response.text)

    def test_actual_reasoning_source_and_no_model_authorization(self):
        self.assertEqual(reasoning({'ai_status':'gemini','reasoning_source':'fallback_rules'})['source'],'gemini')
        self.assertEqual(reasoning({'ai_status':'gemini_overridden','reasoning_source':'gemini'})['source'],'fallback_rules')
        self.assertEqual(reasoning({})['source'],'unknown')
        incident=self.incident()
        data=self.detail(incident)
        self.assertFalse(data['eligibility']['can_propose'])
        self.assertFalse(data['eligibility']['can_execute'])

    def test_identity_revocation_and_safe_unavailable_response(self):
        with patch('app.dashboard_routes.connect',side_effect=sqlite3.OperationalError('private-path/secret='+self.key)):
            response=self.client.get('/dashboard/api/overview',headers=self.headers)
            self.ok(response,503)
            self.assertNotIn(self.key,response.text)
            self.assertNotIn('private-path',response.text)
        self.main.analyst_store.disable_analyst(self.actor['analyst_id'])
        self.ok(self.client.get('/dashboard/api/identity',headers=self.headers),403)

    def test_rollback_stays_available_after_collector_revocation(self):
        incident,request=self.executed()
        self.registry.revoke_collector('http_collector')
        data=self.detail(incident)
        self.assertFalse(data['eligibility']['evidence_current'])
        self.assertTrue(data['eligibility']['can_rollback'])
        self.assertTrue(data['eligibility']['can_verify'])


if __name__=='__main__':
    unittest.main(verbosity=2)
