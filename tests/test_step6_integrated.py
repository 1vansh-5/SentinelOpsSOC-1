"""Real signatures, persistent registries, route functions, rollback and concurrency.

Route functions are invoked directly; these tests do not open network sockets.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import sqlite3
import tempfile
import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from types import SimpleNamespace
from app import database
from app.analyst_identity import AnalystIdentityStore
from app.persistent_collector_registry import PersistentCollectorRegistry
from app.evidence_signing import create_signed_evidence
from app.incident_evidence_store import init_incident_evidence_store
from app.authenticated_evidence_service import ingest_authenticated_evidence
from app.response_execution import init_execution_store, execute_response
from app.response_routes import build_response_router, DecisionPayload


class Integrated(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name)/'incidents.sqlite')
        database.init_db()
        init_incident_evidence_store()
        init_execution_store()
        self.ids = AnalystIdentityStore(str(Path(self.temp.name)/'identities.sqlite'))
        self.actor = self.ids.create_analyst('analyst_01', 'analyst')
        self.viewer = self.ids.create_analyst('viewer_01', 'viewer')
        self.registry = PersistentCollectorRegistry(str(Path(self.temp.name)/'collectors.sqlite'))
        self.key = 'a'*64
        self.registry.register_collector('collector_01', self.key)
        app = FastAPI()
        self.router = build_response_router(self.ids, lambda: self.registry)
        app.include_router(self.router)
        self.schema = app.openapi()
        self.headers = {'X-Analyst-Id':self.actor['analyst_id'], 'X-Analyst-Token':self.actor['token']}
        self.incident, self.request = self.proposal()

    def tearDown(self):
        database.DB_PATH = self.old
        self.temp.cleanup()

    def sql(self, sql, args=()):
        with closing(database.connect()) as c, c:
            return c.execute(sql,args).fetchall()

    def route(self, path, headers=None, json=None):
        """Call the real sync route function; no simulated transport assertions."""
        headers = headers or {}
        creds = dict(x_analyst_id=headers.get('X-Analyst-Id'),
                     x_analyst_token=headers.get('X-Analyst-Token'))
        try:
            if '/for-incident/' in path:
                endpoint = next(r.endpoint for r in self.router.routes if r.path.endswith('/for-incident/{incident_id}'))
                value = endpoint(int(path.rsplit('/',1)[1]), **creds)
            else:
                ident = int(path.split('/')[-2])
                ending = path.rsplit('/',1)[1]
                endpoint = next(r.endpoint for r in self.router.routes if r.path.endswith('/'+ending))
                if ending == 'decision':
                    value = endpoint(ident, DecisionPayload(**json), **creds)
                else:
                    value = endpoint(ident, idempotency_key=headers.get('Idempotency-Key'), **creds)
            return SimpleNamespace(status_code=200, text=str(value), json=lambda:value)
        except HTTPException as exc:
            return SimpleNamespace(status_code=exc.status_code, text=exc.detail, json=lambda:{'detail':exc.detail})

    def proposal(self):
        with closing(database.connect()) as c, c:
            alert = c.execute("INSERT INTO alerts (source_ip,event_type,target,details,severity) VALUES ('8.8.8.8','failed_login','test','test','high')").lastrowid
            incident = c.execute("INSERT INTO incidents (alert_id,assessment,confidence,evidence,response_action,response_status) VALUES (?,'ATTACK_CONFIRMED','high','{}','REVIEW','SIMULATED_ONLY')",(alert,)).lastrowid
        envelope = create_signed_evidence(incident,'collector_01',{'event':'verified test log'},self.key)
        self.assertTrue(ingest_authenticated_evidence(incident,envelope,self.registry)['stored'])
        evidence = {'outcome':{'assessment':'ATTACK_CONFIRMED','ai_status':'fallback_rules'},
                    'investigation':{'trace':[{'result':{'status':'completed','source':'authenticated_collector','signed_evidence':envelope}}]}}
        self.sql('UPDATE incidents SET evidence=? WHERE id=?',(json.dumps(evidence),incident))
        response = self.route(f'/response-requests/for-incident/{incident}',headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        return incident,response.json()['request_id']

    def approve(self, request=None):
        response = self.route(f'/response-requests/{request or self.request}/decision',headers=self.headers,
                                    json={'decision':'APPROVED','reason':'Evidence reviewed'})
        self.assertEqual(response.status_code,200,response.text)
        self.assertFalse(response.json()['executed'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),0)

    def execute(self, key='execution-key-0001', request=None):
        return execute_response(request or self.request,key,self.actor['analyst_id'],self.actor['token'],self.ids,self.registry)

    def assertDenied(self,result):
        self.assertEqual(result['status'],'DENIED',result)
        self.assertEqual(len(self.sql('SELECT * FROM response_executions')),0)
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),0)

    def test_route_end_to_end_and_retry(self):
        self.approve()
        headers = dict(self.headers, **{'Idempotency-Key':'execution-key-0001'})
        url = f'/response-requests/{self.request}/execute'
        first = self.route(url,headers=headers)
        self.assertEqual(first.status_code,200,first.text)
        self.assertEqual(first.json()['mode'],'SIMULATION_ONLY')
        self.assertFalse(first.json()['replayed'])
        self.assertTrue(self.route(url,headers=headers).json()['replayed'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),1)
        self.assertEqual(len(self.sql("SELECT * FROM response_audit WHERE action='SIMULATED_EXECUTED'")),1)
        self.assertEqual(self.sql('SELECT response_status FROM incidents')[0][0],'SIMULATED_EXECUTED')

    def test_pending_and_rejected(self):
        self.assertDenied(self.execute())
        self.route(f'/response-requests/{self.request}/decision',headers=self.headers,json={'decision':'REJECTED','reason':'Not approved'})
        self.assertDenied(self.execute())

    def test_missing_credentials_and_key(self):
        self.approve()
        url = f'/response-requests/{self.request}/execute'
        self.assertEqual(self.route(url).status_code,401)
        self.assertEqual(self.route(url,headers=self.headers).status_code,403)

    def test_roles_tokens_and_missing_dependencies(self):
        self.approve()
        for name,token,ids,reg in [(self.viewer['analyst_id'],self.viewer['token'],self.ids,self.registry),
            (self.actor['analyst_id'],'x'*64,self.ids,self.registry),
            (self.actor['analyst_id'],self.actor['token'],None,self.registry),
            (self.actor['analyst_id'],self.actor['token'],self.ids,None)]:
            self.assertDenied(execute_response(self.request,'execution-key-0001',name,token,ids,reg))
        self.assertEqual(len(self.sql('SELECT * FROM response_execution_denials')),4)

    def test_downgrade(self):
        self.approve(); self.ids.change_role(self.actor['analyst_id'],'viewer')
        self.assertDenied(self.execute())

    def test_disabled(self):
        self.approve(); self.ids.disable_analyst(self.actor['analyst_id'])
        self.assertDenied(self.execute())

    def test_token_rotation(self):
        self.approve(); self.ids.rotate_token(self.actor['analyst_id'])
        self.assertDenied(self.execute())

    def test_collector_revocation(self):
        self.approve(); self.registry.revoke_collector('collector_01')
        self.assertDenied(self.execute())

    def test_collector_rotation(self):
        self.approve(); self.registry.rotate_collector_key('collector_01',self.key,'b'*64)
        self.assertDenied(self.execute())

    def test_expired_at_execution(self):
        self.approve()
        class Later(datetime):
            @classmethod
            def now(cls,tz=None):
                return datetime.now(timezone.utc)+timedelta(minutes=11)
        with patch('app.evidence_freshness.datetime',Later):
            self.assertDenied(self.execute())

    def test_tampered_incident(self):
        self.approve(); self.sql("UPDATE incidents SET evidence='{}'")
        self.assertDenied(self.execute())

    def test_malformed_stored_evidence_is_not_skipped(self):
        self.approve()
        self.sql("INSERT INTO incident_evidence (incident_id,collector_id,signature,envelope_json) VALUES (?,'collector_01',?,'broken')",(self.incident,'f'*64))
        self.assertDenied(self.execute())

    def test_missing_binding_legacy_approval(self):
        self.approve(); self.sql('DELETE FROM response_approval_bindings')
        self.assertDenied(self.execute())

    def test_missing_approval_audit(self):
        self.approve(); self.sql("DELETE FROM response_audit WHERE action='REQUEST_APPROVED'")
        self.assertDenied(self.execute())

    def test_concurrent_same_key(self):
        self.approve()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _:self.execute(),range(8)))
        self.assertTrue(all(r['status']=='SIMULATED_EXECUTED' for r in results),results)
        self.assertEqual(sum(not r['replayed'] for r in results),1)
        self.assertEqual(len(self.sql("SELECT * FROM response_audit WHERE action='SIMULATED_EXECUTED'")),1)

    def test_concurrent_different_keys(self):
        self.approve()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda i:self.execute(f'execution-key-{i:04}'),range(4)))
        self.assertEqual(sum(r['status']=='SIMULATED_EXECUTED' for r in results),1,results)

    def test_audit_failure_rolls_back_every_effect(self):
        self.approve()
        self.sql("CREATE TRIGGER fail_execution_audit BEFORE INSERT ON response_audit WHEN NEW.action='SIMULATED_EXECUTED' BEGIN SELECT RAISE(ABORT,'test failure'); END")
        self.assertDenied(self.execute())
        self.assertEqual(self.sql('SELECT status FROM response_requests')[0][0],'APPROVED')
        self.assertEqual(self.sql('SELECT response_status FROM incidents')[0][0],'SIMULATED_ONLY')
        self.sql('DROP TRIGGER fail_execution_audit')
        self.assertEqual(self.execute()['status'],'SIMULATED_EXECUTED')

    def test_key_reuse_across_requests_and_existing_ip(self):
        incident, request = self.proposal()
        self.approve(); self.approve(request)
        self.assertTrue(self.execute()['block_created'])
        self.assertEqual(self.execute(request=request)['status'],'DENIED')
        second = self.execute('execution-key-0002',request)
        self.assertEqual(second['status'],'SIMULATED_EXECUTED',second)
        self.assertFalse(second['block_created'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),1)
        self.assertEqual(len(self.sql('SELECT * FROM response_executions')),2)

    def test_retry_requires_current_authorization(self):
        self.approve(); self.execute()
        self.ids.disable_analyst(self.actor['analyst_id'])
        self.assertEqual(self.execute()['status'],'DENIED')

    def test_invalid_inputs(self):
        for request in (True,0,-1,'1'):
            self.assertDenied(execute_response(request,'execution-key-0001',self.actor['analyst_id'],self.actor['token'],self.ids,self.registry))
        for key in ('short',' '*16,None,'a'*129):
            self.assertDenied(self.execute(key))

    def test_persistent_retry_after_reopening_stores(self):
        self.approve()
        self.assertEqual(self.execute()['status'],'SIMULATED_EXECUTED')
        self.ids = AnalystIdentityStore(self.ids.database_path)
        reopened = PersistentCollectorRegistry(self.registry.database_path)
        reopened.load_collector_key('collector_01',self.key)
        self.registry = reopened
        self.assertTrue(self.execute()['replayed'])

    def test_legacy_reopen_review_and_execute(self):
        import reopen_legacy_step6
        self.approve()
        self.sql('DELETE FROM response_approval_bindings')
        with patch('sys.argv',['reopen_legacy_step6.py',str(self.request),'--reason','Fresh upgrade review required']):
            reopen_legacy_step6.main()
        self.assertEqual(self.sql('SELECT status FROM response_requests')[0][0],'PENDING')
        self.approve()
        self.assertEqual(self.execute()['status'],'SIMULATED_EXECUTED')

    def test_changed_target_and_unsupported_action(self):
        self.approve()
        self.sql("UPDATE response_requests SET source_ip='127.0.0.1'")
        self.assertDenied(self.execute())
        self.sql("UPDATE response_requests SET source_ip='8.8.8.8',action='REAL_BLOCK'")
        self.assertDenied(self.execute())

    def test_revocation_waits_for_execution_reservation(self):
        self.approve()
        started = threading.Event()
        finished = threading.Event()
        original = self.registry.verify_accepted_evidence
        worker = None

        def revoke():
            started.set()
            self.registry.revoke_collector('collector_01')
            finished.set()

        def verify(*args):
            nonlocal worker
            if worker is None:
                worker = threading.Thread(target=revoke)
                worker.start()
                self.assertTrue(started.wait(2))
                self.assertFalse(finished.wait(0.1))
            return original(*args)

        with patch.object(self.registry,'verify_accepted_evidence',side_effect=verify):
            result = self.execute()
        worker.join(5)
        self.assertTrue(finished.is_set())
        self.assertEqual(result['status'],'SIMULATED_EXECUTED',result)
        # A subsequent new request cannot use the now revoked collector.
        self.assertFalse(original(json.loads(self.sql('SELECT envelope_json FROM incident_evidence')[0][0]),self.incident))


if __name__ == '__main__':
    unittest.main(verbosity=2)
