"""Close roadmap Step 6 verification/rollback gaps, including abrupt process exit."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import test_step6_integrated as baseline
from app.simulation_lifecycle import rollback_response, verify_response


class Lifecycle(unittest.TestCase):
    setUp = baseline.Integrated.setUp
    tearDown = baseline.Integrated.tearDown
    sql = baseline.Integrated.sql
    proposal = baseline.Integrated.proposal
    approve = baseline.Integrated.approve
    execute = baseline.Integrated.execute
    assertDenied = baseline.Integrated.assertDenied
    route = baseline.Integrated.route

    def rollback(self,key='rollback-key-0001',request=None,reason='Operator verified safe rollback'):
        return rollback_response(request or self.request,key,self.actor['analyst_id'],self.actor['token'],self.ids,reason)

    def verify(self):
        return verify_response(self.request,self.actor['analyst_id'],self.actor['token'],self.ids)

    def test_verified_effect_and_persistent_telemetry(self):
        self.approve()
        result = self.execute()
        self.assertEqual(result['verification_status'],'VERIFIED')
        self.assertEqual(result['telemetry']['source'],'synthetic_sqlite_probe')
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'VERIFIED')
        self.assertEqual(self.verify()['status'],'SIMULATION_VERIFIED')
        self.assertEqual(len(self.sql('SELECT * FROM simulation_telemetry')),2)

    def test_verification_failure_compensated_atomically(self):
        self.approve()
        report = {'source':'synthetic_sqlite_probe','expected_blocked':True,'observed_blocked':False,'matched':False}
        with patch('app.simulation_lifecycle._probe',return_value=report):
            result = self.execute()
        self.assertEqual(result['status'],'SIMULATION_FAILED')
        self.assertFalse(result['executed'])
        self.assertTrue(result['compensated'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),0)
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'FAILED')
        self.assertTrue(self.execute()['replayed'])
        self.assertEqual(self.rollback()['status'],'DENIED')

    def test_rollback_and_idempotent_retry(self):
        self.approve(); self.execute()
        result = self.rollback()
        self.assertEqual(result['status'],'SIMULATED_ROLLED_BACK',result)
        self.assertTrue(result['telemetry']['matched'])
        self.assertEqual(result['rolled_back_by'],self.actor['analyst_id'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),0)
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'ROLLED_BACK')
        self.assertTrue(self.rollback()['replayed'])
        self.assertEqual(self.rollback('rollback-key-0002')['status'],'DENIED')
        self.assertEqual(len(self.sql("SELECT * FROM response_audit WHERE action='SIMULATED_ROLLED_BACK'")),1)
        self.assertEqual(self.verify()['status'],'DENIED')
        # An execution retry returns history; it must never recreate a rolled-back effect.
        self.assertTrue(self.execute()['replayed'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),0)

    def test_rollback_rechecks_role_token_and_reason(self):
        self.approve(); self.execute()
        for name,token in [(self.viewer['analyst_id'],self.viewer['token']),(self.actor['analyst_id'],'x'*64)]:
            self.assertEqual(rollback_response(self.request,'rollback-key-0001',name,token,self.ids,'Valid reason')['status'],'DENIED')
        self.assertEqual(self.rollback(reason='x')['status'],'DENIED')
        self.ids.disable_analyst(self.actor['analyst_id'])
        self.assertEqual(self.rollback()['status'],'DENIED')
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),1)

    def test_shared_ip_rollback_preserves_other_active_effect(self):
        _,second = self.proposal()
        self.approve(); self.approve(second)
        self.execute(); self.execute('execution-key-0002',second)
        first = self.rollback()
        self.assertTrue(first['block_retained'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),1)
        last = self.rollback('rollback-key-0002',second)
        self.assertFalse(last['block_retained'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),0)

    def test_rollback_cannot_remove_unknown_legacy_block(self):
        self.sql("INSERT INTO simulated_blocks (source_ip,response_request_id) VALUES ('8.8.8.8',999)")
        # Approve helper expects no block, so use decision route directly.
        decision = self.route(f'/response-requests/{self.request}/decision',headers=self.headers,json={'decision':'APPROVED','reason':'Existing shared block reviewed'})
        self.assertEqual(decision.status_code,200)
        self.assertFalse(self.execute()['block_created'])
        self.assertTrue(self.rollback()['block_retained'])
        self.assertEqual(self.sql('SELECT response_request_id FROM simulated_blocks')[0][0],999)

    def test_rollback_audit_failure_restores_effect_and_allows_retry(self):
        self.approve(); self.execute()
        self.sql("CREATE TRIGGER fail_rollback_audit BEFORE INSERT ON response_audit WHEN NEW.action='SIMULATED_ROLLED_BACK' BEGIN SELECT RAISE(ABORT,'test failure'); END")
        self.assertEqual(self.rollback()['status'],'DENIED')
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),1)
        self.assertEqual(len(self.sql('SELECT * FROM response_rollbacks')),0)
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'VERIFIED')
        self.sql('DROP TRIGGER fail_rollback_audit')
        self.assertEqual(self.rollback()['status'],'SIMULATED_ROLLED_BACK')

    def test_interrupted_verification_restores_effect(self):
        self.approve(); self.execute()
        with patch('app.simulation_lifecycle._probe',side_effect=ValueError('Injected verification failure')):
            self.assertEqual(self.rollback()['status'],'DENIED')
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),1)
        self.assertEqual(len(self.sql('SELECT * FROM response_rollbacks')),0)
        self.assertEqual(self.rollback()['status'],'SIMULATED_ROLLED_BACK')

    def crash_child(self,operation):
        from app import database
        code = '''import os
from app.analyst_identity import AnalystIdentityStore
from app.persistent_collector_registry import PersistentCollectorRegistry
from app.response_execution import execute_response
from app.simulation_lifecycle import rollback_response
import app.simulation_lifecycle as lifecycle
ids=AnalystIdentityStore(os.environ['TEST_IDS'])
registry=PersistentCollectorRegistry(os.environ['TEST_REGISTRY'])
registry.load_collector_key('collector_01',os.environ['TEST_KEY'])
lifecycle._probe=lambda *args: os._exit(41)
request=int(os.environ['TEST_REQUEST'])
if os.environ['TEST_OPERATION']=='execute':
    execute_response(request,'execution-key-0001',os.environ['TEST_ACTOR'],os.environ['TEST_TOKEN'],ids,registry)
else:
    rollback_response(request,'rollback-key-0001',os.environ['TEST_ACTOR'],os.environ['TEST_TOKEN'],ids,'Crash test rollback')
'''
        env = dict(os.environ,SENTINELOPS_DB=database.DB_PATH,TEST_IDS=self.ids.database_path,
                   TEST_REGISTRY=self.registry.database_path,TEST_KEY=self.key,
                   TEST_REQUEST=str(self.request),TEST_ACTOR=self.actor['analyst_id'],
                   TEST_TOKEN=self.actor['token'],TEST_OPERATION=operation)
        result = subprocess.run([sys.executable,'-c',code],cwd=ROOT,
                                env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,41,result.stderr)

    def test_process_crash_before_execution_commit(self):
        self.approve()
        self.crash_child('execute')
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),0)
        self.assertEqual(len(self.sql('SELECT * FROM response_executions')),0)
        self.assertEqual(self.sql('SELECT status FROM response_requests')[0][0],'APPROVED')
        self.assertEqual(self.execute()['status'],'SIMULATED_EXECUTED')

    def test_process_crash_during_rollback(self):
        self.approve(); self.execute()
        self.crash_child('rollback')
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')),1)
        self.assertEqual(len(self.sql('SELECT * FROM response_rollbacks')),0)
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'VERIFIED')
        self.assertEqual(self.rollback()['status'],'SIMULATED_ROLLED_BACK')

    def test_concurrent_rollback_exactly_once(self):
        self.approve(); self.execute()
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _:self.rollback(),range(6)))
        self.assertTrue(all(r['status']=='SIMULATED_ROLLED_BACK' for r in results),results)
        self.assertEqual(sum(not r['replayed'] for r in results),1)
        self.assertEqual(len(self.sql('SELECT * FROM response_rollbacks')),1)

    def test_missing_effect_is_detected(self):
        self.approve(); self.execute()
        self.sql('DELETE FROM simulated_blocks')
        result = self.verify()
        self.assertEqual(result['status'],'SIMULATION_VERIFICATION_FAILED')
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'VERIFICATION_FAILED')

    def test_legacy_receipt_upgrade_requires_explicit_verification(self):
        from app.response_execution import init_execution_store
        self.approve(); self.execute()
        receipt = json.loads(self.sql('SELECT result_json FROM response_executions')[0][0])
        receipt.pop('verification_status',None)
        receipt.pop('telemetry',None)
        self.sql('UPDATE response_executions SET result_json=?',(json.dumps(receipt),))
        self.sql('DELETE FROM simulation_effects')
        self.sql('DELETE FROM simulation_telemetry')
        init_execution_store()
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'LEGACY_UNVERIFIED')
        self.assertNotIn('verification_status',self.execute())
        self.assertEqual(self.verify()['status'],'SIMULATION_VERIFIED')
        self.assertEqual(self.sql('SELECT state FROM simulation_effects')[0][0],'VERIFIED')


if __name__=='__main__':
    unittest.main(verbosity=2)
