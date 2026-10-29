"""Real API persistence/source labels and fallback safety with offline provider seams."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import multiprocessing
import os
import time
import unittest
from unittest.mock import patch

import test_step7_http_contracts as baseline
import test_step8_gemini as fixtures
from app import gemini_runtime as runtime
from step8_test_workers import slow_worker


class HTTPGemini(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline.Contracts.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        baseline.Contracts.tearDownClass.__func__(cls)

    setUp = baseline.Contracts.setUp
    tearDown = baseline.Contracts.tearDown
    ok = baseline.Contracts.ok
    incident = baseline.Contracts.incident

    def settings(self,**values):
        default = {'GEMINI_API_KEY':fixtures.KEY,'GEMINI_MODEL':fixtures.MODEL,
                   'SENTINELOPS_GEMINI_ENABLED':'1','SENTINELOPS_AI_TIMEOUT_MS':'15000',
                   'SENTINELOPS_AI_MAX_ATTEMPTS':'2','SENTINELOPS_AI_BUDGET_MS':'60000'}
        default.update(values)
        return patch.dict(os.environ,default)

    def proposal(self,settings,prompt,schema,timeout_ms):
        properties = schema['properties']
        if 'summary' in properties:
            data = fixtures.TRIAGE
        elif 'tool' in properties:
            payload = json.loads(prompt[prompt.index('{'):])
            data = dict(fixtures.PLANNER,tool=payload['allowed_tools'][0])
        else:
            data = fixtures.OUTCOME
        return {'code':'OK','text':json.dumps(data)}

    def read_incident(self,ident):
        rows = self.ok(self.client.get('/incidents',headers=self.headers))
        return next(row for row in rows if row['id']==ident)

    def test_success_labels_persist_but_placeholder_never_authorizes(self):
        with self.settings(),patch.object(runtime,'_invoke',side_effect=self.proposal) as invoke:
            ident = self.incident()
        record = self.read_incident(ident)
        triage = record['evidence']['triage']
        self.assertEqual(triage['ai_status'],'gemini')
        self.assertEqual(triage['ai_metadata']['provider_status'],'OK')
        self.assertEqual(triage['evidence_refs'],['event_type'])
        trace = record['evidence']['investigation']['trace']
        self.assertTrue(all(row['ai_status']=='gemini' for row in trace))
        self.assertLessEqual(invoke.call_count,5)
        self.assertEqual(record['evidence']['outcome']['fallback_reason'],'NO_ELIGIBLE_EVIDENCE')
        self.ok(self.client.post(f'/response-requests/for-incident/{ident}',headers=self.headers),403)
        self.assertEqual(self.ok(self.client.get('/simulated-blocks',headers=self.headers)),[])
        self.assertNotIn(fixtures.KEY,json.dumps(record))

    def test_quota_fallback_is_clear_persisted_and_never_retried(self):
        with self.settings(),patch.object(runtime,'_invoke',return_value={'code':'PROVIDER_QUOTA'}) as invoke:
            ident = self.incident()
        record = self.read_incident(ident)
        triage = record['evidence']['triage']
        self.assertEqual(triage['ai_status'],'fallback_rules')
        self.assertEqual(triage['reasoning_source'],'fallback_rules')
        self.assertEqual(triage['fallback_reason'],'PROVIDER_QUOTA')
        self.assertEqual(triage['ai_metadata']['attempts'],1)
        self.assertEqual(invoke.call_count,5)
        self.assertTrue(all(step['fallback_reason']=='PROVIDER_QUOTA' for step in record['evidence']['investigation']['trace']))

    def test_malformed_provider_output_falls_back_before_storage(self):
        with self.settings(),patch.object(runtime,'_invoke',return_value={'code':'OK','text':'{"raw_secret":"'+fixtures.KEY+'"}'}):
            ident = self.incident()
        record = self.read_incident(ident)
        self.assertEqual(record['evidence']['triage']['fallback_reason'],'INVALID_RESPONSE')
        self.assertNotIn('raw_secret',json.dumps(record))
        self.assertNotIn(fixtures.KEY,json.dumps(record))

    def test_workflow_deadline_is_shared_between_planner_and_triage(self):
        def consume_budget(settings,prompt,schema,timeout_ms):
            result = self.proposal(settings,prompt,schema,timeout_ms)
            runtime._deadline.set(time.monotonic()-1)
            return result
        with self.settings(),patch.object(runtime,'_invoke',side_effect=consume_budget) as invoke:
            ident = self.incident()
        self.assertEqual(invoke.call_count,1)
        record = self.read_incident(ident)
        self.assertEqual(record['evidence']['triage']['fallback_reason'],'BUDGET_EXHAUSTED')
        self.assertEqual(record['evidence']['triage']['ai_metadata']['attempts'],0)
        self.assertEqual(record['evidence']['investigation']['trace'][0]['ai_status'],'gemini')
        self.assertTrue(all(row['fallback_reason']=='BUDGET_EXHAUSTED' for row in record['evidence']['investigation']['trace'][1:]))

    def test_hung_child_through_http_is_bounded_and_reaped(self):
        before = {process.pid for process in multiprocessing.active_children()}
        def hang(settings,prompt,schema,timeout_ms):
            return runtime._run_process(slow_worker,(),min(timeout_ms,200))
        started = time.monotonic()
        with self.settings(SENTINELOPS_AI_BUDGET_MS='15000'),patch.object(runtime,'_invoke',side_effect=hang):
            ident = self.incident()
        self.assertLess(time.monotonic()-started,3)
        record = self.read_incident(ident)
        self.assertEqual(record['evidence']['triage']['ai_status'],'fallback_rules')
        self.assertIn(record['evidence']['triage']['fallback_reason'],('PROVIDER_TIMEOUT','BUDGET_EXHAUSTED'))
        self.assertEqual({process.pid for process in multiprocessing.active_children()},before)

    def test_status_is_protected_and_does_not_call_provider(self):
        with self.settings(),patch.object(runtime,'_invoke') as invoke:
            self.ok(self.client.get('/ai/status'),401)
            result = self.ok(self.client.get('/ai/status',headers=self.viewer))
            self.assertTrue(result['configured'])
            self.assertEqual(result['model'],fixtures.MODEL)
            self.assertEqual(result['live_authentication'],'not_checked')
            invoke.assert_not_called()
            self.assertNotIn(fixtures.KEY,json.dumps(result))

    def test_even_corroborated_synthetic_gemini_outcome_cannot_authorize(self):
        with self.settings(),patch.object(runtime,'_invoke',side_effect=self.proposal),patch.object(self.main,'run_investigation',return_value=fixtures.completed_observations()):
            alert = self.ok(self.client.post('/webhook/alert',headers=self.api,json=fixtures.ALERT))
            result = self.ok(self.client.post(f"/alerts/{alert['id']}/investigate",headers=self.api))
        self.assertEqual(result['outcome']['ai_status'],'gemini')
        self.assertEqual(result['assessment'],'ATTACK_CONFIRMED')
        self.ok(self.client.post(f"/response-requests/for-incident/{result['incident_id']}",headers=self.headers),403)
        self.assertEqual(self.ok(self.client.get('/response-requests',headers=self.headers)),[])
        self.assertEqual(self.ok(self.client.get('/simulated-blocks',headers=self.headers)),[])


if __name__=='__main__':
    unittest.main(verbosity=2)
