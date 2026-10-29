"""Offline provider, schema, deadline, environment and deterministic safety tests."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from app import gemini_config as config, gemini_runtime as runtime
from app.gemini_models import LiveProbe, TriageProposal
from app.ai_reasoner import analyze_alert
from app.gemini_planner import choose_next_tool
from app.outcome_reasoner import assess_outcome
from step8_test_workers import slow_worker, successful_worker

KEY = 'offline-provider-fixture-'+'k'*40
MODEL = 'gemini-3.5-flash-lite'
ALERT = {'source_ip':'8.8.8.8','event_type':'failed_login','target':'demo-login','details':'Controlled fixture','severity':'high'}
TRIAGE = {'assessment':'ATTEMPT_DETECTED','confidence':'low','summary':'A failed login was reported; success is not established.',
          'evidence':['Failed login alert'],'evidence_refs':['event_type'],
          'recommended_next_steps':['Review corroborating logs.']}
PLANNER = {'tool':'authentication_logs','reason':'Review login observations for the reported event.','evidence_refs':['alert.event_type']}
OUTCOME = {'assessment':'ATTACK_CONFIRMED','reason':'Authentication and application records corroborate unauthorized access.',
           'evidence_refs':['authentication_logs','application_logs']}


def completed_observations():
    return {'trace':[
        {'tool':'authentication_logs','result':{'status':'completed','source':'synthetic_scenario',
            'evidence':{'login_attempts':5,'failed_logins':4,'successful_login':True,'session_created':True}}},
        {'tool':'application_logs','result':{'status':'completed','source':'synthetic_scenario',
            'evidence':{'unauthorized_access_observed':True,'http_status':200}}}]}


class GeminiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env_path = patch.object(config,'PROJECT_ENV',Path(self.tmp.name)/'.env')
        self.env_path.start()
        values = dict.fromkeys(config.AI_SETTINGS,'')
        values.update(GEMINI_API_KEY=KEY,GEMINI_MODEL=MODEL,SENTINELOPS_GEMINI_ENABLED='1',
                      SENTINELOPS_AI_TIMEOUT_MS='15000',SENTINELOPS_AI_MAX_ATTEMPTS='2',SENTINELOPS_AI_BUDGET_MS='60000')
        self.env = patch.dict(os.environ,values); self.env.start()

    def tearDown(self):
        self.env.stop(); self.env_path.stop(); self.tmp.cleanup()

    def answer(self,data):
        return {'code':'OK','text':json.dumps(data)}

    def test_explicit_configuration_and_hidden_key(self):
        settings = config.load_ai_settings()
        self.assertEqual(settings.code,'READY')
        self.assertEqual(settings.model,MODEL)
        self.assertNotIn(KEY,repr(settings))
        metadata = config.public_settings()
        self.assertTrue(metadata['configured'])
        self.assertEqual(metadata['live_authentication'],'not_checked')
        self.assertNotIn(KEY,json.dumps(metadata))

    def test_missing_key_model_disabled_and_invalid_bounds(self):
        cases = [('GEMINI_API_KEY','','KEY_NOT_CONFIGURED'),('GEMINI_MODEL','','MODEL_NOT_CONFIGURED'),
                 ('SENTINELOPS_GEMINI_ENABLED','0','DISABLED'),('SENTINELOPS_GEMINI_ENABLED','yes','INVALID_CONFIGURATION'),
                 ('SENTINELOPS_AI_TIMEOUT_MS','0','INVALID_CONFIGURATION'),('SENTINELOPS_AI_TIMEOUT_MS','30001','INVALID_CONFIGURATION'),
                 ('SENTINELOPS_AI_MAX_ATTEMPTS','3','INVALID_CONFIGURATION'),('SENTINELOPS_AI_BUDGET_MS','60001','INVALID_CONFIGURATION'),
                 ('GEMINI_MODEL','https://untrusted.example/model','INVALID_CONFIGURATION')]
        for name,value,expected in cases:
            with self.subTest(name=name,value=value),patch.dict(os.environ,{name:value}),patch.object(runtime,'_invoke') as invoke:
                result = runtime.request_proposal('fixed',LiveProbe)
                self.assertEqual(result.code,expected)
                self.assertEqual(result.attempts,0)
                invoke.assert_not_called()

    def test_dotenv_whitelist_no_interpolation_or_override(self):
        path = config.PROJECT_ENV
        path.write_text('GEMINI_MODEL=gemini-3.5-flash-lite\nGEMINI_API_KEY="'+KEY+'"\nSENTINELOPS_DB=must-not-load.db\n')
        previous_db = os.environ.get('SENTINELOPS_DB')
        with patch.dict(os.environ):
            os.environ.pop('GEMINI_API_KEY',None)
            os.environ['GEMINI_MODEL']='gemini-existing-config'
            self.assertEqual(config.load_ai_settings().model,'gemini-existing-config')
            self.assertEqual(os.environ['GEMINI_API_KEY'],KEY)
            self.assertEqual(os.environ.get('SENTINELOPS_DB'),previous_db)
        with patch.dict(os.environ,{'GEMINI_API_KEY':''}):
            self.assertEqual(config.load_ai_settings().code,'KEY_NOT_CONFIGURED')

    def test_valid_triage_planner_and_outcome_sources(self):
        with patch.object(runtime,'_invoke',return_value=self.answer(TRIAGE)):
            triage = analyze_alert(ALERT)
        self.assertEqual(triage['ai_status'],'gemini')
        self.assertEqual(triage['reasoning_source'],'gemini')
        self.assertEqual(triage['evidence'],['event_type: failed_login'])
        with patch.object(runtime,'_invoke',return_value=self.answer(PLANNER)):
            planner = choose_next_tool(ALERT,[])
        self.assertEqual(planner['ai_status'],'gemini')
        with patch.object(runtime,'_invoke',return_value=self.answer(OUTCOME)):
            outcome = assess_outcome(completed_observations())
        self.assertEqual(outcome['ai_status'],'gemini')
        self.assertEqual(outcome['assessment'],'ATTACK_CONFIRMED')
        self.assertEqual(outcome['evidence_refs'],OUTCOME['evidence_refs'])

    def test_invalid_json_shape_types_extra_fields_and_duplicate_keys(self):
        texts = ['not json','null','[]','true','{"status":"OK","extra":true}',
                 '{"status":"OK","status":"OK"}','{"status":NaN}',json.dumps({'status':True})]
        for text in texts:
            with self.subTest(text=text),patch.object(runtime,'_invoke',return_value={'code':'OK','text':text}) as invoke:
                answer = runtime.request_proposal('fixed',LiveProbe)
                self.assertEqual(answer.code,'INVALID_RESPONSE')
                self.assertEqual(invoke.call_count,1)
        for changed in [dict(TRIAGE,evidence=[1]),dict(TRIAGE,summary='x'*1201),dict(TRIAGE,confidence='certain'),dict(TRIAGE,approved=True)]:
            with patch.object(runtime,'_invoke',return_value=self.answer(changed)):
                self.assertEqual(analyze_alert(ALERT)['fallback_reason'],'INVALID_RESPONSE')

    def test_missing_or_invalid_evidence_references(self):
        with patch.object(runtime,'_invoke',return_value=self.answer(dict(TRIAGE,evidence_refs=['target']))):
            self.assertEqual(analyze_alert(dict(ALERT,target=''))['fallback_reason'],'INVALID_EVIDENCE_REFERENCE')
        with patch.object(runtime,'_invoke',return_value=self.answer(dict(OUTCOME,evidence_refs=['authentication_logs']))):
            self.assertEqual(assess_outcome(completed_observations())['fallback_reason'],'INVALID_EVIDENCE_REFERENCE')
        with patch.object(runtime,'_invoke',return_value=self.answer(PLANNER)):
            used = [{'tool':'authentication_logs','result':{'status':'completed'}}]
            result = choose_next_tool(ALERT,used)
            self.assertNotEqual(result['tool'],'authentication_logs')
            self.assertEqual(result['fallback_reason'],'INVALID_EVIDENCE_REFERENCE')

    def test_model_cannot_upgrade_triage_or_outcome(self):
        with patch.object(runtime,'_invoke',return_value=self.answer(dict(TRIAGE,assessment='ATTACK_CONFIRMED'))):
            result = analyze_alert(ALERT)
        self.assertEqual(result['assessment'],'ATTEMPT_DETECTED')
        self.assertEqual(result['ai_status'],'gemini_overridden')
        self.assertEqual(result['reasoning_source'],'fallback_rules')
        self.assertEqual(result['fallback_reason'],'MODEL_DISAGREEMENT')
        with patch.object(runtime,'_invoke',return_value=self.answer(dict(OUTCOME,assessment='ATTACK_FAILED'))):
            result = assess_outcome(completed_observations())
        self.assertEqual(result['assessment'],'ATTACK_CONFIRMED')
        self.assertEqual(result['reasoning_source'],'fallback_rules')

    def test_placeholder_does_not_call_provider_or_become_authenticated(self):
        with patch.object(runtime,'_invoke') as invoke:
            result = assess_outcome({'trace':[{'tool':'authentication_logs','result':{
                'status':'completed','source':'authenticated_collector','evidence':{'successful_login':True}}}]})
            self.assertEqual(result['assessment'],'INCONCLUSIVE')
            self.assertEqual(result['fallback_reason'],'NO_ELIGIBLE_EVIDENCE')
            invoke.assert_not_called()

    def test_quota_auth_timeout_are_not_retried(self):
        for code in ('PROVIDER_QUOTA','PROVIDER_AUTHENTICATION','MODEL_UNAVAILABLE','PROVIDER_TIMEOUT','PROVIDER_TRANSPORT','PROVIDER_BLOCKED'):
            with self.subTest(code=code),patch.object(runtime,'_invoke',return_value={'code':code}) as invoke:
                answer = runtime.request_proposal('fixed',LiveProbe)
                self.assertEqual(answer.code,code)
                self.assertEqual(answer.attempts,1)
                self.assertEqual(invoke.call_count,1)

    def test_transient_retry_and_exhaustion_are_bounded(self):
        with patch.object(runtime,'_invoke',side_effect=[{'code':'PROVIDER_TRANSIENT'},self.answer({'status':'OK'})]) as invoke:
            answer = runtime.request_proposal('fixed',LiveProbe)
        self.assertEqual(answer.code,'OK')
        self.assertEqual(answer.attempts,2)
        self.assertEqual(invoke.call_count,2)
        with patch.object(runtime,'_invoke',return_value={'code':'PROVIDER_TRANSIENT'}) as invoke:
            answer = runtime.request_proposal('fixed',LiveProbe)
        self.assertEqual(answer.code,'PROVIDER_TRANSIENT')
        self.assertEqual(invoke.call_count,2)

    def test_expired_workflow_budget_never_starts_another_call(self):
        marker = runtime._deadline.set(time.monotonic()-1)
        try:
            with patch.object(runtime,'_invoke') as invoke:
                self.assertEqual(analyze_alert(ALERT)['fallback_reason'],'BUDGET_EXHAUSTED')
                self.assertEqual(choose_next_tool(ALERT,[])['fallback_reason'],'BUDGET_EXHAUSTED')
                invoke.assert_not_called()
        finally:
            runtime._deadline.reset(marker)
        with runtime.workflow_budget():
            outside = runtime._deadline.get()
            with runtime.workflow_budget():
                self.assertEqual(runtime._deadline.get(),outside)
        self.assertIsNone(runtime._deadline.get())

    def test_local_capacity_and_size_guards(self):
        runtime._capacity.acquire(); runtime._capacity.acquire()
        try:
            with patch.object(runtime,'_invoke') as invoke:
                self.assertEqual(runtime.request_proposal('fixed',LiveProbe).code,'LOCAL_CAPACITY')
                invoke.assert_not_called()
        finally:
            runtime._capacity.release(); runtime._capacity.release()
        with patch.object(runtime,'_invoke') as invoke:
            self.assertEqual(runtime.request_proposal('x'*24001,LiveProbe).code,'PROMPT_TOO_LARGE')
            invoke.assert_not_called()
        with patch.object(runtime,'_invoke',return_value={'code':'OK','text':'x'*24001}):
            self.assertEqual(runtime.request_proposal('fixed',LiveProbe).code,'RESPONSE_TOO_LARGE')

    def test_real_child_process_deadline_and_cleanup(self):
        children = {p.pid for p in multiprocessing.active_children()}
        start = time.monotonic()
        result = runtime._run_process(slow_worker,(),250)
        self.assertEqual(result['code'],'PROVIDER_TIMEOUT')
        self.assertLess(time.monotonic()-start,2.5)
        result = runtime._run_process(successful_worker,(),4000)
        self.assertEqual(result['code'],'OK')
        self.assertEqual({p.pid for p in multiprocessing.active_children()},children)

    def test_sdk_timeout_single_attempt_model_schema_close_and_no_tools(self):
        from google import genai
        client = MagicMock()
        client.models.generate_content.return_value = SimpleNamespace(
            candidates=[SimpleNamespace(finish_reason='STOP')],text='{"status":"OK"}')
        with patch.object(genai,'Client',return_value=client) as constructor:
            answer = runtime._sdk_exchange(config.load_ai_settings(),'fixed',LiveProbe.model_json_schema(),15000)
        self.assertEqual(answer['code'],'OK')
        kwargs = constructor.call_args.kwargs
        self.assertEqual(kwargs['http_options'].timeout,15000)
        self.assertEqual(kwargs['http_options'].retry_options.attempts,1)
        self.assertEqual(kwargs['http_options'].base_url,'https://generativelanguage.googleapis.com')
        self.assertFalse(kwargs['vertexai']); self.assertFalse(kwargs['enterprise'])
        request = client.models.generate_content.call_args.kwargs
        self.assertEqual(request['model'],MODEL)
        self.assertEqual(request['config']['automatic_function_calling'],{'disable':True})
        self.assertNotIn('tools',request['config'])
        client.close.assert_called_once()

    def test_sdk_error_categories_never_emit_raw_exception_or_keys(self):
        from google import genai
        class ProviderError(Exception):
            def __init__(self,code):
                self.code = code
                super().__init__('raw credential '+KEY)
        stream = io.StringIO()
        for number,expected in [(401,'PROVIDER_AUTHENTICATION'),(403,'PROVIDER_AUTHENTICATION'),
             (429,'PROVIDER_QUOTA'),(404,'MODEL_UNAVAILABLE'),(400,'PROVIDER_REQUEST_REJECTED'),(503,'PROVIDER_TRANSIENT')]:
            client = MagicMock()
            client.models.generate_content.side_effect = ProviderError(number)
            with redirect_stdout(stream),redirect_stderr(stream),patch.object(genai,'Client',return_value=client):
                result = runtime._sdk_exchange(config.load_ai_settings(),'fixed',LiveProbe.model_json_schema(),15000)
            self.assertEqual(result['code'],expected)
            self.assertNotIn(KEY,json.dumps(result))
            client.close.assert_called_once()
        self.assertEqual(stream.getvalue(),'')

    def test_blocked_truncated_empty_and_secret_reflection(self):
        from google import genai
        client = MagicMock()
        for response,expected in [(SimpleNamespace(candidates=[],text=''), 'PROVIDER_BLOCKED'),
            (SimpleNamespace(candidates=[SimpleNamespace(finish_reason='MAX_TOKENS')],text='{}'),'PROVIDER_INCOMPLETE'),
            (SimpleNamespace(candidates=[SimpleNamespace(finish_reason='STOP')],text=''),'PROVIDER_EMPTY')]:
            client.models.generate_content.return_value = response
            with patch.object(genai,'Client',return_value=client):
                self.assertEqual(runtime._sdk_exchange(config.load_ai_settings(),'fixed',{},15000)['code'],expected)
        with patch.object(runtime,'_invoke',return_value=self.answer(dict(TRIAGE,summary='Reflected '+KEY))) as invoke:
            result = analyze_alert(dict(ALERT,details='Input '+KEY))
        self.assertNotIn(KEY,json.dumps(result))
        self.assertNotIn(KEY,invoke.call_args.args[1])

    def test_live_probe_never_succeeds_on_fallback(self):
        import verify_gemini_live
        stream = io.StringIO()
        with redirect_stdout(stream),patch.object(runtime,'_invoke',return_value={'code':'PROVIDER_QUOTA'}):
            status = verify_gemini_live.main()
        self.assertEqual(status,1)
        self.assertEqual(json.loads(stream.getvalue())['status'],'LIVE_NOT_VERIFIED')
        self.assertNotIn(KEY,stream.getvalue())

    def sdk_wire(self,status):
        """Real installed SDK serialization over an offline HTTPX transport."""
        import httpx
        from google import genai
        real_client = genai.Client
        requests = []
        def handler(request):
            requests.append(request)
            if status==200:
                payload = {'candidates':[{'content':{'role':'model','parts':[{'text':'{"status":"OK"}'}]},'finishReason':'STOP'}]}
            else:
                payload = {'error':{'code':status,'message':'Offline provider error','status':'UNAVAILABLE'}}
            return httpx.Response(status,json=payload,request=request)
        with httpx.Client(transport=httpx.MockTransport(handler)) as http:
            def constructor(**kwargs):
                kwargs['http_options'] = kwargs['http_options'].model_copy(update={'httpx_client':http})
                return real_client(**kwargs)
            with patch.object(genai,'Client',side_effect=constructor):
                answer = runtime._sdk_exchange(config.load_ai_settings(),'fixed',LiveProbe.model_json_schema(),15000)
        return answer,requests

    def test_real_sdk_offline_request_and_response_contract(self):
        answer,requests = self.sdk_wire(200)
        self.assertEqual(answer['code'],'OK')
        self.assertEqual(len(requests),1)
        self.assertEqual(requests[0].headers['x-goog-api-key'],KEY)
        self.assertEqual(requests[0].url.host,'generativelanguage.googleapis.com')
        payload = json.loads(requests[0].content)
        self.assertIn('responseJsonSchema',payload['generationConfig'])
        self.assertNotIn('tools',payload)
        self.assertEqual(json.loads(answer['text']),{'status':'OK'})

    def test_real_sdk_hidden_retries_are_disabled(self):
        answer,requests = self.sdk_wire(503)
        self.assertEqual(answer['code'],'PROVIDER_TRANSIENT')
        self.assertEqual(len(requests),1)


if __name__=='__main__':
    unittest.main(verbosity=2)
