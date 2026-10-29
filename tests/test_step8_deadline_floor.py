"""Regression for the provider's minimum ten-second deadline."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import os
import time
import unittest
from unittest.mock import patch
import test_step8_gemini as baseline
from app import gemini_config as config, gemini_runtime as runtime
from app.gemini_models import LiveProbe


class DeadlineFloor(unittest.TestCase):
    setUp = baseline.GeminiTests.setUp
    tearDown = baseline.GeminiTests.tearDown

    def test_fixed_defaults(self):
        with patch.dict(os.environ):
            for key in ('SENTINELOPS_AI_TIMEOUT_MS','SENTINELOPS_AI_BUDGET_MS'):
                os.environ.pop(key,None)
            value = config.load_ai_settings()
        self.assertEqual(value.timeout_ms,15000)
        self.assertEqual(value.budget_ms,60000)

    def test_old_five_second_configuration_fails_without_request(self):
        with patch.dict(os.environ,{'SENTINELOPS_AI_TIMEOUT_MS':'5000'}),patch.object(runtime,'_invoke') as invoke:
            result = runtime.request_proposal('fixed',LiveProbe)
        self.assertEqual(result.code,'INVALID_CONFIGURATION')
        self.assertEqual(result.attempts,0)
        invoke.assert_not_called()

    def test_partial_budget_cannot_make_short_provider_deadline(self):
        marker = runtime._deadline.set(time.monotonic()+9.5)
        try:
            with patch.object(runtime,'_invoke') as invoke:
                result = runtime.request_proposal('fixed',LiveProbe)
            self.assertEqual(result.code,'BUDGET_EXHAUSTED')
            self.assertEqual(result.attempts,0)
            invoke.assert_not_called()
        finally:
            runtime._deadline.reset(marker)

    def test_retry_reserves_minimum_provider_deadline(self):
        clock = [time.monotonic()]
        def transient(*args):
            clock[0] += 20.5
            return {'code':'PROVIDER_TRANSIENT'}
        marker = runtime._deadline.set(clock[0]+30)
        try:
            with patch.object(runtime.time,'monotonic',side_effect=lambda:clock[0]),patch.object(runtime,'_invoke',side_effect=transient) as invoke:
                result = runtime.request_proposal('fixed',LiveProbe)
            self.assertEqual(result.code,'BUDGET_EXHAUSTED')
            self.assertEqual(result.attempts,1)
            self.assertEqual(invoke.call_count,1)
        finally:
            runtime._deadline.reset(marker)

    def test_low_level_sdk_guard(self):
        from google import genai
        with patch.object(genai,'Client') as client:
            result = runtime._sdk_exchange(config.load_ai_settings(),'fixed',{},9999)
        self.assertEqual(result['code'],'BUDGET_EXHAUSTED')
        client.assert_not_called()

    def test_valid_request_uses_at_least_ten_seconds(self):
        with patch.object(runtime,'_invoke',return_value={'code':'OK','text':json.dumps({'status':'OK'})}) as invoke:
            result = runtime.request_proposal('fixed',LiveProbe)
        self.assertEqual(result.code,'OK')
        self.assertGreaterEqual(invoke.call_args.args[3],10000)
        self.assertLessEqual(invoke.call_args.args[3],15000)


if __name__=='__main__':
    unittest.main(verbosity=2)
