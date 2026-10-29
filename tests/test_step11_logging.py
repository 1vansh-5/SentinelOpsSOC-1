"""Operational logging omits headers, bodies, URLs, raw messages and exceptions."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import io
import json
import logging
import unittest
from unittest.mock import patch
import uuid
import test_step7_http_contracts as fixture
from app.structured_logging import SafeJSONFormatter


class StructuredLogs(unittest.TestCase):
    @classmethod
    def setUpClass(cls): fixture.Contracts.setUpClass.__func__(cls)
    @classmethod
    def tearDownClass(cls): fixture.Contracts.tearDownClass.__func__(cls)
    setUp=fixture.Contracts.setUp
    tearDown=fixture.Contracts.tearDown
    ok=fixture.Contracts.ok

    def test_http_metadata_only_and_server_generated_request_id(self):
        stream=io.StringIO(); handler=logging.StreamHandler(stream); handler.setFormatter(SafeJSONFormatter())
        logger=logging.getLogger('sentinelops.operations')
        with patch.object(logger,'handlers',[handler]):
            response=self.client.get('/health?api_key='+self.key,headers={'X-Analyst-Token':self.actor['token'],'X-Request-Id':self.key})
            self.ok(response)
            self.client.get('/unknown-'+self.key)
            self.client.post('/webhook/alert',headers=self.api,json={'password':self.key})
        entries=[json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(len(entries),3)
        self.assertEqual(entries[0]['route'],'/health')
        self.assertNotIn('route',entries[1])
        self.assertEqual(entries[2]['status_code'],422)
        self.assertEqual(str(uuid.UUID(response.headers['x-request-id'])),entries[0]['request_id'])
        for secret in (self.key,self.actor['token'],self.api['X-API-Key']): self.assertNotIn(secret,stream.getvalue())
        self.assertNotIn('password',stream.getvalue())

    def test_raw_exception_message_args_and_extra_fields_are_never_formatted(self):
        secret='not-a-real-provider-credential-'+uuid.uuid4().hex
        record=logging.LogRecord('uvicorn.error',logging.ERROR,'private/source/path',1,secret,(),(ValueError,ValueError(secret),None))
        record.api_key=secret; record.request_id=secret; record.route_template='/health?token='+secret
        value=SafeJSONFormatter().format(record)
        self.assertNotIn(secret,value); self.assertNotIn('private/source/path',value)
        self.assertNotIn('route',json.loads(value))
        self.assertEqual(json.loads(value)['event'],'server.lifecycle')

    def test_log_sink_failure_cannot_change_http_result(self):
        with patch.object(logging.getLogger('sentinelops.operations'),'info',side_effect=OSError('private log sink unavailable')):
            self.ok(self.client.get('/health'))


if __name__=='__main__': unittest.main(verbosity=2)
