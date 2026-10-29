"""Verify the portfolio replay cannot use caller-supplied production paths."""

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
import tempfile
import unittest


class FinalReplay(unittest.TestCase):
    def test_report_is_redacted_and_project_databases_are_untouched(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); sentinel=root/'do-not-open.sqlite'; sentinel.write_bytes(b'protected project data')
            report=root/'report.json'
            env=dict(os.environ,SENTINELOPS_DB=str(sentinel),SENTINELOPS_ANALYST_DB=str(sentinel),
                     SENTINELOPS_REGISTRY_DB=str(sentinel),GEMINI_API_KEY='unusable-provider-sentinel')
            command=[sys.executable,'scripts/run_step12_walkthrough.py','--output',str(report)]
            result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=65)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(sentinel.read_bytes(),b'protected project data')
            data=json.loads(report.read_text()); self.assertEqual(data['cleanup'],'PASSED')
            self.assertEqual(len(data['stages']),9)
            self.assertTrue(all(row['passed'] for row in data['stages']))
            self.assertEqual(data['live_gemini'],'NOT_RUN')
            self.assertEqual(data['browser_capture'],'NOT_RUN')
            self.assertNotIn('unusable-provider-sentinel',report.read_text())
            self.assertNotIn(str(sentinel),report.read_text())
            allowed={'stage','passed','assessment','current_evidence_records','block_present','unauthenticated_http',
                     'viewer_http','http_status','request_status','verification_source','same_receipt','execution_audit_count',
                     'source','lifecycle_state','rollback_audit_count'}
            for row in data['stages']: self.assertLessEqual(set(row),allowed)
            before=report.read_bytes()
            repeated=subprocess.run(command,env=env,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(repeated.returncode,0)
            self.assertEqual(before,report.read_bytes())


if __name__=='__main__': unittest.main(verbosity=2)
