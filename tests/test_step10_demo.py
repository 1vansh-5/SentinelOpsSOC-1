"""Exercise the isolated demo bootstrap in a fresh interpreter, never project DBs."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class IsolatedDemo(unittest.TestCase):
    def test_bootstrap_with_temporary_databases_and_no_live_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            code='''
import os
from pathlib import Path
import tempfile
from run_step10_demo import prepare
from socket_free_test_loop import OfflineLoop
from fastapi.testclient import TestClient
# prepare() must choose the database paths before importing app.main.
root=Path(os.environ['STEP10_DEMO_TEST'])
sentinel=root/'protected.sqlite'; sentinel.write_bytes(b'untouched sentinel')
os.environ['SENTINELOPS_DB']=str(sentinel)
app,actor,viewer=prepare(root/'isolated')
assert sentinel.read_bytes()==b'untouched sentinel'
assert os.environ['GEMINI_API_KEY']==''
assert os.environ['SENTINELOPS_GEMINI_ENABLED']=='0'
headers={'X-Analyst-Id':actor['analyst_id'],'X-Analyst-Token':actor['token']}
with TestClient(app,backend_options={'loop_factory':OfflineLoop}) as client:
    response=client.get('/dashboard/api/overview',headers=headers)
    assert response.status_code==200
    counts=response.json()['counts']
    assert counts=={'incidents':3,'pending':1,'active_effects':0,'rollbacks':1},counts
    detail=client.get('/dashboard/api/incidents/3',headers=headers).json()
    assert detail['eligibility']['can_approve']
    assert len(detail['evidence'])==2
    assert all(item['provenance']=='authenticated_current' for item in detail['evidence'])
    viewer_headers={'X-Analyst-Id':viewer['analyst_id'],'X-Analyst-Token':viewer['token']}
    assert not client.get('/dashboard/api/identity',headers=viewer_headers).json()['can_decide']
assert all((root/'isolated'/name).is_file() for name in ('incidents.sqlite','analysts.sqlite','registry.sqlite'))
print('Isolated demo seed, roles, current evidence, historical rollback and production-path sentinel: PASSED')
'''
            env=dict(os.environ,STEP10_DEMO_TEST=tmp)
            result=subprocess.run([sys.executable,'-c',code],cwd=ROOT,
                env=env,capture_output=True,text=True,encoding='utf-8',timeout=50)
            print(result.stdout)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__=='__main__':
    unittest.main(verbosity=2)
