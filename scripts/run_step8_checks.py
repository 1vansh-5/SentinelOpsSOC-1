"""Offline gate: unchanged Steps 2-7 plus Gemini unit and real ASGI integration tests."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from run_step7_checks import SUITES as PREVIOUS_SUITES

SUITES = PREVIOUS_SUITES + ['test_step8_gemini.py','test_step8_http.py','test_step8_deadline_floor.py']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket-free-http',action='store_true')
    options = parser.parse_args()
    root = ROOT
    work = root/'work'; work.mkdir(exist_ok=True)
    results = []; failures = []
    with tempfile.TemporaryDirectory(prefix='step8-checks-',dir=work) as tmp:
        for suite in SUITES:
            env = dict(os.environ,TEMP=tmp,TMP=tmp,
                SENTINELOPS_DB=str(Path(tmp)/(suite+'.sqlite')),
                SENTINELOPS_ANALYST_DB=str(Path(tmp)/(suite+'.analysts.sqlite')),
                SENTINELOPS_REGISTRY_DB=str(Path(tmp)/(suite+'.registry.sqlite')),
                SENTINELOPS_COLLECTOR_ID='',SENTINELOPS_COLLECTOR_KEY='',
                GEMINI_API_KEY='',GEMINI_MODEL='',SENTINELOPS_GEMINI_ENABLED='1',
                SENTINELOPS_AI_TIMEOUT_MS='15000',SENTINELOPS_AI_MAX_ATTEMPTS='2',
                SENTINELOPS_AI_BUDGET_MS='60000',PYTHONIOENCODING='utf-8')
            code = ('import socket_free_test_loop; socket_free_test_loop.enable(); ' if options.socket_free_http else '')
            code += 'import runpy; runpy.run_path(__import__("project_paths").test_path('+repr(suite)+'),run_name="__main__")'
            try:
                result = subprocess.run([sys.executable,'-c',code],cwd=root,env=env,
                    capture_output=True,text=True,encoding='utf-8',timeout=90)
                passed = result.returncode==0
                output = result.stdout+result.stderr
            except subprocess.TimeoutExpired:
                passed = False; output = 'TIMEOUT: test did not finish within 90 seconds\n'
            heading = suite+(': PASSED' if passed else ': FAILED')
            print(heading,flush=True); results.append(heading+'\n'+output)
            if not passed:
                failures.append(suite); print(output,flush=True)
    summary = f'{len(SUITES)-len(failures)}/{len(SUITES)} suites passed'
    (root/'STEP8_TEST_RESULTS.txt').write_text('\n'.join(results)+'\n'+summary+'\n',encoding='utf-8')
    print(summary)
    print('Live Gemini authentication: NOT RUN by this offline gate.')
    return int(bool(failures))


if __name__=='__main__':
    raise SystemExit(main())
