"""Run the unchanged 12-suite gate plus lifecycle and HTTP contract suites."""

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
from run_step6_checks import SUITES as PREVIOUS_SUITES

SUITES = PREVIOUS_SUITES + ['test_step7_lifecycle.py','test_step7_http_contracts.py']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket-free-http',action='store_true')
    options = parser.parse_args()
    root = ROOT
    work = root/'work'
    work.mkdir(exist_ok=True)
    log = []
    failures = []
    with tempfile.TemporaryDirectory(prefix='step7-checks-',dir=work) as tmp:
        for suite in SUITES:
            env = dict(os.environ,TEMP=tmp,TMP=tmp,
                       SENTINELOPS_DB=str(Path(tmp)/(suite+'.sqlite')),
                       SENTINELOPS_ANALYST_DB=str(Path(tmp)/(suite+'.analysts.sqlite')),
                       SENTINELOPS_REGISTRY_DB=str(Path(tmp)/(suite+'.registry.sqlite')),
                       SENTINELOPS_COLLECTOR_ID='',SENTINELOPS_COLLECTOR_KEY='',
                       GEMINI_API_KEY='',PYTHONIOENCODING='utf-8')
            code = ('import socket_free_test_loop; socket_free_test_loop.enable(); ' if options.socket_free_http else '')
            code += 'import runpy; runpy.run_path(__import__("project_paths").test_path('+repr(suite)+'),run_name="__main__")'
            try:
                result = subprocess.run([sys.executable,'-c',code],cwd=root,env=env,
                                        capture_output=True,text=True,encoding='utf-8',timeout=90)
                passed = result.returncode == 0
                output = result.stdout+result.stderr
            except subprocess.TimeoutExpired:
                passed = False
                output = 'TIMEOUT: test did not finish within 90 seconds\n'
            heading = suite+(': PASSED' if passed else ': FAILED')
            print(heading,flush=True)
            log.append(heading+'\n'+output)
            if not passed:
                failures.append(suite)
                print(output,flush=True)
    summary = f'{len(SUITES)-len(failures)}/{len(SUITES)} suites passed'
    (root/'STEP7_TEST_RESULTS.txt').write_text('\n'.join(log)+'\n'+summary+'\n',encoding='utf-8')
    print(summary)
    return int(bool(failures))


if __name__=='__main__':
    raise SystemExit(main())
