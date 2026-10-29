"""Run all ten baseline suites and both Step 6 suites in isolated subprocesses."""

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

SUITES = [
    'test_step_2_security.py', 'test_step_3_collector_lifecycle.py',
    'test_step_4_evidence_trust.py', 'test_step_4_authenticated_provenance.py',
    'test_step4_incident_evidence_store.py', 'test_step4_registry_storage_integration.py',
    'test_step4_api_ingestion.py', 'test_step4_response_authorization.py',
    'test_step5_analyst_identity.py', 'test_step5_integrated.py',
    'test_step6_integrated.py', 'test_step6_http.py']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket-free-http',action='store_true',help='Use offline polling asyncio loop for in-process ASGI tests')
    options = parser.parse_args()
    root = ROOT
    work = root/'work'
    work.mkdir(exist_ok=True)
    failed = []
    log = []
    with tempfile.TemporaryDirectory(prefix='step6-checks-',dir=work) as tmp:
        for suite in SUITES:
            env = dict(os.environ, TEMP=tmp, TMP=tmp,
                       SENTINELOPS_DB=str(Path(tmp)/(suite+'.sqlite')),
                       SENTINELOPS_ANALYST_DB=str(Path(tmp)/(suite+'.analysts.sqlite')),
                       SENTINELOPS_REGISTRY_DB=str(Path(tmp)/(suite+'.registry.sqlite')),
                       SENTINELOPS_COLLECTOR_ID='', SENTINELOPS_COLLECTOR_KEY='',
                       PYTHONIOENCODING='utf-8')
            code = ('import socket_free_test_loop; socket_free_test_loop.enable(); ' if options.socket_free_http else '')
            code += 'import runpy; runpy.run_path(__import__("project_paths").test_path('+repr(suite)+'),run_name="__main__")'
            try:
                result = subprocess.run([sys.executable,'-c',code],cwd=root,env=env,
                                        capture_output=True,text=True,encoding='utf-8',timeout=90)
                output = result.stdout+result.stderr
                passed = result.returncode == 0
            except subprocess.TimeoutExpired:
                output = 'TIMEOUT: suite did not complete within 90 seconds\n'
                passed = False
            entry = f'{suite}: '+('PASSED' if passed else 'FAILED')
            print(entry,flush=True)
            log.append(entry+'\n'+output)
            if not passed:
                failed.append(suite)
                print(output,flush=True)
    (root/'STEP6_TEST_RESULTS.txt').write_text('\n'.join(log),encoding='utf-8')
    print(f'{len(SUITES)-len(failed)}/{len(SUITES)} suites passed')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
