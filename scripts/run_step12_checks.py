"""Run the grouped offline gate in a disposable source copy."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
from datetime import datetime, timezone
import re
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

GROUPS = {
    'unit_and_security': [
        'test_step_2_security.py', 'test_step_3_collector_lifecycle.py',
        'test_step_4_evidence_trust.py', 'test_step_4_authenticated_provenance.py',
        'test_step5_analyst_identity.py', 'test_step8_gemini.py',
        'test_step8_deadline_floor.py'],
    'sqlite_and_transactions': [
        'test_step4_incident_evidence_store.py', 'test_step4_registry_storage_integration.py',
        'test_step4_response_authorization.py', 'test_step5_integrated.py',
        'test_step6_integrated.py', 'test_step7_lifecycle.py'],
    'api_integration': [
        'test_step4_api_ingestion.py', 'test_step6_http.py',
        'test_step7_http_contracts.py', 'test_step8_http.py'],
    'gate_safety': ['test_step9_gate.py'],
    'dashboard': ['test_step10_dashboard.py','test_step10_frontend.py','test_step10_demo.py'],
    'final_handoff': ['test_step12_walkthrough.py','test_step12_contracts.py'],
    'operations': ['test_step11_operations.py','test_step11_logging.py','test_step11_hygiene.py','test_step11_clean_setup.py'],
}


def copy_source(source, target):
    from project_paths import copy_public_source
    copy_public_source(source,target)


def child_environment(folder):
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(('GEMINI_', 'GOOGLE_', 'SENTINELOPS_', 'TEST_'))
           and not any(word in key.upper() for word in ('TOKEN', 'SECRET', 'API_KEY', 'PASSWORD'))}
    env.update(TEMP=str(folder), TMP=str(folder), PYTHONPATH=str(folder),
               PYTHONIOENCODING='utf-8', PYTHONNOUSERSITE='1', PYTHONOPTIMIZE='0',
               GEMINI_API_KEY='', GEMINI_MODEL='', SENTINELOPS_OFFLINE_GATE='1',
               SENTINELOPS_DB=str(folder/'incidents.sqlite'),
               SENTINELOPS_ANALYST_DB=str(folder/'analysts.sqlite'),
               SENTINELOPS_REGISTRY_DB=str(folder/'registry.sqlite'),
               SENTINELOPS_COLLECTOR_ID='', SENTINELOPS_COLLECTOR_KEY='',
               SENTINELOPS_GEMINI_ENABLED='1', SENTINELOPS_AI_TIMEOUT_MS='15000',
               SENTINELOPS_AI_BUDGET_MS='60000', SENTINELOPS_AI_MAX_ATTEMPTS='2')
    return env


def run_job(folder, suite, socket_free, timeout=120):
    code = 'import step9_offline_guard; step9_offline_guard.install(); '
    if socket_free:
        code += 'import socket_free_test_loop; socket_free_test_loop.enable(); '
    code += 'import runpy; runpy.run_path(__import__("project_paths").test_path('+repr(suite)+'),run_name="__main__")'
    started = time.monotonic()
    try:
        result = subprocess.run([sys.executable, '-c', code], cwd=folder,
                                env=child_environment(folder), capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=timeout)
        return {'passed': result.returncode == 0, 'returncode': result.returncode,
                'seconds': round(time.monotonic()-started, 3),
                'output': result.stdout+result.stderr}
    except subprocess.TimeoutExpired:
        return {'passed': False, 'returncode': None,
                'seconds': round(time.monotonic()-started, 3), 'output': 'Test process timed out.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket-free-http', action='store_true')
    parser.add_argument('--repeat-concurrency', type=int, default=3, choices=range(3, 11))
    parser.add_argument('--node',default=shutil.which('node'))
    args = parser.parse_args()
    if not args.node or not Path(args.node).is_file():
        parser.error('Node.js 20+ is required. Install Node or pass --node with its full executable path.')
    node=Path(args.node).resolve()
    version=subprocess.run([str(node),'--version'],capture_output=True,text=True,timeout=10)
    match=re.match(r'v(\d+)\.',version.stdout.strip())
    if version.returncode or not match or int(match.group(1))<20:
        parser.error('Node.js 20+ is required for frontend tests.')
    os.environ['STEP10_NODE']=str(node)
    root = ROOT
    from run_step8_checks import SUITES
    inherited = [suite for group, suites in GROUPS.items() if group not in ('gate_safety','dashboard','operations','final_handoff') for suite in suites]
    if len(inherited) != len(set(inherited)) or set(inherited) != set(SUITES):
        raise SystemExit('Gate catalog differs from the Step 8 suite list; no tests run.')
    work = root/'work'; work.mkdir(exist_ok=True)
    report = {'started_utc': datetime.now(timezone.utc).isoformat(),
              'live_gemini': 'NOT_RUN', 'ci_execution': 'NOT_RUN_LOCALLY',
              'browser_visual_qa': 'NOT_RUN_BY_OFFLINE_GATE',
              'frontend_test_kind': 'Node DOM contract tests; not a browser renderer',
              'socket_free_http': args.socket_free_http, 'results': [], 'cleanup': 'PENDING'}
    jobs = [(group, suite, None) for group, suites in GROUPS.items() for suite in suites]
    jobs += [('concurrency', 'test_step9_concurrency.py', repeat)
             for repeat in range(1, args.repeat_concurrency+1)]
    folder = Path(tempfile.mkdtemp(prefix='step12-checks-', dir=work))
    try:
        for index, (group, suite, repeat) in enumerate(jobs, 1):
            # A fresh source tree and environment for EVERY job prevents cross-suite state.
            job_folder = folder/str(index)
            copy_source(root, job_folder)
            result = run_job(job_folder, suite, args.socket_free_http)
            result.update(group=group, suite=suite, repeat=repeat)
            report['results'].append(result)
            heading = f'[{group}] {suite}' + (f' (repeat {repeat})' if repeat else '')
            print(heading+(': PASSED' if result['passed'] else ': FAILED'), flush=True)
            if not result['passed']:
                print(result['output'], flush=True)
            try:
                shutil.rmtree(job_folder)
            except OSError:
                report['results'].append({'group':'cleanup', 'suite':suite, 'repeat':repeat,
                                          'passed':False, 'output':'Temporary files still in use.'})
                print('Windows cleanup: FAILED', flush=True)
    finally:
        try:
            shutil.rmtree(folder)
            report['cleanup'] = 'PASSED'
        except OSError:
            report['cleanup'] = 'FAILED'
        failures = sum(not item['passed'] for item in report['results'])
        passed = sum(item['passed'] for item in report['results'])
        report['passed'] = failures == 0 and report['cleanup'] == 'PASSED' and len(report['results']) == len(jobs)
        report['summary'] = f'{passed}/{len(jobs)} test jobs passed; cleanup: {report["cleanup"]}'
        (root/'STEP12_TEST_RESULTS.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        text = '\n\n'.join(f'[{r["group"]}] {r["suite"]} repeat={r["repeat"]}\n{r["output"]}'
                            for r in report['results'])
        (root/'STEP12_TEST_RESULTS.txt').write_text(text+'\n\n'+report['summary']+'\n', encoding='utf-8')
    print(report['summary'])
    print('Live Gemini authentication: NOT RUN by this offline gate.')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
