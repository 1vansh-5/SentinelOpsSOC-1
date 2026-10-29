"""Replay a synthetic response through real ASGI routes in disposable databases.

Run in a fresh interpreter. No listening socket, production database or provider
request is used. The report contains only fixed labels and selected safe values.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile


class WalkthroughFailed(RuntimeError):
    pass


def replay(folder):
    from step9_offline_guard import install
    install()
    from run_step10_demo import prepare
    app,actor,viewer=prepare(folder)
    from fastapi.testclient import TestClient
    from socket_free_test_loop import OfflineLoop
    analyst={'X-Analyst-Id':actor['analyst_id'],'X-Analyst-Token':actor['token']}
    observer={'X-Analyst-Id':viewer['analyst_id'],'X-Analyst-Token':viewer['token']}
    stages=[]

    def require(condition):
        if not condition: raise WalkthroughFailed('WALKTHROUGH_CONTRACT_FAILED')

    def record(name,**values):
        stages.append({'stage':name,'passed':True,**values})

    with TestClient(app,raise_server_exceptions=False,backend_options={'loop_factory':OfflineLoop}) as client:
        def call(method,path,headers=analyst,status=200,body=None):
            response=client.request(method,path,headers=headers,json=body) if body is not None else client.request(method,path,headers=headers)
            require(response.status_code==status)
            return response.json()

        def detail(): return call('GET','/dashboard/api/incidents/3')
        initial=detail(); request=initial['request']['id']
        require(initial['incident']['assessment']=='ATTACK_CONFIRMED')
        require(initial['request']['status']=='PENDING' and not initial['block_present'])
        require(len(initial['evidence'])==2 and all(row['provenance']=='authenticated_current' for row in initial['evidence']))
        record('SIGNED_SYNTHETIC_INVESTIGATION',assessment='ATTACK_CONFIRMED',current_evidence_records=2,block_present=False)
        call('GET','/dashboard/api/overview',headers={},status=401)
        call('POST',f'/response-requests/{request}/decision',headers=observer,status=403,
             body={'decision':'APPROVED','reason':'Synthetic viewer denial check'})
        record('UNAUTHENTICATED_AND_VIEWER_DENIED',unauthenticated_http=401,viewer_http=403)
        execution=dict(analyst,**{'Idempotency-Key':'step12-execution-0001'})
        # Even an authorized analyst must obtain approval before execution.
        denied=client.post(f'/response-requests/{request}/execute',headers=execution)
        require(denied.status_code in (403,409) and not detail()['block_present'])
        record('PENDING_EXECUTION_DENIED',http_status=denied.status_code,block_present=False)
        call('POST',f'/response-requests/{request}/decision',body={'decision':'APPROVED','reason':'Synthetic authenticated evidence reviewed'})
        approved=detail(); require(approved['request']['status']=='APPROVED' and not approved['block_present'])
        record('EXPLICIT_ANALYST_APPROVAL',request_status='APPROVED',block_present=False)
        receipt=call('POST',f'/response-requests/{request}/execute',headers=execution)
        executed=detail(); require(executed['block_present'])
        require(executed['telemetry'][0]['source']=='synthetic_sqlite_probe' and executed['telemetry'][0]['matched'])
        record('SIMULATED_EXECUTION',block_present=True,verification_source='synthetic_sqlite_probe')
        repeated=call('POST',f'/response-requests/{request}/execute',headers=execution)
        require(not receipt['replayed'] and repeated['replayed'])
        require({k:v for k,v in receipt.items() if k!='replayed'}=={k:v for k,v in repeated.items() if k!='replayed'})
        require(sum(row['action']=='SIMULATED_EXECUTED' for row in detail()['audit'])==1)
        record('EXECUTION_RETRY',same_receipt=True,execution_audit_count=1)
        call('POST',f'/response-requests/{request}/verify')
        record('EXPLICIT_VERIFICATION',source='synthetic_sqlite_probe')
        rollback=dict(analyst,**{'Idempotency-Key':'step12-rollback-0001'})
        rolled=call('POST',f'/response-requests/{request}/rollback',headers=rollback,body={'reason':'Synthetic final walkthrough cleanup'})
        repeated_rollback=call('POST',f'/response-requests/{request}/rollback',headers=rollback,body={'reason':'Synthetic final walkthrough cleanup'})
        require(not rolled['replayed'] and repeated_rollback['replayed'])
        require({k:v for k,v in rolled.items() if k!='replayed'}=={k:v for k,v in repeated_rollback.items() if k!='replayed'})
        final=detail(); require(not final['block_present'] and final['request']['lifecycle_state']=='ROLLED_BACK')
        require(sum(row['action']=='SIMULATED_ROLLED_BACK' for row in final['audit'])==1)
        record('ROLLBACK_AND_RETRY',lifecycle_state='ROLLED_BACK',block_present=False,rollback_audit_count=1)
        # A historical receipt must never recreate the rolled-back effect.
        historical=call('POST',f'/response-requests/{request}/execute',headers=execution)
        require(historical['replayed'])
        require({k:v for k,v in historical.items() if k!='replayed'}=={k:v for k,v in receipt.items() if k!='replayed'})
        require(not detail()['block_present'])
        overview=call('GET','/dashboard/api/overview')
        require(overview['counts']['active_effects']==0 and overview['counts']['rollbacks']==2)
        record('HISTORICAL_EXECUTION_REPLAY',same_receipt=True,block_present=False)
    return {'format':1,'status':'PASSED','mode':'SIMULATION_ONLY',
        'generated_utc':datetime.now(timezone.utc).isoformat(),
        'transport':'in-process ASGI; not browser or listening-server validation',
        'live_gemini':'NOT_RUN','browser_capture':'NOT_RUN','production_data':'NOT_OPENED',
        'seeded_cases':3,'stages':stages,'cleanup':'PENDING'}


def run():
    root=ROOT; work=root/'work'; work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='step12-walkthrough-',dir=work) as folder:
        report=replay(Path(folder))
    report['cleanup']='PASSED'
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='New JSON report path; refuses to overwrite')
    args=parser.parse_args()
    if not args.output.parent.is_dir() or args.output.exists():
        parser.error('Choose a new report filename in an existing directory')
    try:
        report=run()
    except Exception:
        # Never print a provider error, envelope, token, raw database row or traceback.
        raise SystemExit('Final walkthrough failed; no report published. Run the regression gate for diagnostics.') from None
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2)
    print(f'{len(report["stages"])}/{len(report["stages"])} walkthrough stages passed; cleanup: PASSED')
    print('Live Gemini and browser capture: NOT RUN')


if __name__=='__main__': main()
