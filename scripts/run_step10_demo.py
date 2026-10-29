"""Start an isolated, temporary, localhost-only dashboard demo; no live AI calls."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
import os
from pathlib import Path
import secrets
import sys
import tempfile


def seed(app, actor, key, api_key):
    from fastapi.testclient import TestClient
    from socket_free_test_loop import OfflineLoop
    from app.evidence_signing import create_signed_evidence
    analyst={'X-Analyst-Id':actor['analyst_id'],'X-Analyst-Token':actor['token']}
    api={'X-API-Key':api_key}
    def checked(response):
        if response.status_code!=200:
            raise RuntimeError('Isolated demo setup failed; no project databases were opened')
        return response.json()
    # Only the in-process seed client uses this loop; the API server stays normal.
    with TestClient(app,raise_server_exceptions=False,backend_options={'loop_factory':OfflineLoop}) as client:
        for index,(ip,target) in enumerate([('9.9.9.9','admin-console'),('1.1.1.1','customer-api'),('8.8.8.8','identity-gateway')]):
            alert=checked(client.post('/webhook/alert',headers=api,json={
                'source_ip':ip,'event_type':'failed_login','target':target,
                'details':'Synthetic Step 10 isolated demo observations','severity':'high' if index!=1 else 'medium'}))
            incident=checked(client.post(f'/alerts/{alert["id"]}/investigate',headers=api))['incident_id']
            failed=index==1
            records=[('authentication_logs',{'login_attempts':36,'failed_logins':36 if failed else 35,
                'successful_login':not failed,'session_created':not failed}),
                ('application_logs',{'unauthorized_access_observed':not failed,'http_status':403 if failed else 200})]
            for tool,observations in records:
                envelope=create_signed_evidence(incident,'step10_demo_collector',{'source_ip':ip,'tool':tool,'observations':observations},key)
                checked(client.post(f'/incidents/{incident}/evidence/submit',headers=api,json={'envelope':envelope}))
            checked(client.post(f'/incidents/{incident}/investigate-authenticated',headers=analyst))
            if not failed:
                request=checked(client.post(f'/response-requests/for-incident/{incident}',headers=analyst))['request_id']
                if index==0:
                    checked(client.post(f'/response-requests/{request}/decision',headers=analyst,json={'decision':'APPROVED','reason':'Isolated synthetic demonstration reviewed'}))
                    checked(client.post(f'/response-requests/{request}/execute',headers=dict(analyst,**{'Idempotency-Key':'demo-execution-0001'})))
                    checked(client.post(f'/response-requests/{request}/rollback',headers=dict(analyst,**{'Idempotency-Key':'demo-rollback-0001'}),json={'reason':'Isolated demo historical rollback'}))


def prepare(folder):
    """Must run before importing the application. Never reads production DBs."""
    folder=Path(folder).resolve()
    if 'app.main' in sys.modules or 'app.database' in sys.modules:
        raise RuntimeError('Start the isolated demo in a fresh Python process')
    folder.mkdir(parents=True,exist_ok=True)
    if any((folder/name).exists() for name in ('incidents.sqlite','analysts.sqlite','registry.sqlite')):
        raise RuntimeError('Refusing to reuse an existing demo database')
    key=secrets.token_hex(32); api_key=secrets.token_hex(32)
    os.environ.update(SENTINELOPS_DB=str(folder/'incidents.sqlite'),
        SENTINELOPS_ANALYST_DB=str(folder/'analysts.sqlite'),
        SENTINELOPS_REGISTRY_DB=str(folder/'registry.sqlite'),
        SENTINELOPS_COLLECTOR_ID='step10_demo_collector',SENTINELOPS_COLLECTOR_KEY=key,
        SENTINELOPS_API_KEY=api_key,SENTINELOPS_DEMO_MODE='1',GEMINI_API_KEY='',GEMINI_MODEL='',
        SENTINELOPS_GEMINI_ENABLED='0',SENTINELOPS_AI_TIMEOUT_MS='15000',SENTINELOPS_AI_BUDGET_MS='60000')
    from app.persistent_collector_registry import PersistentCollectorRegistry
    registry=PersistentCollectorRegistry(os.environ['SENTINELOPS_REGISTRY_DB'])
    registry.register_collector('step10_demo_collector',key)
    from app.main import app,analyst_store
    actor=analyst_store.create_analyst('demo_analyst','analyst')
    viewer=analyst_store.create_analyst('demo_viewer','viewer')
    seed(app,actor,key,api_key)
    return app,actor,viewer


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    if not 1024<=args.port<=65535:
        parser.error('Choose a port between 1024 and 65535')
    root=ROOT
    work=root/'work'; work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='step10-demo-',dir=work) as folder:
        app,actor,viewer=prepare(folder)
        print('\nSIMULATED / NOT PRODUCTION. Temporary demo databases only. Live Gemini disabled.',flush=True)
        print(f'Open http://127.0.0.1:{args.port}/dashboard and choose Connect analyst.',flush=True)
        for account in (actor,viewer):
            print(f'Local demo ID: {account["analyst_id"]}\nOne-session demo token: {account["token"]}',flush=True)
        print('These are generated demo credentials, not production tokens. Do not share them.\n'
              'Signed demo evidence expires after ten minutes. Restart for a fresh demo.\n'
              'Press Ctrl+C to stop and remove the temporary databases.\n',flush=True)
        import uvicorn
        uvicorn.run(app,host='127.0.0.1',port=args.port,access_log=False,log_level='warning')


if __name__=='__main__':
    main()
