"""Supported localhost launcher. Load explicit settings before importing the app."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import sys

ROOT=ROOT
NAMES={'SENTINELOPS_DB','SENTINELOPS_ANALYST_DB','SENTINELOPS_REGISTRY_DB',
    'SENTINELOPS_API_KEY','SENTINELOPS_COLLECTOR_ID','SENTINELOPS_COLLECTOR_KEY',
    'GEMINI_API_KEY','GEMINI_MODEL','SENTINELOPS_GEMINI_ENABLED','SENTINELOPS_AI_TIMEOUT_MS',
    'SENTINELOPS_AI_MAX_ATTEMPTS','SENTINELOPS_AI_BUDGET_MS','ALLOWED_ORIGINS'}


def validate(env_file=None):
    if sys.version_info[:2]!=(3,15):
        raise ValueError('UNSUPPORTED_PYTHON: use Python 3.15')
    if env_file:
        path=Path(env_file).resolve()
        if not path.is_file() or path.stat().st_size>65536:
            raise ValueError('ENVIRONMENT_FILE_UNAVAILABLE')
        from dotenv import dotenv_values
        settings=dotenv_values(path,interpolate=False,encoding='utf-8-sig')
        for name in NAMES:
            if name not in os.environ and isinstance(settings.get(name),str): os.environ[name]=settings[name]
    for line in (ROOT/'requirements-step9-lock.txt').read_text().splitlines():
        if '==' not in line: continue
        name,version=line.split('==')
        try: installed=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError: installed=None
        if installed!=version: raise ValueError('DEPENDENCIES_DIFFER: install requirements.txt in a fresh environment')
    paths=[]
    for name,default in [('SENTINELOPS_DB','sentinelops.db'),('SENTINELOPS_ANALYST_DB','analysts.sqlite'),('SENTINELOPS_REGISTRY_DB','collector_registry.db')]:
        value=os.environ.get(name,default)
        if not value or value==':memory:': raise ValueError('PERSISTENT_DATABASE_PATH_REQUIRED')
        path=Path(value)
        path=(ROOT/path).resolve() if not path.is_absolute() else path.resolve()
        paths.append(path); os.environ[name]=str(path)
    if len(set(paths))!=3: raise ValueError('THREE_DISTINCT_DATABASE_PATHS_REQUIRED')
    for i,path in enumerate(paths):
        for other in paths[:i]:
            if path.exists() and other.exists() and os.path.samefile(path,other):
                raise ValueError('THREE_DISTINCT_DATABASE_PATHS_REQUIRED')
    if bool(os.environ.get('SENTINELOPS_COLLECTOR_ID'))!=bool(os.environ.get('SENTINELOPS_COLLECTOR_KEY')):
        raise ValueError('COLLECTOR_ID_AND_KEY_MUST_BE_CONFIGURED_TOGETHER')
    return {'status':'CONFIGURATION_VALID','mode':'SIMULATION_ONLY',
            'api_key_configured':bool(os.environ.get('SENTINELOPS_API_KEY')),
            'collector_configured':bool(os.environ.get('SENTINELOPS_COLLECTOR_ID')),
            'live_gemini':'NOT_CHECKED'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file',type=Path)
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if not 1024<=args.port<=65535: parser.error('Choose a port from 1024 through 65535')
    try: result=validate(args.env_file)
    except Exception as exc:
        # Only locally defined codes are allowed, never exception/provider text.
        code=str(exc) if isinstance(exc,ValueError) and str(exc).split(':')[0] in {
            'UNSUPPORTED_PYTHON','ENVIRONMENT_FILE_UNAVAILABLE','DEPENDENCIES_DIFFER',
            'PERSISTENT_DATABASE_PATH_REQUIRED','THREE_DISTINCT_DATABASE_PATHS_REQUIRED',
            'COLLECTOR_ID_AND_KEY_MUST_BE_CONFIGURED_TOGETHER'} else 'CONFIGURATION_UNAVAILABLE'
        print(json.dumps({'status':'CONFIGURATION_REJECTED','reason':code})); return 1
    print(json.dumps(result),flush=True)
    if args.check: return 0
    os.chdir(ROOT)
    import uvicorn
    print(f'SIMULATED / NOT PRODUCTION: http://127.0.0.1:{args.port}/dashboard',flush=True)
    try:
        uvicorn.run('app.main:app',host='127.0.0.1',port=args.port,workers=1,
            access_log=False,log_config=json.loads((ROOT/'ops/uvicorn_logging.json').read_text()))
    except Exception:
        print(json.dumps({'status':'SERVER_START_FAILED','reason':'STARTUP_OR_RUNTIME_UNAVAILABLE'})); return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
