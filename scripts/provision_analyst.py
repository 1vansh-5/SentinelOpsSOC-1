"""Local-only trusted CLI provisioning. Never prints tokens to logs automatically."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
import os
from app.analyst_identity import AnalystIdentityStore

parser = argparse.ArgumentParser()
parser.add_argument('analyst_id')
parser.add_argument('role', choices=('viewer', 'analyst', 'admin'))
args = parser.parse_args()
store = AnalystIdentityStore(os.getenv('SENTINELOPS_ANALYST_DB', 'analysts.sqlite'))
created = store.create_analyst(args.analyst_id, args.role)
print('Identity created:', created['analyst_id'], 'role:', created['role'])
print('Store this token securely; it will not be shown again:')
print(created['token'])
