"""Offline backup/verify/recovery CLI. Recovery never replaces live databases."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
import json
from pathlib import Path
from ops_databases import backup,verify_snapshot,recover,inspect,OperationsError


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    snapshot=commands.add_parser('backup')
    for name in ('incidents','analysts','registry'): snapshot.add_argument('--'+name,type=Path,required=True)
    snapshot.add_argument('--output',type=Path,required=True)
    snapshot.add_argument('--server-stopped',action='store_true')
    verify=commands.add_parser('verify'); verify.add_argument('--snapshot',type=Path,required=True)
    for name in ('restore','stage-upgrade'):
        command=commands.add_parser(name)
        command.add_argument('--snapshot',type=Path,required=True)
        command.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.command=='backup':
            result=backup({name:getattr(args,name) for name in ('incidents','analysts','registry')},args.output,server_stopped=args.server_stopped)
        elif args.command=='verify':
            verify_snapshot(args.snapshot); result={'status':'BACKUP_VERIFIED','mode':'SIMULATION_ONLY','database_count':3}
        else: result=recover(args.snapshot,args.output,upgrade=args.command=='stage-upgrade')
        print(json.dumps(result)); return 0
    except OperationsError as exc:
        print(json.dumps({'status':'OPERATION_REFUSED','reason':str(exc),'mode':'SIMULATION_ONLY'})); return 1
    except Exception:
        print(json.dumps({'status':'OPERATION_REFUSED','reason':'OPERATION_UNAVAILABLE','mode':'SIMULATION_ONLY'})); return 1


if __name__=='__main__':
    raise SystemExit(main())
