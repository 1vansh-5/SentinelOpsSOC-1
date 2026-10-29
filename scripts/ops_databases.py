"""Coordinated SQLite snapshots and recovery into NEW directories only.

No app import during backup/restore. Never overwrites source databases, env files
or credentials. Plain signing keys and bearer tokens are not recoverable from DBs.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
from contextlib import ExitStack, closing
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import tempfile

FILES={'incidents':'incidents.sqlite','analysts':'analysts.sqlite','registry':'registry.sqlite'}
CORE={'incidents':{'alerts','incidents','response_requests','simulated_blocks','response_audit','incident_evidence'},
      'analysts':{'analysts'},'registry':{'collectors','accepted_evidence','evidence_audit','collector_key_history'}}
CURRENT={'incidents':CORE['incidents'] | {'response_approval_bindings','response_executions',
        'response_execution_denials','simulation_effects','simulation_telemetry','response_rollbacks'},
        'analysts':CORE['analysts'],'registry':CORE['registry']}
COLUMNS={
 'alerts':'id created_at source_ip event_type target details severity status',
 'incidents':'id alert_id created_at assessment confidence evidence response_action response_status',
 'response_requests':'id incident_id source_ip action status requested_at decided_at decided_by',
 'simulated_blocks':'source_ip response_request_id blocked_at',
 'response_audit':'id response_request_id incident_id action actor details created_at',
 'incident_evidence':'id incident_id collector_id signature envelope_json stored_at',
 'analysts':'analyst_id role token_digest enabled created_at',
 'collectors':'collector_id key_fingerprint enabled',
 'accepted_evidence':'signature incident_id collector_id accepted_at',
 'evidence_audit':'id incident_id collector_id action reason signature_fingerprint created_at',
 'collector_key_history':'collector_id key_fingerprint created_at',
 'response_approval_bindings':'request_id digest',
 'response_executions':'request_id idempotency_key result_json created_at',
 'response_execution_denials':'id request_id claimed_analyst reason created_at',
 'simulation_effects':'request_id source_ip state updated_at',
 'simulation_telemetry':'id request_id operation expected_blocked observed_blocked matched source created_at',
 'response_rollbacks':'request_id idempotency_key result_json created_at'}


class OperationsError(Exception):
    """Contains only a safe, fixed reason code."""


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def readonly(path): return sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=1)


def inspect(path,role,current=False):
    if role not in FILES or not Path(path).is_file(): raise OperationsError('DATABASE_UNAVAILABLE')
    try:
        with closing(readonly(path)) as connection:
            if connection.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]: raise OperationsError('DATABASE_INTEGRITY_FAILED')
            tables={row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not (CURRENT if current else CORE)[role].issubset(tables): raise OperationsError('UNSUPPORTED_SCHEMA')
            for table in CURRENT[role] & tables:
                columns={row[1] for row in connection.execute('PRAGMA table_info('+table+')')}
                if not set(COLUMNS[table].split()).issubset(columns): raise OperationsError('UNSUPPORTED_SCHEMA')
            return {'role':role,'integrity':'ok','tables':sorted(tables),
                    'application_schema_current':CURRENT[role].issubset(tables)}
    except sqlite3.Error:
        raise OperationsError('DATABASE_UNAVAILABLE') from None


def destination(path):
    target=Path(path).resolve()
    if target.exists(): raise OperationsError('DESTINATION_ALREADY_EXISTS')
    if not target.parent.is_dir(): raise OperationsError('DESTINATION_PARENT_MISSING')
    return target


def validate_paths(paths):
    if set(paths)!=set(FILES): raise OperationsError('THREE_DATABASES_REQUIRED')
    resolved={role:Path(path).resolve() for role,path in paths.items()}
    if len(set(resolved.values()))!=3: raise OperationsError('DISTINCT_DATABASES_REQUIRED')
    for role,path in resolved.items(): inspect(path,role)
    for role,path in resolved.items():
        for other_role,other in resolved.items():
            if role!=other_role and os.path.samefile(path,other): raise OperationsError('DISTINCT_DATABASES_REQUIRED')
    return resolved


def backup(paths,output,*,server_stopped=False):
    if not server_stopped: raise OperationsError('SERVER_STOP_CONFIRMATION_REQUIRED')
    target=destination(output); paths=validate_paths(paths)
    stage=Path(tempfile.mkdtemp(prefix='.snapshot-partial-',dir=target.parent))
    try:
        with ExitStack() as stack:
            # Reserve every writer before taking any snapshots. Read connections
            # remain separate: sqlite backup on a writer transaction can deadlock.
            for path in sorted(paths.values()):
                lock=stack.enter_context(closing(sqlite3.connect(path.as_uri()+'?mode=rw',uri=True,timeout=1)))
                lock.execute('BEGIN IMMEDIATE')
            for role,path in paths.items():
                with closing(readonly(path)) as source, closing(sqlite3.connect(stage/FILES[role])) as dest:
                    source.backup(dest)
                    dest.execute('PRAGMA journal_mode=DELETE')
                inspect(stage/FILES[role],role)
        manifest={'format':1,'mode':'SIMULATION_ONLY','created_at':datetime.now(timezone.utc).isoformat(),
                  'databases':{role:{'file':name,'sha256':digest(stage/name)} for role,name in FILES.items()}}
        (stage/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
        verify_snapshot(stage)
        stage.rename(target)
        return {'status':'BACKUP_VERIFIED','mode':'SIMULATION_ONLY','database_count':3,
                'plaintext_credentials_included':False}
    except OperationsError: raise
    except (OSError,sqlite3.Error): raise OperationsError('BACKUP_FAILED') from None
    finally:
        if stage.exists(): shutil.rmtree(stage)


def verify_snapshot(folder):
    folder=Path(folder).resolve()
    try:
        path=folder/'manifest.json'
        if path.stat().st_size>65536: raise OperationsError('BACKUP_MANIFEST_INVALID')
        def pairs(items):
            result={}
            for key,value in items:
                if key in result: raise OperationsError('BACKUP_MANIFEST_INVALID')
                result[key]=value
            return result
        manifest=json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=pairs)
        if set(manifest)!={'format','mode','created_at','databases'} or type(manifest['format']) is not int or manifest['format']!=1 or manifest['mode']!='SIMULATION_ONLY':
            raise OperationsError('BACKUP_MANIFEST_INVALID')
        if set(manifest['databases'])!=set(FILES): raise OperationsError('BACKUP_MANIFEST_INVALID')
        timestamp=manifest['created_at']
        if not isinstance(timestamp,str) or len(timestamp)>64 or datetime.fromisoformat(timestamp).tzinfo is None:
            raise OperationsError('BACKUP_MANIFEST_INVALID')
        for role,name in FILES.items():
            entry=manifest['databases'][role]
            if set(entry)!={'file','sha256'} or entry['file']!=name: raise OperationsError('BACKUP_MANIFEST_INVALID')
            if not isinstance(entry['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',entry['sha256']): raise OperationsError('BACKUP_MANIFEST_INVALID')
            path=folder/name
            if path.is_symlink() or path.resolve().parent!=folder: raise OperationsError('BACKUP_MANIFEST_INVALID')
            if digest(path)!=entry['sha256']: raise OperationsError('BACKUP_HASH_MISMATCH')
            inspect(path,role)
        return manifest
    except OperationsError: raise
    except (OSError,ValueError,TypeError,KeyError): raise OperationsError('BACKUP_MANIFEST_INVALID') from None


def apply_current_schema(folder):
    # Work on a private recovery copy only. Preserve the application's established
    # migrations; legacy receipts remain LEGACY_UNVERIFIED, never retro-approved.
    from app import database
    from app.incident_evidence_store import init_incident_evidence_store
    from app.response_execution import init_execution_store
    from app.analyst_identity import AnalystIdentityStore
    from app.persistent_collector_registry import PersistentCollectorRegistry
    old=database.DB_PATH
    try:
        database.DB_PATH=str(Path(folder)/FILES['incidents'])
        database.init_db(); init_incident_evidence_store(); init_execution_store()
        AnalystIdentityStore(str(Path(folder)/FILES['analysts']))
        PersistentCollectorRegistry(str(Path(folder)/FILES['registry']))
    finally:
        database.DB_PATH=old


def recover(snapshot,output,*,upgrade=False):
    target=destination(output)
    manifest=verify_snapshot(snapshot)
    snapshot=Path(snapshot).resolve()
    stage=Path(tempfile.mkdtemp(prefix='.recovery-partial-',dir=target.parent))
    try:
        for role,name in FILES.items():
            # Reverify the copied bytes too, before treating them as SQLite.
            shutil.copyfile(snapshot/name,stage/name)
            if digest(stage/name)!=manifest['databases'][role]['sha256']: raise OperationsError('BACKUP_HASH_MISMATCH')
        if upgrade: apply_current_schema(stage)
        for role,name in FILES.items(): inspect(stage/name,role,current=upgrade)
        recovery={'status':'UPGRADE_STAGED' if upgrade else 'RESTORE_STAGED','mode':'SIMULATION_ONLY',
                  'credential_reconciliation_required':True,'automatic_activation':False,
                  'source_created_at':manifest['created_at']}
        (stage/'RECOVERY.json').write_text(json.dumps(recovery,indent=2),encoding='utf-8')
        stage.rename(target)
        return recovery
    except OperationsError: raise
    except Exception: raise OperationsError('RECOVERY_FAILED') from None
    finally:
        if stage.exists(): shutil.rmtree(stage)
