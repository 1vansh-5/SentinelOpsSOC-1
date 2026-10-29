"""Backup consistency, staged migration, recovery refusal and Windows cleanup."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import test_step6_integrated as fixture
import ops_databases as ops


class Operations(unittest.TestCase):
    setUp=fixture.Integrated.setUp
    tearDown=fixture.Integrated.tearDown
    sql=fixture.Integrated.sql
    proposal=fixture.Integrated.proposal
    route=fixture.Integrated.route
    approve=fixture.Integrated.approve
    execute=fixture.Integrated.execute

    def paths(self):
        from app import database
        return {'incidents':Path(database.DB_PATH),'analysts':Path(self.ids.database_path),'registry':Path(self.registry.database_path)}

    def output(self,name): return Path(self.temp.name)/name

    def snapshot(self):
        path=self.output('snapshot')
        ops.backup(self.paths(),path,server_stopped=True)
        return path

    def test_backup_integrity_and_source_rows_preserved(self):
        self.approve(); self.execute()
        before={role:ops.digest(path) for role,path in self.paths().items()}
        snapshot=self.snapshot(); manifest=ops.verify_snapshot(snapshot)
        self.assertEqual(set(manifest['databases']),set(ops.FILES))
        self.assertEqual(before,{role:ops.digest(path) for role,path in self.paths().items()})
        text=json.dumps(manifest)
        self.assertNotIn(self.key,text); self.assertNotIn(self.actor['token'],text)
        self.assertNotIn(self.temp.name,text)
        restored=self.output('restored'); result=ops.recover(snapshot,restored)
        self.assertEqual(result['status'],'RESTORE_STAGED')
        self.assertTrue(result['credential_reconciliation_required'])
        self.assertFalse(result['automatic_activation'])
        with closing(sqlite3.connect(restored/ops.FILES['incidents'])) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM response_executions').fetchone()[0],1)

    def test_requires_stop_confirmation_distinct_existing_stores_and_new_output(self):
        with self.assertRaisesRegex(ops.OperationsError,'SERVER_STOP'): ops.backup(self.paths(),self.output('one'))
        paths=self.paths(); paths['registry']=paths['analysts']
        with self.assertRaisesRegex(ops.OperationsError,'DISTINCT'): ops.backup(paths,self.output('two'),server_stopped=True)
        paths=self.paths(); paths['registry']=self.output('missing.sqlite')
        with self.assertRaisesRegex(ops.OperationsError,'DATABASE_UNAVAILABLE'): ops.backup(paths,self.output('three'),server_stopped=True)
        self.assertFalse(paths['registry'].exists())
        snapshot=self.snapshot()
        with self.assertRaisesRegex(ops.OperationsError,'DESTINATION_ALREADY'): ops.backup(self.paths(),snapshot,server_stopped=True)

    def test_tampering_and_path_traversal_refused(self):
        snapshot=self.snapshot(); manifest_path=snapshot/'manifest.json'
        original=manifest_path.read_bytes(); manifest=json.loads(original)
        manifest['databases']['incidents']['file']='../protected.sqlite'
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ops.OperationsError): ops.recover(snapshot,self.output('unsafe'))
        self.assertFalse(self.output('unsafe').exists())
        manifest_path.write_bytes(original)
        path=snapshot/ops.FILES['incidents']; data=path.read_bytes(); path.write_bytes(data+b'tamper')
        with self.assertRaisesRegex(ops.OperationsError,'HASH_MISMATCH'): ops.verify_snapshot(snapshot)

    def test_wal_committed_rows_are_included(self):
        paths=self.paths()
        with closing(sqlite3.connect(paths['incidents'])) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            with writer: writer.execute("UPDATE alerts SET details='Committed WAL observation'")
            snapshot=self.snapshot()
            with closing(sqlite3.connect(snapshot/ops.FILES['incidents'])) as restored:
                self.assertEqual(restored.execute('SELECT details FROM alerts').fetchone()[0],'Committed WAL observation')

    def test_writer_conflict_fails_without_partial_bundle(self):
        with closing(sqlite3.connect(self.paths()['registry'])) as writer:
            writer.execute('BEGIN IMMEDIATE')
            with self.assertRaisesRegex(ops.OperationsError,'BACKUP_FAILED'):
                ops.backup(self.paths(),self.output('blocked'),server_stopped=True)
        self.assertFalse(self.output('blocked').exists())
        self.assertFalse(list(Path(self.temp.name).glob('.snapshot-partial-*')))

    def test_staged_upgrade_is_idempotent_and_preserves_legacy_safety(self):
        self.approve(); self.execute()
        for name in ('simulation_effects','simulation_telemetry','response_rollbacks'):
            self.sql('DROP TABLE '+name)
        snapshot=self.snapshot(); before=ops.digest(snapshot/ops.FILES['incidents'])
        output=self.output('upgraded'); ops.recover(snapshot,output,upgrade=True)
        ops.inspect(output/ops.FILES['incidents'],'incidents',current=True)
        with closing(sqlite3.connect(output/ops.FILES['incidents'])) as connection:
            self.assertEqual(connection.execute('SELECT state FROM simulation_effects').fetchone()[0],'LEGACY_UNVERIFIED')
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM response_executions').fetchone()[0],1)
        ops.apply_current_schema(output)
        self.assertEqual(before,ops.digest(snapshot/ops.FILES['incidents']))
        ops.verify_snapshot(snapshot)

    def test_upgrade_failure_preserves_snapshot_and_never_activates(self):
        snapshot=self.snapshot(); before={name:ops.digest(snapshot/name) for name in ops.FILES.values()}
        with patch.object(ops,'apply_current_schema',side_effect=sqlite3.OperationalError('private sensitive failure')):
            with self.assertRaisesRegex(ops.OperationsError,'RECOVERY_FAILED'): ops.recover(snapshot,self.output('failed'),upgrade=True)
        self.assertFalse(self.output('failed').exists())
        self.assertEqual(before,{name:ops.digest(snapshot/name) for name in ops.FILES.values()})
        self.assertFalse(list(Path(self.temp.name).glob('.recovery-partial-*')))


if __name__=='__main__': unittest.main(verbosity=2)
