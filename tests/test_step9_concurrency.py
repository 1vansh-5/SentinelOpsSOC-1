"""Barrier-started races: ordering may vary, committed effects must not."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import sqlite3
import threading
import unittest
import test_step7_lifecycle as baseline
import test_step6_integrated as execution_baseline
from app.persistent_collector_registry import PersistentCollectorRegistry


class Races(unittest.TestCase):
    setUp = baseline.Lifecycle.setUp
    tearDown = baseline.Lifecycle.tearDown
    sql = baseline.Lifecycle.sql
    proposal = baseline.Lifecycle.proposal
    approve = baseline.Lifecycle.approve
    route = baseline.Lifecycle.route
    execute = baseline.Lifecycle.execute
    rollback = baseline.Lifecycle.rollback
    # Repeat the original lock-ordering assertion without relaxing or rewriting it.
    test_revocation_respects_execution_reservation = execution_baseline.Integrated.test_revocation_waits_for_execution_reservation

    def race(self, operation):
        barrier = threading.Barrier(8, timeout=10)
        def worker(index):
            barrier.wait()
            return operation(index)
        with ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(worker, range(8)))

    def test_same_execution_key_exactly_once(self):
        self.approve()
        results = self.race(lambda _: self.execute())
        self.assertTrue(all(r['status'] == 'SIMULATED_EXECUTED' for r in results), results)
        self.assertEqual(sum(not r['replayed'] for r in results), 1)
        for table in ('response_executions', 'simulated_blocks', 'simulation_effects'):
            self.assertEqual(len(self.sql('SELECT * FROM '+table)), 1)
        self.assertEqual(len(self.sql("SELECT * FROM response_audit WHERE action='SIMULATED_EXECUTED'")), 1)

    def test_different_execution_keys_have_one_winner(self):
        self.approve()
        results = self.race(lambda i: self.execute(f'concurrent-key-{i:04}'))
        self.assertEqual(sum(r['status'] == 'SIMULATED_EXECUTED' for r in results), 1, results)
        self.assertEqual(sum(r['status'] == 'DENIED' for r in results), 7, results)
        self.assertEqual(len(self.sql('SELECT * FROM response_executions')), 1)
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')), 1)
        self.assertEqual(len(self.sql("SELECT * FROM response_audit WHERE action='SIMULATED_EXECUTED'")), 1)

    def test_rollback_retries_cannot_recreate_effect(self):
        self.approve(); self.execute()
        results = self.race(lambda _: self.rollback())
        self.assertTrue(all(r['status'] == 'SIMULATED_ROLLED_BACK' for r in results), results)
        self.assertEqual(sum(not r['replayed'] for r in results), 1)
        self.assertEqual(len(self.sql('SELECT * FROM response_rollbacks')), 1)
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')), 0)
        self.assertEqual(len(self.sql("SELECT * FROM response_audit WHERE action='SIMULATED_ROLLED_BACK'")), 1)
        self.assertTrue(self.execute()['replayed'])
        self.assertEqual(len(self.sql('SELECT * FROM simulated_blocks')), 0)

    def test_collector_key_rotation_has_one_persistent_winner(self):
        stores = [PersistentCollectorRegistry(self.registry.database_path) for _ in range(8)]
        keys = [format(i+2, '064x') for i in range(8)]
        results = self.race(lambda i: stores[i].rotate_collector_key('collector_01',self.key,keys[i]))
        winners = [i for i, result in enumerate(results) if result.get('rotated') is True]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(sum(r.get('rotated') is False for r in results), 7, results)
        with closing(sqlite3.connect(self.registry.database_path)) as connection:
            active = connection.execute('SELECT key_fingerprint FROM collectors WHERE collector_id=?',('collector_01',)).fetchone()[0]
            history = connection.execute('SELECT COUNT(*) FROM collector_key_history').fetchone()[0]
            audits = connection.execute("SELECT COUNT(*) FROM evidence_audit WHERE action='COLLECTOR_KEY_ROTATED'").fetchone()[0]
        self.assertEqual(active, hashlib.sha256(keys[winners[0]].encode()).hexdigest())
        self.assertEqual(history, 2)
        self.assertEqual(audits, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
