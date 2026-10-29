"""Verify gate isolation, blocked egress, exit handling and bounded test execution."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import run_step9_checks as gate


class GateSafety(unittest.TestCase):
    def test_production_files_are_not_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'source'; source.mkdir()
            (source/'app').mkdir()
            (source/'app/main.py').write_text('pass')
            (source/'test_example.py').write_text('pass')
            (source/'.env').write_text('GEMINI_API_KEY=sentinel-test-secret')
            (source/'sentinelops.db').write_bytes(b'protected sentinel')
            gate.copy_source(source, root/'copy')
            self.assertTrue((root/'copy/app/main.py').is_file())
            self.assertFalse((root/'copy/.env').exists())
            self.assertFalse((root/'copy/sentinelops.db').exists())
            self.assertEqual((source/'sentinelops.db').read_bytes(), b'protected sentinel')

    def test_environment_does_not_forward_credentials_or_database_paths(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            'GEMINI_API_KEY':'sentinel-test-secret', 'SENTINELOPS_DB':'protected.sqlite',
            'GOOGLE_APPLICATION_CREDENTIALS':'protected.json', 'OTHER_API_KEY':'sentinel-test-secret'}):
            folder = Path(tmp); env = gate.child_environment(folder)
            self.assertEqual(env['GEMINI_API_KEY'], '')
            self.assertEqual(env['PYTHONOPTIMIZE'], '0')
            self.assertNotIn('GOOGLE_APPLICATION_CREDENTIALS', env)
            self.assertNotIn('OTHER_API_KEY', env)
            self.assertEqual(env['SENTINELOPS_DB'], str(folder/'incidents.sqlite'))

    def test_external_connections_dns_and_datagrams_are_blocked(self):
        with socket.socket() as connection:
            with self.assertRaises(PermissionError): connection.connect(('192.0.2.1',443))
            with self.assertRaises(PermissionError): connection.connect_ex(('192.0.2.1',443))
        with self.assertRaises(PermissionError): socket.getaddrinfo('example.com',443)
        with socket.socket(type=socket.SOCK_DGRAM) as datagram:
            with self.assertRaises(PermissionError): datagram.sendto(b'x',('192.0.2.1',53))

    def test_failed_child_does_not_pass_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            gate.copy_source(ROOT,folder)
            (folder/'intentional_failure.py').write_text('raise SystemExit(7)')
            result = gate.run_job(folder,'intentional_failure.py',False)
            self.assertFalse(result['passed']); self.assertEqual(result['returncode'],7)

    def test_hung_child_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            gate.copy_source(ROOT,folder)
            (folder/'intentional_timeout.py').write_text('import time; time.sleep(20)')
            result = gate.run_job(folder,'intentional_timeout.py',False,timeout=0.25)
            self.assertFalse(result['passed']); self.assertIsNone(result['returncode'])

    def test_sqlite_handles_close_before_windows_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp); path = folder/'cleanup.sqlite'
            connection = sqlite3.connect(path)
            try:
                with connection: connection.execute('CREATE TABLE cleanup_test (id INTEGER)')
            finally:
                connection.close()
            path.rename(folder/'renamed.sqlite')
            (folder/'renamed.sqlite').unlink()
            self.assertFalse(any(folder.iterdir()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
