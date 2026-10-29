"""A source-only export can bootstrap the isolated demo with fixed dependencies."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
import ops_hygiene


class CleanSetup(unittest.TestCase):
    def test_exported_checkout_bootstraps_without_embedded_env_or_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=root/'source.zip'
            result=ops_hygiene.export(ROOT,archive)
            checkout=root/'checkout'; checkout.mkdir()
            with zipfile.ZipFile(archive) as source:
                source.extractall(checkout)
            self.assertFalse((checkout/'.env').exists())
            self.assertFalse(list(checkout.rglob('*.sqlite')))
            self.assertFalse(list(checkout.rglob('*.db')))
            env=dict(os.environ)
            env['PYTHONPATH']=str(checkout)
            # Preserve offline network guard in all Python subprocesses.
            (checkout/'sitecustomize.py').write_text('from project_paths import activate\nactivate()\nfrom step9_offline_guard import install\ninstall()\n')
            hygiene=subprocess.run([sys.executable,'scripts/ops_hygiene.py','check','--node',env['STEP10_NODE']],
                cwd=checkout,env=env,capture_output=True,text=True,encoding='utf-8',timeout=45)
            self.assertEqual(hygiene.returncode,0,hygiene.stdout+hygiene.stderr)
            demo=subprocess.run([sys.executable,'tests/test_step10_demo.py'],cwd=checkout,env=env,
                capture_output=True,text=True,encoding='utf-8',timeout=60)
            self.assertEqual(demo.returncode,0,demo.stdout+demo.stderr)
            print('Clean source-only checkout: syntax/secret gate and isolated HTTP demo bootstrap PASSED.')


if __name__=='__main__': unittest.main(verbosity=2)
