"""Run the dependency-free Node client contract suite without browser automation."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import os
from pathlib import Path
import shutil
import subprocess
import unittest


class Frontend(unittest.TestCase):
    def test_client_contracts(self):
        node=os.environ.get('STEP10_NODE') or shutil.which('node')
        self.assertTrue(node,'Node.js 20+ is required for the frontend gate. Install Node, or pass --node to run_step10_checks.py.')
        result=subprocess.run([str(node),'--test',str(Path(__file__).with_suffix('.cjs'))],
            cwd=ROOT,capture_output=True,text=True,encoding='utf-8',timeout=45)
        print(result.stdout)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__=='__main__':
    unittest.main(verbosity=2)
