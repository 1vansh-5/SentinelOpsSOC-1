"""Secret detection without printing secrets; clean source exports and launcher checks."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import ops_hygiene as hygiene
import run_sentinelops as launcher


class Hygiene(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        # Copy exactly public files, never environment/runtime/DB material.
        source=ROOT
        for name,path in hygiene.release_paths(source):
            destination=self.root/name; destination.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,destination)
    def tearDown(self): self.tmp.cleanup()

    def test_current_syntax_templates_and_fixed_dependency_set(self):
        result=hygiene.check(self.root,os.environ.get('STEP10_NODE') or shutil.which('node'))
        self.assertTrue(result['passed'],json.dumps(result['findings']))
        self.assertEqual(result['javascript_syntax'],'CHECKED')
        example=(self.root/'.env.example').read_text()
        self.assertNotIn('AIza',example)

    def test_known_credential_detection_never_echoes_the_value(self):
        secret='AIza'+'Z'*35
        (self.root/'leaked.py').write_text('API_KEY = '+repr(secret))
        result=hygiene.check(self.root)
        self.assertFalse(result['passed']); self.assertNotIn(secret,json.dumps(result))
        self.assertIn('GOOGLE_API_KEY',[item['rule'] for item in result['findings']])

    def test_private_key_and_invalid_python_are_rejected(self):
        private='-----BEGIN '+'PRIVATE KEY-----'
        (self.root/'broken.py').write_text('value='+repr(private)+'\nif (')
        result=hygiene.check(self.root)
        self.assertFalse(result['passed'])
        rules={item['rule'] for item in result['findings']}
        self.assertTrue({'PRIVATE_KEY','PYTHON_SYNTAX'}.issubset(rules))

    def test_example_credentials_and_release_path_escape_are_rejected(self):
        with (self.root/'.env.example').open('a') as stream: stream.write('\nGEMINI_API_KEY=placeholder-is-not-blank\n')
        self.assertFalse(hygiene.check(self.root)['passed'])
        (self.root/'release-files.json').write_text(json.dumps(['../outside.py']))
        with self.assertRaises(ValueError): hygiene.release_paths(self.root)

    def test_clean_export_excludes_runtime_files_and_existing_output(self):
        (self.root/'.env').write_text('GEMINI_API_KEY=local-only-not-exported')
        (self.root/'sentinelops.db').write_bytes(b'private database')
        output=self.root/'clean.zip'; result=hygiene.export(self.root,output)
        self.assertEqual(result['status'],'SOURCE_ARCHIVE_VERIFIED')
        with zipfile.ZipFile(output) as archive:
            self.assertNotIn('.env',archive.namelist()); self.assertNotIn('sentinelops.db',archive.namelist())
            manifest=json.loads(archive.read('RELEASE_MANIFEST.json'))
            self.assertEqual(len(manifest['files']),result['files'])
            self.assertIn('scripts/run_step10_demo.py',manifest['files'])
        with self.assertRaises(ValueError): hygiene.export(self.root,output)

    def test_launcher_check_has_no_database_side_effects_and_env_precedence(self):
        env_file=self.root/'local.env'
        env_file.write_text('GEMINI_API_KEY=placeholder-from-file\nSENTINELOPS_DB=first.sqlite\nUNRELATED_SECRET=do-not-load\n')
        keys={k:v for k,v in os.environ.items() if not k.startswith(('SENTINELOPS_','GEMINI_'))}
        keys['GEMINI_API_KEY']=''
        with patch.dict(os.environ,keys,clear=True),patch.object(launcher,'ROOT',self.root):
            result=launcher.validate(env_file)
            self.assertEqual(os.environ['GEMINI_API_KEY'],'')
            self.assertNotIn('UNRELATED_SECRET',os.environ)
            self.assertEqual(result['status'],'CONFIGURATION_VALID')
            self.assertFalse((self.root/'first.sqlite').exists())
            os.environ['SENTINELOPS_ANALYST_DB']=os.environ['SENTINELOPS_DB']
            with self.assertRaisesRegex(ValueError,'DISTINCT_DATABASE_PATHS'): launcher.validate()


if __name__=='__main__': unittest.main(verbosity=2)
