"""Ensure handoff links, documented endpoints and the final gate stay usable."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import ast
import json
from pathlib import Path
import re
import unittest

ROOT=ROOT


def registered_paths():
    result=set()
    for path in (ROOT/'app').glob('*.py'):
        tree=ast.parse(path.read_text(encoding='utf-8-sig'))
        prefix=''
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='APIRouter':
                for keyword in node.keywords:
                    if keyword.arg=='prefix': prefix=ast.literal_eval(keyword.value)
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    if isinstance(decorator,ast.Call) and isinstance(decorator.func,ast.Attribute) and decorator.func.attr in ('get','post') and decorator.args and isinstance(decorator.args[0],ast.Constant):
                        result.add(re.sub(r'\{[^}]+\}','{id}',prefix+decorator.args[0].value))
    return result


class HandoffContracts(unittest.TestCase):
    def test_documentation_links_and_architecture_sources_exist(self):
        docs=[ROOT/'README.md',ROOT/'docs/guides/README_STEP12.md',*(ROOT/'docs').glob('*.md')]
        self.assertGreaterEqual(len(docs),7)
        for path in docs:
            text=path.read_text(encoding='utf-8')
            for target in re.findall(r'\]\(([^)]+)\)',text):
                if '://' not in target: self.assertTrue((path.parent/target.split('#')[0]).is_file(),target)
        architecture=(ROOT/'docs/ARCHITECTURE.md').read_text()
        for name in re.findall(r'\b(?:(?:app|scripts)/)?[a-z_]+\.py\b',architecture):
            self.assertTrue((ROOT/name).is_file(),name)

    def test_documented_canonical_api_routes_exist(self):
        routes=registered_paths()
        expected=['/health','/dashboard','/webhook/alert','/simulate/attack','/alerts/{id}/investigate',
                  '/incidents/{id}/evidence/submit','/incidents/{id}/investigate-authenticated',
                  '/response-requests/for-incident/{id}','/response-requests/{id}/decision',
                  '/response-requests/{id}/execute','/response-requests/{id}/verify','/response-requests/{id}/rollback',
                  '/alerts','/incidents','/response-requests','/audit-history','/incidents/{id}/evidence',
                  '/simulated-blocks','/ai/status','/dashboard/api/identity','/dashboard/api/overview',
                  '/dashboard/api/incidents/{id}']
        for path in expected: self.assertIn(path,routes,path)

    def test_final_gate_preserves_every_previous_job(self):
        import run_step11_checks as previous
        import run_step12_checks as current
        for group,suites in previous.GROUPS.items(): self.assertEqual(suites,current.GROUPS[group])
        self.assertEqual(set(current.GROUPS)-set(previous.GROUPS),{'final_handoff'})
        self.assertEqual(current.GROUPS['final_handoff'],['test_step12_walkthrough.py','test_step12_contracts.py'])
        self.assertEqual(sum(map(len,current.GROUPS.values()))+3,30)

    def test_release_contains_the_actual_user_handoff(self):
        from ops_hygiene import release_paths
        names={name for name,path in release_paths(ROOT)}
        for name in ['README.md','docs/guides/README_STEP12.md','scripts/run_step12_walkthrough.py','scripts/run_step12_checks.py',
                     'tests/test_step12_walkthrough.py','tests/test_step12_contracts.py',
                     'docs/THREAT_MODEL.md','docs/DEMO_SCRIPT.md','docs/FINAL_VALIDATION.md',
                     'docs/PRESENTATION.md','docs/ARCHITECTURE.md']:
            self.assertIn(name,names)
        self.assertNotIn('.env',names)
        self.assertFalse(any(Path(name).suffix in ('.sqlite','.db','.mp4','.pptx') for name in names))


if __name__=='__main__': unittest.main(verbosity=2)
