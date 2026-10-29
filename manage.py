"""One entry point for the organized SentinelOps source tree."""
import argparse
import os
import runpy
import sys
from project_paths import ROOT,activate

COMMANDS={'checks':'run_step12_checks.py','demo':'run_step10_demo.py',
          'walkthrough':'run_step12_walkthrough.py','serve':'run_sentinelops.py',
          'ops':'opsctl.py','hygiene':'ops_hygiene.py','provision':'provision_analyst.py',
          'verify-live':'verify_gemini_live.py'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=[*COMMANDS,'test'])
    parser.add_argument('arguments',nargs=argparse.REMAINDER)
    options=parser.parse_args()
    activate();os.chdir(ROOT)
    if options.command=='test':
        if not options.arguments:parser.error('test requires the test filename')
        name=options.arguments.pop(0)
        if name!=os.path.basename(name) or not name.startswith('test_') or not name.endswith('.py'):
            parser.error('Choose a test_*.py filename from tests/')
        script=ROOT/'tests'/name
    else:script=ROOT/'scripts'/COMMANDS[options.command]
    sys.argv=[str(script),*options.arguments]
    runpy.run_path(str(script),run_name='__main__')


if __name__=='__main__':main()
