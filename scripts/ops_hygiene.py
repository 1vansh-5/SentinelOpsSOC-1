"""Syntax/credential hygiene and an allowlisted clean-source ZIP exporter.

Findings contain file/line/rule only, never the matching text or secret value.
This is a focused source gate, not a credential-validity or Git-history scanner.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import zipfile

KNOWN=[('GOOGLE_API_KEY',re.compile(r'AIza[0-9A-Za-z_\-]{35}')),
       ('GITHUB_TOKEN',re.compile(r'(?:gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{30,})')),
       ('AWS_ACCESS_KEY',re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
       ('PRIVATE_KEY',re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'))]
ASSIGNMENT=re.compile(r'''(?i)(?:api[_-]?key|collector[_-]?key|signing[_-]?key|password|token)["']?\s*[:=]\s*["']([^"'\r\n]{24,})["']''')
SECRETS={'SENTINELOPS_API_KEY','SENTINELOPS_COLLECTOR_KEY','GEMINI_API_KEY'}


def entropy(value):
    return -sum((value.count(c)/len(value))*math.log2(value.count(c)/len(value)) for c in set(value))


def findings_for(text,name):
    findings=[]
    for number,line in enumerate(text.splitlines(),1):
        for rule,pattern in KNOWN:
            if pattern.search(line): findings.append({'file':name,'line':number,'rule':rule})
        # Generic fixture strings are permitted in tests; recognizable provider
        # tokens/private keys above are still rejected there.
        if not (Path(name).name.startswith('test_') or Path(name).name=='step8_test_workers.py'):
            for match in ASSIGNMENT.finditer(line):
                value=match.group(1)
                if entropy(value)>=3.8 and not any(word in value.lower() for word in ('example','placeholder','fixture','your_')):
                    findings.append({'file':name,'line':number,'rule':'LIKELY_EMBEDDED_CREDENTIAL'})
    return findings


def release_paths(root):
    root=Path(root).resolve()
    data=json.loads((root/'release-files.json').read_text(encoding='utf-8'))
    if not isinstance(data,list) or len(data)!=len(set(data)) or len(data)>300:
        raise ValueError('RELEASE_MANIFEST_INVALID')
    paths=[]
    for name in data:
        path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
            raise ValueError('RELEASE_PATH_INVALID')
        if path.name.startswith('.env') and name!='.env.example': raise ValueError('RELEASE_PATH_INVALID')
        if any(part.startswith(('.venv','.git','.step')) or part in ('work','backups','recovery','node_modules','__pycache__') for part in path.parts):
            if name!='.gitignore': raise ValueError('RELEASE_PATH_INVALID')
        if path.suffix.lower() in ('.db','.sqlite','.sqlite3','.pem','.key','.pyc','.pfx','.p12'): raise ValueError('RELEASE_PATH_INVALID')
        source=root/name
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(root): raise ValueError('RELEASE_FILE_UNAVAILABLE')
        paths.append((name,source))
    return paths


def check(root,node=None):
    root=Path(root).resolve(); problems=[]
    try: paths=release_paths(root)
    except Exception:
        return {'passed':False,'findings':[{'file':'release-files.json','line':0,'rule':'RELEASE_MANIFEST_INVALID'}]}
    scan=dict(paths)
    for pattern in ('*.py','*.cjs'):
        for path in root.glob(pattern): scan[path.name]=path
    for path in (root/'app').rglob('*.py'):
        if '__pycache__' not in path.parts and not any(word in path.name for word in ('backup','before_race','race_fix_attempt')):
            scan[path.relative_to(root).as_posix()]=path
    for name,path in scan.items():
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root): raise ValueError('PATH')
            source=path.read_text(encoding='utf-8-sig')
            problems.extend(findings_for(source,name))
            if path.suffix=='.py':
                try: ast.parse(source,filename=name)
                except SyntaxError as exc: problems.append({'file':name,'line':exc.lineno or 0,'rule':'PYTHON_SYNTAX'})
            if path.suffix in ('.js','.cjs') and node:
                result=subprocess.run([str(node),'--check',str(path)],capture_output=True,timeout=10)
                if result.returncode: problems.append({'file':name,'line':0,'rule':'JAVASCRIPT_SYNTAX'})
        except Exception: problems.append({'file':name,'line':0,'rule':'SOURCE_UNAVAILABLE'})
    for number,line in enumerate((root/'.env.example').read_text().splitlines(),1):
        name,separator,value=line.partition('=')
        if separator and name.strip() in SECRETS and value.strip():
            problems.append({'file':'.env.example','line':number,'rule':'NONEMPTY_EXAMPLE_CREDENTIAL'})
    if (root/'requirements.txt').read_text().strip().splitlines()[-1]!='-r requirements-step9-lock.txt':
        problems.append({'file':'requirements.txt','line':0,'rule':'UNPINNED_DEPENDENCIES'})
    for number,line in enumerate((root/'requirements-step9-lock.txt').read_text().splitlines(),1):
        if line.strip() and not line.startswith('#') and not re.fullmatch(r'[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+',line):
            problems.append({'file':'requirements-step9-lock.txt','line':number,'rule':'UNPINNED_DEPENDENCIES'})
    return {'passed':not problems,'checked_files':len(scan),'findings':problems,
            'javascript_syntax':'CHECKED' if node else 'NOT_RUN', 'git_history':'NOT_SCANNED'}


def export(root,output):
    root=Path(root).resolve(); output=Path(output).resolve()
    if output.exists(): raise ValueError('DESTINATION_ALREADY_EXISTS')
    result=check(root)
    if not result['passed']: raise ValueError('SOURCE_GATE_FAILED')
    paths=release_paths(root)
    descriptor,temp=tempfile.mkstemp(prefix='.source-partial-',suffix='.zip',dir=output.parent)
    os.close(descriptor); temporary=Path(temp)
    try:
        hashes={}
        with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,path in paths:
                data=path.read_bytes(); hashes[name]=hashlib.sha256(data).hexdigest()
                archive.writestr(name,data)
            archive.writestr('RELEASE_MANIFEST.json',json.dumps({'format':1,'mode':'SIMULATION_ONLY','files':hashes},indent=2))
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None: raise ValueError('SOURCE_ARCHIVE_INVALID')
            for name,expected in hashes.items():
                if hashlib.sha256(archive.read(name)).hexdigest()!=expected: raise ValueError('SOURCE_ARCHIVE_INVALID')
        temporary.rename(output)
        return {'status':'SOURCE_ARCHIVE_VERIFIED','files':len(hashes),'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}
    finally:
        if temporary.exists(): temporary.unlink()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('check','export'))
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--node')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        if args.command=='check':
            result=check(args.root,args.node); print(json.dumps(result)); return 0 if result['passed'] else 1
        if not args.output: parser.error('export requires --output with a new ZIP path')
        print(json.dumps(export(args.root,args.output))); return 0
    except Exception:
        print(json.dumps({'passed':False,'reason':'HYGIENE_OR_EXPORT_REFUSED'})); return 1


if __name__=='__main__':
    raise SystemExit(main())
