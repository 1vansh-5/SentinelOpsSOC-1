"""Shared repository paths for launchers, tests and disposable source copies."""
import os
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parent


def activate():
    paths=[str(ROOT),str(ROOT/'scripts'),str(ROOT/'tests')]
    for value in reversed(paths):
        if value not in sys.path: sys.path.insert(0,value)
    inherited=os.environ.get('PYTHONPATH','').split(os.pathsep)
    os.environ['PYTHONPATH']=os.pathsep.join(dict.fromkeys(paths+[p for p in inherited if p]))


def test_path(name):
    path=Path(name)
    return str(path if path.exists() else ROOT/'tests'/path)


def copy_public_source(source,target):
    source=Path(source);target=Path(target);target.mkdir(parents=True,exist_ok=True)
    if (source/'release-files.json').is_file():
        from ops_hygiene import release_paths
        items=release_paths(source)
    else:
        # Keep the original gate's minimal-source isolation tests meaningful.
        items=[(path.relative_to(source).as_posix(),path)
               for path in source.rglob('*.py') if '__pycache__' not in path.parts]
    for name,path in items:
        destination=target/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(path,destination)
    (target/'sitecustomize.py').write_text(
        'from project_paths import activate\nactivate()\nfrom step9_offline_guard import install\ninstall()\n',encoding='utf-8')
