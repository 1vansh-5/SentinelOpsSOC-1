"""Offline child-process fixtures. No provider connections or production effects."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import time


def slow_worker(connection):
    try:
        time.sleep(5)
        connection.send({'code':'OK','text':'{"status":"OK"}'})
    finally:
        connection.close()


def successful_worker(connection):
    try:
        connection.send({'code':'OK','text':'{"status":"OK"}'})
    finally:
        connection.close()
