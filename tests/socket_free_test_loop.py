"""Optional offline ASGI test loop for restricted Windows runtimes.

No sockets are opened. A short selector poll replaces asyncio's wakeup socket;
HTTPX still exercises the real ASGI app, middleware, validation and lifespan.
Only used by run_step6_checks.py --socket-free-http, never by the API server.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import asyncio
import selectors
import threading


class PollSelector(selectors.SelectSelector):
    def select(self, timeout=None):
        interval = 0.01 if timeout is None else min(timeout, 0.01)
        if not self.get_map():
            threading.Event().wait(interval)
            return []
        return super().select(interval)


class OfflineLoop(asyncio.SelectorEventLoop):
    def __init__(self):
        super().__init__(PollSelector())

    def _make_self_pipe(self):
        self._ssock = self._csock = None

    def _close_self_pipe(self):
        pass

    def _write_to_self(self):
        pass


def enable():
    from fastapi.testclient import TestClient
    original = TestClient.__init__

    def initialize(self, *args, **kwargs):
        options = dict(kwargs.pop('backend_options', None) or {})
        options['loop_factory'] = OfflineLoop
        return original(self, *args, backend_options=options, **kwargs)

    TestClient.__init__ = initialize
