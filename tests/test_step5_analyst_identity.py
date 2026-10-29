"""Standalone security regression for Step 5, Part 1."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()

import sqlite3
from contextlib import closing
import tempfile
from pathlib import Path

from app.analyst_identity import AnalystIdentityStore


def check(name, condition):
    assert condition, name
    print(f"{name}: PASSED")


def run():
    with tempfile.TemporaryDirectory() as temp:
        db = str(Path(temp) / "analysts.sqlite")
        store = AnalystIdentityStore(db)
        admin = store.create_analyst("admin_01", "admin")
        analyst = store.create_analyst("analyst_01", "analyst")
        viewer = store.create_analyst("viewer_01", "viewer")
        check("Role-based analyst creation", bool(admin["token"] and analyst["token"]))
        check("Viewer cannot decide", store.authorize("viewer_01", viewer["token"], "decide") is None)
        check("Analyst can decide", store.authorize("analyst_01", analyst["token"], "decide") is not None)
        check("Analyst cannot manage identities", store.authorize("analyst_01", analyst["token"], "manage_analysts") is None)
        check("Admin can manage identities", store.authorize("admin_01", admin["token"], "manage_analysts") is not None)
        check("Wrong credential rejected", store.authenticate("admin_01", "x" * 64) is None)
        check("Unknown permission rejected", store.authorize("admin_01", admin["token"], "unknown") is None)
        with closing(sqlite3.connect(db)) as conn:
            values = str(conn.execute("SELECT * FROM analysts").fetchall())
        check("Plaintext credentials not stored", all(x["token"] not in values for x in (admin, analyst, viewer)))
        new_token = store.rotate_token("analyst_01")
        check("Old credential invalidated on rotation", new_token is not None and store.authenticate("analyst_01", analyst["token"]) is None)
        check("New credential works", store.authenticate("analyst_01", new_token) is not None)
        check("Role downgrade immediate", store.change_role("analyst_01", "viewer") and store.authorize("analyst_01", new_token, "decide") is None)
        check("Revocation immediate", store.disable_analyst("admin_01") and store.authenticate("admin_01", admin["token"]) is None)
        restarted = AnalystIdentityStore(db)
        check("Revocation persists across restart", restarted.authenticate("admin_01", admin["token"]) is None)
        try:
            store.create_analyst("admin_01", "admin")
        except sqlite3.IntegrityError:
            duplicate_rejected = True
        else:
            duplicate_rejected = False
        check("Duplicate identity rejected", duplicate_rejected)
    print("Windows SQLite cleanup: PASSED")
    print("STEP 5 PART 1 ANALYST IDENTITY TEST: PASSED")


if __name__ == "__main__":
    run()
