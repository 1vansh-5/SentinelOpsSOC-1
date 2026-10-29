
"""
SentinelOps SOC 2.0
Major Step 3: Collector Lifecycle and Migration Assurance

SIMULATION / DEVELOPMENT ONLY

Tests:
1. Collector registration
2. Duplicate registration protection
3. Signing-key validation
4. Key loading after restart
5. Incorrect key rejection
6. Successful key rotation
7. Previous key rejection
8. Historical key reuse protection
9. Incorrect old key rejection
10. Persistence across restart
11. Collector revocation
12. Revoked collector rejection
13. Revoked key loading prevention
14. Repeated revocation protection
15. Legacy key-history migration
16. Migration idempotency
17. Lifecycle audit records
18. Secret protection in audit records
19. SQLite cleanup on Windows
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()

import hashlib
import secrets
import sqlite3
import tempfile

from contextlib import closing
from pathlib import Path

from app.evidence_signing import create_signed_evidence
from app.persistent_collector_registry import PersistentCollectorRegistry


INCIDENT_ID = 11
COLLECTOR_ID = "step3-collector"


def make_key():
    """Generate a strong, temporary test key."""
    return secrets.token_hex(32)


def fingerprint(key):
    """Compute the fingerprint stored by the registry."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def signed_submission(collector_id, key, event):
    """Create a new signed, simulated evidence record."""
    return create_signed_evidence(
        INCIDENT_ID,
        collector_id,
        {"event": event},
        key,
    )


def passed(name):
    print(f"{name}: PASSED")


def expect_value_error(name, operation):
    """Check that an invalid operation raises ValueError."""
    try:
        operation()
    except ValueError:
        passed(name)
    else:
        raise AssertionError(
            f"{name}: expected ValueError"
        )


def read_database(db_path, query, parameters=()):
    """
    Read SQLite data and explicitly close the connection.

    Explicit closure prevents WinError 32 during temporary
    database cleanup on Windows.
    """
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(query, parameters).fetchall()


def run_tests():

    key_one = make_key()
    key_two = make_key()
    key_three = make_key()
    incorrect_key = make_key()

    # This database is isolated from the actual project.
    with tempfile.TemporaryDirectory() as directory:

        db_path = str(Path(directory) / "step3_test.db")

        registry = PersistentCollectorRegistry(db_path)

        # ---------------------------------------------
        # 1. Registration
        # ---------------------------------------------

        registry.register_collector(
            COLLECTOR_ID,
            key_one,
        )

        rows = read_database(
            db_path,
            """
            SELECT key_fingerprint, enabled
            FROM collectors
            WHERE collector_id = ?
            """,
            (COLLECTOR_ID,),
        )

        assert rows == [(fingerprint(key_one), 1)]
        passed("Collector registration")

        # ---------------------------------------------
        # 2. Duplicate registration
        # ---------------------------------------------

        try:
            registry.register_collector(
                COLLECTOR_ID,
                key_two,
            )
        except sqlite3.IntegrityError:
            passed("Duplicate registration rejection")
        else:
            raise AssertionError(
                "Duplicate registration was accepted"
            )

        # Verify duplicate registration did not replace
        # the existing collector key.
        rows = read_database(
            db_path,
            """
            SELECT key_fingerprint
            FROM collectors
            WHERE collector_id = ?
            """,
            (COLLECTOR_ID,),
        )

        assert rows[0][0] == fingerprint(key_one)
        passed("Original key preserved")

        # ---------------------------------------------
        # 3. Weak signing key rejection
        # ---------------------------------------------

        expect_value_error(
            "Weak signing key rejection",
            lambda: registry.register_collector(
                "weak-key-collector",
                "short",
            ),
        )

        # ---------------------------------------------
        # 4. Registry restart and key loading
        # ---------------------------------------------

        restarted = PersistentCollectorRegistry(db_path)

        expect_value_error(
            "Incorrect key loading rejection",
            lambda: restarted.load_collector_key(
                COLLECTOR_ID,
                incorrect_key,
            ),
        )

        restarted.load_collector_key(
            COLLECTOR_ID,
            key_one,
        )

        passed("Correct key loading after restart")

        # ---------------------------------------------
        # 5. Valid signed evidence
        # ---------------------------------------------

        initial_submission = signed_submission(
            COLLECTOR_ID,
            key_one,
            "before_rotation",
        )

        result = restarted.verify_submission(
            initial_submission,
            INCIDENT_ID,
        )

        assert result["accepted"] is True, result
        passed("Signed evidence before rotation")

        # ---------------------------------------------
        # 6. Rotate collector key
        # ---------------------------------------------

        result = restarted.rotate_collector_key(
            COLLECTOR_ID,
            key_one,
            key_two,
        )

        assert result["rotated"] is True, result
        passed("Collector key rotation")

        # ---------------------------------------------
        # 7. Previous key must not authorize evidence
        # ---------------------------------------------

        old_submission = signed_submission(
            COLLECTOR_ID,
            key_one,
            "old_key_after_rotation",
        )

        result = restarted.verify_submission(
            old_submission,
            INCIDENT_ID,
        )

        assert result["accepted"] is False, result
        passed("Previous key rejection")

        # ---------------------------------------------
        # 8. New key must work
        # ---------------------------------------------

        new_submission = signed_submission(
            COLLECTOR_ID,
            key_two,
            "after_rotation",
        )

        result = restarted.verify_submission(
            new_submission,
            INCIDENT_ID,
        )

        assert result["accepted"] is True, result
        passed("New key acceptance")

        # ---------------------------------------------
        # 9. Historical key reuse must be prohibited
        # ---------------------------------------------

        result = restarted.rotate_collector_key(
            COLLECTOR_ID,
            key_two,
            key_one,
        )

        assert result["rotated"] is False, result

        assert (
            result["reason"]
            == "Historical key reuse prohibited"
        ), result

        passed("Historical key reuse rejection")

        # ---------------------------------------------
        # 10. Incorrect old key cannot rotate
        # ---------------------------------------------

        result = restarted.rotate_collector_key(
            COLLECTOR_ID,
            incorrect_key,
            key_three,
        )

        assert result["rotated"] is False, result
        passed("Incorrect old key rotation rejection")

        # ---------------------------------------------
        # 11. Key history persists across restart
        # ---------------------------------------------

        history = read_database(
            db_path,
            """
            SELECT key_fingerprint
            FROM collector_key_history
            WHERE collector_id = ?
            """,
            (COLLECTOR_ID,),
        )

        recorded_fingerprints = {
            row[0] for row in history
        }

        assert recorded_fingerprints == {
            fingerprint(key_one),
            fingerprint(key_two),
        }

        passed("Persistent key history")

        another_restart = PersistentCollectorRegistry(db_path)

        expect_value_error(
            "Old key loading after restart",
            lambda: another_restart.load_collector_key(
                COLLECTOR_ID,
                key_one,
            ),
        )

        another_restart.load_collector_key(
            COLLECTOR_ID,
            key_two,
        )

        passed("Active key loading after restart")

        # ---------------------------------------------
        # 12. Revoke collector
        # ---------------------------------------------

        result = another_restart.revoke_collector(
            COLLECTOR_ID
        )

        assert result["revoked"] is True, result
        passed("Collector revocation")

        # ---------------------------------------------
        # 13. Revoked collector cannot submit evidence
        # ---------------------------------------------

        revoked_submission = signed_submission(
            COLLECTOR_ID,
            key_two,
            "after_revocation",
        )

        result = another_restart.verify_submission(
            revoked_submission,
            INCIDENT_ID,
        )

        assert result["accepted"] is False, result
        passed("Revoked collector evidence rejection")

        # ---------------------------------------------
        # 14. Revoked collector cannot load its key
        # ---------------------------------------------

        expect_value_error(
            "Revoked collector key loading rejection",
            lambda: another_restart.load_collector_key(
                COLLECTOR_ID,
                key_two,
            ),
        )

        # ---------------------------------------------
        # 15. Repeated revocation
        # ---------------------------------------------

        result = another_restart.revoke_collector(
            COLLECTOR_ID
        )

        assert result["revoked"] is False, result
        passed("Repeated revocation rejection")

        # ---------------------------------------------
        # 16. Revoked collector cannot rotate
        # ---------------------------------------------

        result = another_restart.rotate_collector_key(
            COLLECTOR_ID,
            key_two,
            key_three,
        )

        assert result["rotated"] is False, result
        passed("Revoked collector rotation rejection")

        # ---------------------------------------------
        # 17. Verify revocation persisted
        # ---------------------------------------------

        final_restart = PersistentCollectorRegistry(db_path)

        rows = read_database(
            db_path,
            """
            SELECT enabled
            FROM collectors
            WHERE collector_id = ?
            """,
            (COLLECTOR_ID,),
        )

        assert rows == [(0,)]
        passed("Revocation persistence")

        # ---------------------------------------------
        # 18. Simulate an older collector record
        # ---------------------------------------------

        legacy_id = "legacy-collector"
        legacy_key = make_key()

        # Simulate a legacy database entry with no
        # corresponding collector_key_history entry.
        with closing(sqlite3.connect(db_path)) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO collectors
                    (collector_id, key_fingerprint, enabled)
                    VALUES (?, ?, ?)
                    """,
                    (
                        legacy_id,
                        fingerprint(legacy_key),
                        0,
                    ),
                )

        passed("Legacy collector test setup")

        # ---------------------------------------------
        # 19. Migrate existing key fingerprints
        # ---------------------------------------------

        result = final_restart.migrate_existing_key_history()

        assert result["migrated"] is True, result
        assert result["fingerprints_added"] == 1, result

        passed("Legacy key history migration")

        # ---------------------------------------------
        # 20. Verify migrated fingerprint
        # ---------------------------------------------

        rows = read_database(
            db_path,
            """
            SELECT key_fingerprint
            FROM collector_key_history
            WHERE collector_id = ?
            """,
            (legacy_id,),
        )

        assert rows == [(fingerprint(legacy_key),)]
        passed("Migrated fingerprint verification")

        # Migration must not activate a disabled collector.
        rows = read_database(
            db_path,
            """
            SELECT enabled
            FROM collectors
            WHERE collector_id = ?
            """,
            (legacy_id,),
        )

        assert rows == [(0,)]
        passed("Migration preserves disabled status")

        # ---------------------------------------------
        # 21. Migration idempotency
        # ---------------------------------------------

        result = final_restart.migrate_existing_key_history()

        assert result["migrated"] is True, result
        assert result["fingerprints_added"] == 0, result

        passed("Repeated migration idempotency")

        # ---------------------------------------------
        # 22. Audit lifecycle events
        # ---------------------------------------------

        audits = read_database(
            db_path,
            """
            SELECT action, reason
            FROM evidence_audit
            """
        )

        actions = [action for action, reason in audits]

        assert actions.count("COLLECTOR_KEY_ROTATED") == 1
        assert actions.count("COLLECTOR_REVOKED") == 1
        assert actions.count("KEY_HISTORY_MIGRATED") == 2

        passed("Collector lifecycle audit records")

        # ---------------------------------------------
        # 23. Audit records must not contain raw keys
        # ---------------------------------------------

        audit_text = repr(audits)

        for key in (
            key_one,
            key_two,
            key_three,
            incorrect_key,
            legacy_key,
        ):
            assert key not in audit_text

        passed("Audit secret protection")

        # ---------------------------------------------
        # 24. Database consistency
        # ---------------------------------------------

        rows = read_database(
            db_path,
            """
            SELECT key_fingerprint, enabled
            FROM collectors
            WHERE collector_id = ?
            """,
            (COLLECTOR_ID,),
        )

        assert rows == [(fingerprint(key_two), 0)]

        passed("Final collector database consistency")

    # All SQLite connections must be closed before
    # TemporaryDirectory can remove its database.
    passed("Temporary SQLite cleanup")

    print()
    print("=" * 55)
    print("MAJOR STEP 3 COLLECTOR LIFECYCLE TEST: PASSED")
    print("=" * 55)


if __name__ == "__main__":
    run_tests()
