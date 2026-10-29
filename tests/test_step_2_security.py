
"""Major Step 2: SentinelOps SOC 2.0 security regression tests.

Tests:
- Input structure and signature validation
- Incident and collector ID validation
- Evidence size and timestamp validation
- Expired and future-dated evidence rejection
- Valid evidence acceptance and replay protection
- Audit logging without exposing secrets or payloads

Uses a temporary SQLite database.
Simulation and development only.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()

import copy
import hashlib
import hmac
import secrets
import sqlite3
import tempfile

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.evidence_integrity import canonicalize_evidence
from app.evidence_signing import create_signed_evidence
from app.persistent_collector_registry import PersistentCollectorRegistry


# --------------------------------------------------
# Test configuration
# --------------------------------------------------

# Generate a fresh signing key for this test run.
# Never print or store the raw key in audit records.
KEY = secrets.token_hex(32)

COLLECTOR = "collector-01"
INCIDENT = 11


# --------------------------------------------------
# Test helpers
# --------------------------------------------------

def resign(record):
    """Create a valid HMAC signature for a modified test record."""

    signature = hmac.new(
        KEY.encode("utf-8"),
        canonicalize_evidence(record),
        hashlib.sha256,
    ).hexdigest()

    return {
        "record": record,
        "signature": signature,
        "algorithm": "HMAC-SHA256",
    }


def check(registry, name, submission, expected_reason):
    """Assert that an invalid submission is rejected correctly."""

    result = registry.verify_submission(
        submission,
        INCIDENT,
    )

    assert result["accepted"] is False, (
        f"{name}: unexpected acceptance: {result}"
    )

    assert result["reason"] == expected_reason, (
        f"{name}: expected {expected_reason}, got {result}"
    )

    print(f"{name}: PASSED ({expected_reason})")


# --------------------------------------------------
# Main security test
# --------------------------------------------------

def run_security_tests():
    """Execute the complete Step 2 security regression suite."""

    # TemporaryDirectory automatically removes the test files
    # after all SQLite connections have been closed.
    with tempfile.TemporaryDirectory() as directory:

        db_path = str(
            Path(directory) / "security_test.db"
        )

        # Initialize a fresh test registry.
        registry = PersistentCollectorRegistry(db_path)

        # Register one authorized simulated collector.
        registry.register_collector(
            COLLECTOR,
            KEY,
        )

        # Generate one correctly signed evidence submission.
        valid = create_signed_evidence(
            INCIDENT,
            COLLECTOR,
            {"event": "step_2_test"},
            KEY,
        )

        # ------------------------------------------
        # Invalid submission structure
        # ------------------------------------------

        check(
            registry,
            "None submission",
            None,
            "Invalid submission",
        )

        check(
            registry,
            "Integer submission",
            123,
            "Invalid submission",
        )

        check(
            registry,
            "Missing signature",
            {"record": {}},
            "Invalid signature",
        )

        # ------------------------------------------
        # Invalid record fields
        # ------------------------------------------

        invalid_record = copy.deepcopy(valid)
        invalid_record["record"]["incident_id"] = True

        check(
            registry,
            "Boolean incident ID",
            invalid_record,
            "Invalid record",
        )

        invalid_record = copy.deepcopy(valid)
        invalid_record["record"]["collector_id"] = "x" * 129

        check(
            registry,
            "Oversized collector ID",
            invalid_record,
            "Invalid record",
        )

        invalid_record = copy.deepcopy(valid)
        invalid_record["record"]["evidence"] = {}

        check(
            registry,
            "Empty evidence",
            invalid_record,
            "Invalid record",
        )

        invalid_record = copy.deepcopy(valid)
        invalid_record["record"]["evidence"] = {
            "data": "x" * 65536
        }

        check(
            registry,
            "Oversized evidence",
            invalid_record,
            "Invalid record",
        )

        # ------------------------------------------
        # Invalid timestamps
        # ------------------------------------------

        invalid_record = copy.deepcopy(valid)
        invalid_record["record"]["collected_at"] = "not-a-timestamp"

        check(
            registry,
            "Malformed timestamp",
            invalid_record,
            "Invalid record",
        )

        invalid_record = copy.deepcopy(valid)
        invalid_record["record"]["collected_at"] = (
            "2026-10-18T10:00:00"
        )

        check(
            registry,
            "Timezone missing",
            invalid_record,
            "Invalid record",
        )

        # ------------------------------------------
        # Expired evidence
        # ------------------------------------------

        expired = copy.deepcopy(valid["record"])

        expired["collected_at"] = (
            datetime.now(timezone.utc)
            - timedelta(minutes=20)
        ).isoformat()

        check(
            registry,
            "Expired evidence",
            resign(expired),
            "Evidence is too old",
        )

        # ------------------------------------------
        # Future-dated evidence
        # ------------------------------------------

        future = copy.deepcopy(valid["record"])

        future["collected_at"] = (
            datetime.now(timezone.utc)
            + timedelta(minutes=5)
        ).isoformat()

        check(
            registry,
            "Future-dated evidence",
            resign(future),
            "Future timestamp rejected",
        )

        # ------------------------------------------
        # Valid submission
        # ------------------------------------------

        accepted = registry.verify_submission(
            valid,
            INCIDENT,
        )

        assert accepted["accepted"] is True, accepted

        print("Valid submission: PASSED")

        # ------------------------------------------
        # Replay protection
        # ------------------------------------------

        check(
            registry,
            "Replay",
            valid,
            "Replay detected",
        )

        # ------------------------------------------
        # Audit and database verification
        # ------------------------------------------

        # IMPORTANT:
        # closing() actually closes the SQLite connection.
        #
        # A normal "with sqlite3.connect(...)" block only
        # manages transactions and may leave the file open.
        #
        # Windows requires the file handle to be released
        # before TemporaryDirectory can delete the database.

        with closing(sqlite3.connect(db_path)) as conn:

            audits = conn.execute(
                """
                SELECT
                    action,
                    reason,
                    signature_fingerprint
                FROM evidence_audit
                """
            ).fetchall()

            accepted_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM accepted_evidence
                """
            ).fetchone()[0]

        # The connection has been explicitly closed here.

        assert accepted_count == 1, (
            f"Expected one accepted record, got {accepted_count}"
        )

        # Eleven rejected submissions + one acceptance + one replay.
        assert len(audits) == 13, (
            f"Expected 13 audit records, got {len(audits)}"
        )

        print("Audit rejection count: PASSED")

        # Verify audit reasons do not contain the signing key
        # or raw evidence payloads.
        for action, reason, fingerprint in audits:

            assert KEY not in reason
            assert "step_2_test" not in reason
            assert "x" * 100 not in reason

            # Only hashed signature fingerprints are stored.
            if fingerprint is not None:
                assert len(fingerprint) == 64

        print("Audit secret/payload protection: PASSED")
        print(f"Accepted evidence count: {accepted_count}")

    # Reaching this line means TemporaryDirectory cleanup
    # completed without a Windows file-lock exception.
    print("Temporary SQLite cleanup: PASSED")
    print("MAJOR STEP 2 SECURITY TEST: PASSED")


# --------------------------------------------------
# Program entry point
# --------------------------------------------------

if __name__ == "__main__":
    run_security_tests()
