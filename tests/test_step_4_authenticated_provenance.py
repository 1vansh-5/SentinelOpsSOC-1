
"""Step 4 positive authenticated provenance tests."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()

import copy
import secrets
import tempfile
from pathlib import Path

from app.evidence_signing import create_signed_evidence
from app.evidence_provenance import validate_evidence_provenance
from app.persistent_collector_registry import PersistentCollectorRegistry


def passed(name):
    print(f"{name}: PASSED")


def wrap(envelope):
    """Build an investigation containing authenticated evidence."""
    return {
        "investigation": {
            "trace": [{
                "tool": "authentication_logs",
                "result": {
                    "status": "completed",
                    "source": "authenticated_collector",
                    "signed_evidence": envelope,
                },
            }]
        }
    }


def run_tests():
    with tempfile.TemporaryDirectory() as directory:
        db_path = str(Path(directory) / "step4_auth.db")

        registry = PersistentCollectorRegistry(db_path)
        collector_id = "step4-auth-collector"
        incident_id = 101
        key_one = secrets.token_hex(32)
        key_two = secrets.token_hex(32)

        registry.register_collector(collector_id, key_one)
        passed("Collector registration")

        envelope = create_signed_evidence(
            incident_id,
            collector_id,
            {"event": "simulated_authentication_event"},
            key_one,
        )

        # Evidence must be accepted before it can be trusted.
        result = validate_evidence_provenance(
            wrap(envelope),
            registry,
            incident_id,
        )
        assert result["trusted"] is False
        passed("Unaccepted evidence rejection")

        acceptance = registry.verify_submission(
            envelope,
            incident_id,
        )
        assert acceptance["accepted"] is True, acceptance
        passed("Authenticated evidence acceptance")

        result = validate_evidence_provenance(
            wrap(envelope),
            registry,
            incident_id,
        )
        assert result["trusted"] is True, result
        assert result["status"] == "VERIFIED"
        passed("Positive authenticated provenance")

        # Read-only checks must not consume replay protection.
        again = validate_evidence_provenance(
            wrap(envelope),
            registry,
            incident_id,
        )
        assert again["trusted"] is True
        passed("Repeat read-only verification")

        # The original submission still cannot be ingested twice.
        replay = registry.verify_submission(
            envelope,
            incident_id,
        )
        assert replay["accepted"] is False
        passed("Replay protection preserved")

        tampered = copy.deepcopy(envelope)
        tampered["record"]["evidence"]["event"] = "tampered"

        result = validate_evidence_provenance(
            wrap(tampered),
            registry,
            incident_id,
        )
        assert result["trusted"] is False
        passed("Tampered evidence rejection")

        result = validate_evidence_provenance(
            wrap(envelope),
            registry,
            incident_id + 1,
        )
        assert result["trusted"] is False
        passed("Wrong incident rejection")

        result = validate_evidence_provenance(
            wrap(envelope),
        )
        assert result["trusted"] is False
        passed("Missing registry rejection")

        forged = wrap(envelope)
        forged["trusted"] = True
        forged["investigation"]["provenance"] = {
            "trusted": True
        }

        result = validate_evidence_provenance(forged)
        assert result["trusted"] is False
        passed("Forged trust metadata rejection")

        # Rotation invalidates the old signing key for
        # current authorization decisions.
        rotation = registry.rotate_collector_key(
            collector_id,
            key_one,
            key_two,
        )
        assert rotation["rotated"] is True

        result = validate_evidence_provenance(
            wrap(envelope),
            registry,
            incident_id,
        )
        assert result["trusted"] is False
        passed("Rotated key rejection")

        new_envelope = create_signed_evidence(
            incident_id,
            collector_id,
            {"event": "after_rotation"},
            key_two,
        )

        accepted = registry.verify_submission(
            new_envelope,
            incident_id,
        )
        assert accepted["accepted"] is True

        result = validate_evidence_provenance(
            wrap(new_envelope),
            registry,
            incident_id,
        )
        assert result["trusted"] is True
        passed("New signing key verification")

        revocation = registry.revoke_collector(collector_id)
        assert revocation["revoked"] is True

        result = validate_evidence_provenance(
            wrap(new_envelope),
            registry,
            incident_id,
        )
        assert result["trusted"] is False
        passed("Revoked collector rejection")

    passed("Temporary SQLite cleanup")

    print()
    print("=" * 55)
    print("STEP 4 AUTHENTICATED PROVENANCE TEST: PASSED")
    print("=" * 55)


if __name__ == "__main__":
    run_tests()
