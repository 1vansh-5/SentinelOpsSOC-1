"""
SentinelOps SOC 2.0
Persistent Collector Registry

SIMULATION / DEVELOPMENT ONLY

Features:
- Collector registration
- Collector key fingerprint verification
- Signed evidence verification
- Evidence freshness validation
- Persistent replay protection
- Automatic evidence auditing
- Atomic evidence acceptance and audit logging

This module does not authorize firewall actions.
"""

import hashlib
import hmac
import sqlite3

from contextlib import closing

from .evidence_signing import verify_signed_evidence
from .evidence_freshness import validate_evidence_freshness
from .evidence_record_validation import validate_evidence_record


class PersistentCollectorRegistry:

    def __init__(self, database_path: str):
        self.database_path = database_path

        # Development-only in-memory signing keys.
        self._keys = {}

        with closing(self._connect()) as conn:
            with conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS collectors (
                        collector_id TEXT PRIMARY KEY,
                        key_fingerprint TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1
                    );

                    CREATE TABLE IF NOT EXISTS accepted_evidence (
                        signature TEXT PRIMARY KEY,
                        incident_id INTEGER NOT NULL,
                        collector_id TEXT NOT NULL,
                        accepted_at TEXT NOT NULL
                            DEFAULT (datetime('now'))
                    );

                    CREATE TABLE IF NOT EXISTS evidence_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id INTEGER,
                        collector_id TEXT,
                        action TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        signature_fingerprint TEXT,
                        created_at TEXT NOT NULL
                            DEFAULT (datetime('now'))
                    );
                    CREATE TABLE IF NOT EXISTS collector_key_history (
    collector_id TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (collector_id, key_fingerprint),
    FOREIGN KEY (collector_id)
        REFERENCES collectors(collector_id)
);
                    """
                )

    # -----------------------------------------
    # Database connection
    # -----------------------------------------

    def _connect(self):
        return sqlite3.connect(
            self.database_path,
            timeout=10,
        )

    # -----------------------------------------
    # Collector registration
    # -----------------------------------------

    def migrate_existing_key_history(self) -> dict:
        """
        Backfill current collector key fingerprints.

        Does not activate collectors, change keys,
        or recover historical keys that were never stored.
        """

        with closing(self._connect()) as conn:
            with conn:
                missing_before = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM collectors AS c
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM collector_key_history AS h
                        WHERE h.collector_id = c.collector_id
                          AND h.key_fingerprint = c.key_fingerprint
                    )
                    """
                ).fetchone()[0]

                conn.execute(
                    """
                    INSERT OR IGNORE INTO collector_key_history
                    (collector_id, key_fingerprint)
                    SELECT collector_id, key_fingerprint
                    FROM collectors
                    """
                )

                conn.execute(
                    """
                    INSERT INTO evidence_audit
                    (
                        incident_id,
                        collector_id,
                        action,
                        reason
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        None,
                        None,
                        "KEY_HISTORY_MIGRATED",
                        "Existing collector fingerprints backfilled",
                    ),
                )

        return {
            "migrated": True,
            "fingerprints_added": missing_before,
        }

    def register_collector(
        self,
        collector_id: str,
        signing_key: str,
    ):
        if (
            not isinstance(collector_id, str)
            or not collector_id.strip()
        ):
            raise ValueError("Collector ID is required")

        if (
            not isinstance(signing_key, str)
            or len(signing_key) < 32
        ):
            raise ValueError("Strong signing key is required")

        fingerprint = hashlib.sha256(
            signing_key.encode("utf-8")
        ).hexdigest()


        with closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO collectors
                    (collector_id, key_fingerprint, enabled)
                    VALUES (?, ?, 1)
                    """,
                    (collector_id, fingerprint),
                )

                conn.execute(
                    """
                    INSERT INTO collector_key_history
                    (collector_id, key_fingerprint)
                    VALUES (?, ?)
                    """,
                    (collector_id, fingerprint),
                )

        self._keys[collector_id] = signing_key


    # -----------------------------------------
    # Load existing collector key
    # -----------------------------------------

    def load_collector_key(
        self,
        collector_id: str,
        signing_key: str,
    ):
        if not isinstance(signing_key, str):
            raise ValueError("Invalid signing key")

        fingerprint = hashlib.sha256(
            signing_key.encode("utf-8")
        ).hexdigest()

        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT key_fingerprint
                FROM collectors
                WHERE collector_id = ?
                  AND enabled = 1
                """,
                (collector_id,),
            ).fetchone()

        if (
            row is None
            or not hmac.compare_digest(
                row[0],
                fingerprint,
            )
        ):
            raise ValueError(
                "Collector key verification failed"
            )

        self._keys[collector_id] = signing_key

    # -----------------------------------------
    # Persistent audit logging
    # -----------------------------------------

    def record_audit(
        self,
        incident_id: int | None,
        collector_id: str | None,
        action: str,
        reason: str,
        signature: str | None = None,
    ):
        fingerprint = None

        if isinstance(signature, str):
            fingerprint = hashlib.sha256(
                signature.encode("utf-8")
            ).hexdigest()

        with closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO evidence_audit
                    (
                        incident_id,
                        collector_id,
                        action,
                        reason,
                        signature_fingerprint
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        collector_id,
                        action,
                        reason,
                        fingerprint,
                    ),
                )

    # -----------------------------------------
    # Automatic rejection auditing
    # -----------------------------------------

    def _reject_submission(
        self,
        reason: str,
        incident_id: int | None = None,
        collector_id: str | None = None,
        signature: str | None = None,
    ) -> dict:

        self.record_audit(
            incident_id=incident_id,
            collector_id=collector_id,
            action="SUBMISSION_REJECTED",
            reason=reason,
            signature=signature,
        )

        return {
            "accepted": False,
            "reason": reason,
        }

    # -----------------------------------------
    # Verify signed evidence submission
    # -----------------------------------------

    def rotate_collector_key(
        self,
        collector_id: str,
        old_key: str,
        new_key: str,
    ) -> dict:
        """Rotate an active collector key and audit the change."""

        if not isinstance(collector_id, str) or not collector_id.strip():
            raise ValueError("Valid collector ID required")

        if not isinstance(old_key, str):
            raise ValueError("Invalid old key")

        if not isinstance(new_key, str) or len(new_key) < 32:
            raise ValueError("Strong new key required")

        old_fingerprint = hashlib.sha256(
            old_key.encode("utf-8")
        ).hexdigest()

        new_fingerprint = hashlib.sha256(
            new_key.encode("utf-8")
        ).hexdigest()

        if hmac.compare_digest(old_fingerprint, new_fingerprint):
            raise ValueError("New key must differ from old key")

        # Verify the current key and update it atomically.

        with closing(self._connect()) as conn:
            with conn:
                # Prevent historical key reuse.
                existing_key = conn.execute(
                    """
                    SELECT 1
                    FROM collector_key_history
                    WHERE collector_id = ?
                      AND key_fingerprint = ?
                    """,
                    (collector_id, new_fingerprint),
                ).fetchone()

                if existing_key is not None:
                    return {
                        "rotated": False,
                        "reason": "Historical key reuse prohibited",
                    }

                # Rotate only if collector is active
                # and the supplied old key matches.
                cursor = conn.execute(
                    """
                    UPDATE collectors
                    SET key_fingerprint = ?
                    WHERE collector_id = ?
                      AND enabled = 1
                      AND key_fingerprint = ?
                    """,
                    (
                        new_fingerprint,
                        collector_id,
                        old_fingerprint,
                    ),
                )

                if cursor.rowcount != 1:
                    return {
                        "rotated": False,
                        "reason": "Collector disabled or old key invalid",
                    }

                # Record the new key fingerprint.
                conn.execute(
                    """
                    INSERT INTO collector_key_history
                    (collector_id, key_fingerprint)
                    VALUES (?, ?)
                    """,
                    (collector_id, new_fingerprint),
                )

                # Audit rotation atomically.
                conn.execute(
                    """
                    INSERT INTO evidence_audit
                    (
                        incident_id,
                        collector_id,
                        action,
                        reason
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        None,
                        collector_id,
                        "COLLECTOR_KEY_ROTATED",
                        "Collector signing key rotated",
                    ),
                )

        # Activate the new key only after commit.
        self._keys[collector_id] = new_key

        return {
            "rotated": True,
            "collector_id": collector_id,
        }


    def revoke_collector(self, collector_id: str) -> dict:
        """Disable a registered collector and audit the change."""

        if not isinstance(collector_id, str) or not collector_id.strip():
            raise ValueError("Valid collector ID required")

        with closing(self._connect()) as conn:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE collectors
                    SET enabled = 0
                    WHERE collector_id = ?
                      AND enabled = 1
                    """,
                    (collector_id,),
                )

                if cursor.rowcount != 1:
                    return {
                        "revoked": False,
                        "reason": "Collector not found or already disabled",
                    }

                conn.execute(
                    """
                    INSERT INTO evidence_audit
                    (
                        incident_id,
                        collector_id,
                        action,
                        reason
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        None,
                        collector_id,
                        "COLLECTOR_REVOKED",
                        "Collector disabled",
                    ),
                )

        # Remove the signing key from active memory.
        self._keys.pop(collector_id, None)

        return {
            "revoked": True,
            "collector_id": collector_id,
        }

    def verify_submission(
        self,
        signed_evidence: dict,
        expected_incident_id: int,
    ) -> dict:
        # Validate structure before any database write transaction.
        if not isinstance(signed_evidence, dict):
            return self._reject_submission(
                reason="Invalid submission",
                incident_id=expected_incident_id,
            )



        # Get the signature from the submitted evidence.
        signature = signed_evidence.get("signature")

        # HMAC-SHA256 produces a 64-character hexadecimal signature.
        # Check the format before cryptographic verification.
        #
        # isinstance() ensures the value is a string.
        # len() ensures it contains exactly 64 characters.
        # any() detects characters outside lowercase hexadecimal.
        if (
            not isinstance(signature, str)
            or len(signature) != 64
            or any(
                character not in "0123456789abcdef"
                for character in signature
            )
        ):
            # Reject malformed signatures safely.
            return self._reject_submission(
                reason="Invalid signature",
                incident_id=expected_incident_id,
            )


        record = signed_evidence.get("record")
        if not isinstance(record, dict):
            return self._reject_submission(
                reason="Invalid record",
                incident_id=expected_incident_id,
                signature=signature,
            )
        # Reject malformed, missing, or oversized evidence records.
        # This check occurs before key lookup and HMAC verification.
        if not validate_evidence_record(record):
            return self._reject_submission(
                reason="Invalid record",
                incident_id=expected_incident_id,
                signature=signature,
            )
        collector_id = record.get("collector_id")
        if not isinstance(collector_id, str) or not collector_id.strip():
            return self._reject_submission(
                reason="Invalid collector",
                incident_id=expected_incident_id,
                signature=signature,
            )

        key = self._keys.get(collector_id)
        if key is None:
            return self._reject_submission(
                reason="Collector key not loaded",
                incident_id=expected_incident_id,
                collector_id=collector_id,
                signature=signature,
            )

        # Cryptographic and freshness validation may run before acquiring
        # the write reservation. Authorization is checked again afterward.
        if not verify_signed_evidence(
            signed_evidence, key, expected_incident_id, collector_id
        ):
            return self._reject_submission(
                reason="Invalid signature",
                incident_id=expected_incident_id,
                collector_id=collector_id,
                signature=signature,
            )

        freshness = validate_evidence_freshness(
            signed_evidence,
            max_age_minutes=10,
            max_future_seconds=30,
        )
        if not freshness["fresh"]:
            return self._reject_submission(
                reason=freshness["reason"],
                incident_id=expected_incident_id,
                collector_id=collector_id,
                signature=signature,
            )

        fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()
        signature_fingerprint = hashlib.sha256(
            signature.encode("utf-8")
        ).hexdigest()

        with closing(self._connect()) as conn:
            # Serializes this final authorization check with key rotation
            # and revocation performed by other SQLite writers.
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = conn.execute(
                    """
                    SELECT enabled, key_fingerprint
                    FROM collectors
                    WHERE collector_id = ?
                    """,
                    (collector_id,),
                ).fetchone()

                if (
                    current is None
                    or current[0] != 1
                    or not hmac.compare_digest(current[1], fingerprint)
                ):
                    action = "SUBMISSION_REJECTED"
                    reason = "Collector not authorized"
                    accepted = False
                else:
                    try:
                        conn.execute(
                            """
                            INSERT INTO accepted_evidence
                            (signature, incident_id, collector_id)
                            VALUES (?, ?, ?)
                            """,
                            (signature, expected_incident_id, collector_id),
                        )
                    except sqlite3.IntegrityError:
                        action = "SUBMISSION_REJECTED"
                        reason = "Replay detected"
                        accepted = False
                    else:
                        action = "SUBMISSION_ACCEPTED"
                        reason = "Evidence accepted"
                        accepted = True

                conn.execute(
                    """
                    INSERT INTO evidence_audit
                    (incident_id, collector_id, action, reason,
                     signature_fingerprint)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        expected_incident_id,
                        collector_id,
                        action,
                        reason,
                        signature_fingerprint,
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        if not accepted:
            return {"accepted": False, "reason": reason}
        return {
            "accepted": True,
            "collector_id": collector_id,
            "incident_id": expected_incident_id,
        }
    def verify_accepted_evidence(
        self,
        signed_evidence: dict,
        expected_incident_id: int,
    ) -> bool:
        """Read-only check of an accepted, currently authorized submission."""
        if not isinstance(signed_evidence, dict):
            return False
        signature = signed_evidence.get("signature")
        record = signed_evidence.get("record")
        if (
            not isinstance(signature, str)
            or len(signature) != 64
            or any(c not in "0123456789abcdef" for c in signature)
            or not validate_evidence_record(record)
        ):
            return False
        if (
            type(expected_incident_id) is not int
            or expected_incident_id <= 0
            or record.get("incident_id") != expected_incident_id
        ):
            return False
        collector_id = record["collector_id"]
        key = self._keys.get(collector_id)
        if not isinstance(key, str):
            return False
        if not verify_signed_evidence(
            signed_evidence, key, expected_incident_id, collector_id
        ):
            return False
        freshness = validate_evidence_freshness(
            signed_evidence, max_age_minutes=10, max_future_seconds=30
        )
        if not freshness["fresh"]:
            return False
        key_fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()
        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM accepted_evidence AS e
                JOIN collectors AS c ON c.collector_id = e.collector_id
                WHERE e.signature = ?
                  AND e.incident_id = ?
                  AND e.collector_id = ?
                  AND c.enabled = 1
                  AND c.key_fingerprint = ?
                """,
                (signature, expected_incident_id, collector_id, key_fingerprint),
            ).fetchone()
        return row is not None
