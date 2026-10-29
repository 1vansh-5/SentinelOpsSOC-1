
"""Collector authorization and replay protection."""

import secrets


class CollectorRegistry:
    def __init__(self):
        self._collectors = {}
        self._used_signatures = set()

    def register_collector(self, collector_id: str, signing_key: str):
        if not collector_id or not collector_id.strip():
            raise ValueError("Collector ID is required")

        if not signing_key or len(signing_key) < 32:
            raise ValueError("Strong signing key is required")

        if collector_id in self._collectors:
            raise ValueError("Collector already registered")

        self._collectors[collector_id] = signing_key

    def verify_submission(
        self,
        signed_evidence: dict,
        expected_incident_id: int,
    ) -> dict:
        from .evidence_signing import verify_signed_evidence

        if not isinstance(signed_evidence, dict):
            return {"accepted": False, "reason": "Invalid submission"}

        record = signed_evidence.get("record")

        if not isinstance(record, dict):
            return {"accepted": False, "reason": "Invalid record"}

        collector_id = record.get("collector_id")
        signing_key = self._collectors.get(collector_id)

        if not signing_key:
            return {
                "accepted": False,
                "reason": "Collector is not authorized",
            }

        signature = signed_evidence.get("signature")

        if not isinstance(signature, str):
            return {
                "accepted": False,
                "reason": "Missing signature",
            }

        if not verify_signed_evidence(
            signed_evidence,
            signing_key,
            expected_incident_id,
            collector_id,
        ):
            return {
                "accepted": False,
                "reason": "Signature verification failed",
            }

        if signature in self._used_signatures:
            return {
                "accepted": False,
                "reason": "Replay detected",
            }

        self._used_signatures.add(signature)

        return {
            "accepted": True,
            "collector_id": collector_id,
            "incident_id": expected_incident_id,
        }