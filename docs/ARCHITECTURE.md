# Architecture and trust boundaries

FastAPI assembles the application in app/main.py. The dashboard is served from
app/dashboard without a frontend dependency build. Public shell content is separate
from protected data in app/dashboard_routes.py. Sample mode is read-only and
labeled; connecting an analyst obtains local snapshots through same-origin calls.

| Boundary | Enforcement | Main source |
| --- | --- | --- |
| Caller → ingestion | API key, typed schemas, bounded requests | app/main.py, app/api_contracts.py |
| Collector → evidence | HMAC, registration, replay state, key history, freshness and incident/IP binding | app/evidence_signing.py, app/persistent_collector_registry.py |
| Browser → analyst actions | Token hashes and current role/revocation checks | app/analyst_identity.py, app/response_routes.py |
| Approval → execution | Frozen approval binding, raw envelope recheck, writer reservations | app/response_approval.py, app/response_execution.py |
| Execution → effect | SQLite-only simulation; receipt/status/audit/effect commit together | app/response_execution.py, app/simulation_lifecycle.py |
| Operator → recovery | Stopped-server backup, hashes/schema/integrity checks, new-directory restore | scripts/ops_databases.py, scripts/opsctl.py |

SENTINELOPS_DB holds alerts, incidents, evidence, approval bindings, requests,
receipts, simulation effects, synthetic telemetry and audits. SENTINELOPS_ANALYST_DB
holds identity, roles, revocation and token hashes. SENTINELOPS_REGISTRY_DB holds
collector/key trust state, fingerprints, replay state and history. These must be
distinct persistent files. Signing keys come from server configuration, never
caller-supplied verification parameters.

## Lifecycle

1. An alert creates an initial investigation. Optional Gemini assistance is
   advisory: strict structured output, reference validation, bounded worker, no
   automatic tools and deterministic override/fallback.
2. Two current signed auth/application observations establish the authenticated
   deterministic assessment. Model placeholders do not qualify.
3. An analyst proposes a response; investigation is frozen for that proposal.
4. An analyst explicitly approves or rejects. Approval creates no effect.
5. Execution reauthorizes and revalidates all stored evidence, then commits the
   simulated effect, receipt and audit together. Uniqueness constraints and
   BEGIN IMMEDIATE prevent competing duplicate effects.
6. A synthetic SQLite probe checks local simulation state. Failed verification
   compensates the effect. This does not test real network traffic.
7. Authorized rollback removes the applicable effect, with shared-IP protections
   and one rollback receipt. It remains available if evidence expires or a
   collector is revoked, so recovery is not blocked by stale evidence.
8. A retry returns historical receipt data with replayed=true. Read the current
   dashboard snapshot to determine present state after rollback.

Legacy effects are LEGACY_UNVERIFIED, not retroactively trusted. Crash recovery
and competing processes are covered by existing Step 7/9 tests. There is no
multi-host distributed lock. Safe operational route/status/timing logs are
separate from transactional response_audit. Neither is an externally anchored,
tamper-proof audit service.
