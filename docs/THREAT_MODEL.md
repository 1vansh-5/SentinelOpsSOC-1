# Threat model and limitations

Scope: a trusted local operator on one machine, distinct SQLite stores, controlled
collector configuration and explicit analyst provisioning. This is a design review
of the prototype, not a compliance certification.

Assets include analyst bearer tokens/hashes, signing material, API/provider keys,
evidence, decisions, receipts and private backups. Source archives exclude runtime
data and configuration. Protect backups even when plaintext keys are absent.

| Threat | Current control | Residual risk / assumption |
| --- | --- | --- |
| Forged/replayed evidence | Registered HMAC, replay state, key history, freshness and incident/IP binding | A compromised collector can sign false events; HMAC establishes key possession, not event truth |
| Stale evidence / changed approval | Raw envelope recheck at execution, immutable binding | Trusted clock and host state remain assumptions |
| Stolen/revoked identity | Hashed bearer tokens, current role/revocation checks | Theft permits actions until revocation; no MFA/federation |
| Viewer escalation | Separate ingestion and analyst credentials; server role enforcement | Trusted local provisioning can create privileged identities |
| Model injection/bad output | Strict structure/references, no auto tools, worker budgets, deterministic override | Advice may be inaccurate; enabled live prompts can leave the host |
| Duplicate/competing execution | Unique constraints, writer reservations, atomic effect/receipt/audit and crash tests | Local SQLite/filesystem semantics trusted; no multi-host control plane |
| False containment claim | SIMULATION_ONLY and synthetic_sqlite_probe labels | A row proves no real firewall or network result |
| Browser injection/credential persistence | textContent, CSP, same-origin calls, memory-only tokens, explicit confirmations | Malicious extensions or compromised browser/host remain out of scope |
| Credential disclosure in logs | Bounded public errors, redaction and structured safe logging | Alternate debug launchers and token-bearing terminal recordings can leak |
| Backup tampering / old access revival | Hash/schema checks, private new-directory restore, manual reconciliation | Hashes detect corruption, not malicious replacement; old backups can revive revoked identities |
| Host/database compromise | Local filesystem permissions assumed | Administrators can alter keys, databases and audits; no external audit anchor |
| Availability abuse | Bounded requests, model budgets/worker cap, pagination | No complete rate limiting, TLS termination or high availability |

The supported launcher binds loopback with one worker. CI and Docker templates
are unexecuted here. Node DOM contracts do not establish actual browser layout,
accessibility or compatibility; screenshots/video remain a local capture task.

The offline gate does not establish provider availability, billing, live telemetry
truth, attack-detection accuracy, network containment, production security or SOC 2
compliance. Production work would require independent collector attestation,
stronger identity, secure transport, operational monitoring, rate limits,
authenticated backups, external audit retention and separately reviewed response
adapters. No real response adapter is included or enabled.
