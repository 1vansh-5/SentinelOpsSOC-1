> Historical step guide. This organized source uses `python manage.py`; see the root README for current commands. Old overlay-install paths below describe earlier deliveries.

# SentinelOps SOC 2.0 — Major Step 7

API integration and contracts, with the missing Step 6 verification/rollback work
completed. Simulation only. This overlay targets your verified Step 6 project.
It supplies complete replacement modules, not fragments to paste into files.

## 1. Extract OUTSIDE the project

Download the ZIP into Downloads. Extract into a new folder:

```powershell
$package = "$env:USERPROFILE\Downloads\SentinelOps_Step7_Complete"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SentinelOps_Step7_Complete.zip" -DestinationPath $package
Test-Path -LiteralPath "$package\install_step7.py"
```

The last command must print True. If it prints False, find the exact extracted path:

```powershell
Get-ChildItem -LiteralPath "$env:USERPROFILE\Downloads" -Filter install_step7.py -Recurse | Select-Object FullName
```

Set `$package` to the folder containing that file. Do not extract the ZIP into app,
do not move individual files, and do not run the Step 5 or Step 6 installers again.

## 2. Stop, back up, check, install

Stop Uvicorn and other project writers first. From PowerShell:

```powershell
Set-Location -LiteralPath 'C:\Users\tripa\OneDrive\Desktop\sentinel ops 14 10 2026\sentinelops-gemini'
$project = (Get-Location).Path
$backup = $project + '-before-step7-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -LiteralPath $project -Destination $backup -Recurse
```

Also copy any databases configured outside this folder by SENTINELOPS_DB,
SENTINELOPS_ANALYST_DB or SENTINELOPS_REGISTRY_DB. Include their matching sidecar
files if present; stop all writers before copying. The installer itself never opens
production databases and backs up replaced source files under `.step7_backups`.

```powershell
& .\.venv\Scripts\python.exe "$package\install_step7.py" --project "$project" --check
if ($LASTEXITCODE -ne 0) { throw 'Unknown baseline or damaged package; nothing installed' }
& .\.venv\Scripts\python.exe "$package\install_step7.py" --project "$project"
if ($LASTEXITCODE -ne 0) { throw 'Installation failed; do not start the API' }
```

The four replaced app modules are main.py, schemas.py, response_routes.py and
response_execution.py. Five new app modules are api_contracts.py, api_security.py,
api_read_routes.py, authenticated_investigation.py and simulation_lifecycle.py.
The installer also adds the Step 7 runner, two test files and this guide at project
root. Existing Step 2–6 tests, the earlier approval service and collector registry
remain unchanged. Unknown source differences cause refusal before any copy.

## 3. Run the complete gate

No new application dependency is introduced. HTTP tests require HTTPX, already
present in the inspected virtual environment. If missing, install the supplied
requirements-test.txt into that environment first.

```powershell
& .\.venv\Scripts\python.exe .\run_step7_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Tests failed; do not restart the API' }
```

Expected: **14/14 suites passed**. That includes the unchanged ten Step 2–5 suites,
the two unchanged Step 6 suites (24 integrated cases plus its HTTP flow), 13 new
simulation lifecycle cases and nine new full HTTP contract/workflow cases. Output
is saved in STEP7_TEST_RESULTS.txt. Temporary database paths and an empty Gemini
key are set in child test processes; tests make no external model calls.

`--socket-free-http` is a test-only asyncio polling-loop option inherited from
Step 6. It allows actual in-process HTTPX/ASGI requests, validation, middleware and
startup/shutdown tests without an asyncio wakeup socket on restricted Windows.
You may omit it on an unrestricted machine. No running network listener was used
for verification, and this flag does not alter the production Uvicorn event loop.

## 4. Restart

Keep your existing environment configuration and three DISTINCT persistent SQLite
files. Do not switch the analyst path or you will appear to lose existing identities.
Collector ID/key must match an active enrolled collector. No provisioning, rotation
or administrative mutation endpoint is exposed. Continue provisioning identities
locally using the established Step 5 workflow.

```powershell
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/docs for the typed contracts and safe schema examples.
Startup creates three new tables without deleting previous data: simulation_effects,
simulation_telemetry and response_rollbacks. Previously executed Step 6 requests
are marked LEGACY_UNVERIFIED in the new lifecycle table. Their receipts are retained
unchanged. Explicit /verify checks their current simulated state before marking it
VERIFIED; an old historical receipt is never silently upgraded to verified.

## API contracts

All ordinary success responses remain HTTP 200 for compatibility. Their typed
status fields distinguish an applied operation, verification failure and history
replay. Bad input is not echoed in validation errors.

| HTTP status | Stable error code | Meaning |
|---|---|---|
| 401 | AUTHENTICATION_REQUIRED | Credentials missing or API key invalid |
| 403 | OPERATION_DENIED | Role/token, evidence, state or idempotency denied |
| 404 | NOT_FOUND | Unknown resource or route |
| 409 | STATE_CONFLICT | Evidence refused or authenticated assessment unavailable/frozen |
| 413 | PAYLOAD_TOO_LARGE | Request body exceeds 128 KiB |
| 422 | INVALID_INPUT | Request/model/query/path validation failed |
| 503 | SERVICE_UNAVAILABLE | Required configuration, database or handler unavailable |

The legacy execution/proposal/decision routes deliberately keep their existing
403 denial status, including idempotency conflicts. Example safe error body:

```json
{"detail":"Request validation failed","code":"INVALID_INPUT"}
```

Positive resource IDs and typed envelopes are validated. Input models reject unknown
fields. The signature is lowercase HMAC-SHA256 hex; collected_at stays an exact
string during validation so the signed record is never rewritten by date conversion.
The existing registry still checks timestamps, signature, replay and collector state.

| Endpoint | Authorization | Purpose |
|---|---|---|
| GET /health | Public | Minimal simulation health |
| GET /alerts, GET /incidents | Viewer, analyst or admin headers | Bounded operational lists |
| POST /webhook/alert, POST /simulate/attack | X-API-Key | Create alert |
| POST /alerts/{alert_id}/investigate | X-API-Key | Existing bounded investigation; creates incident |
| POST /incidents/{alert_id}/investigate | X-API-Key | Retained legacy alias; parameter is ALERT ID |
| POST /incidents/{incident_id}/evidence/submit | X-API-Key plus valid signed envelope | Accept/store collector record |
| GET /incidents/{incident_id}/evidence | Analyst headers, any enabled role | Current provenance summaries; no signatures |
| POST /incidents/{incident_id}/investigate-authenticated | Analyst or admin | Deterministic review of exact corroborating stored records |
| POST /response-requests/for-incident/{incident_id} | Analyst or admin | Create/reuse pending proposal |
| POST /response-requests/{request_id}/decision | Analyst or admin | Explicit approval/rejection, no execution |
| POST /response-requests/{request_id}/execute | Analyst/admin plus Idempotency-Key | Simulated action and synthetic verification |
| POST /response-requests/{request_id}/verify | Analyst or admin | Inspect current simulated effect and audit result |
| POST /response-requests/{request_id}/rollback | Analyst/admin plus Idempotency-Key | Release this request's effect and verify final state |
| GET /response-requests, GET /response-requests/{request_id} | Any enabled role | Status plus lifecycle_state |
| GET /audit-history | Any enabled role | Ordered, bounded audit history |
| GET /simulated-blocks | Any enabled role | Database-only simulated blocks |

Analyst headers are X-Analyst-Id and X-Analyst-Token. The server API key does not
substitute for analyst authorization. Read endpoints formerly open in Step 6 are
now protected; clients must add analyst headers. Alert/incident lists now use
ascending keyset ordering with after_id and limit (1–100). Request/audit lists
also support after_id; audit-history accepts optional request_id. Preserve the last
returned id to fetch the next page. Public /docs and /openapi.json contain schemas,
not database contents or server credentials.

## HTTP walkthrough with an existing collector

The nine-case HTTP test suite is the repeatable, isolated demonstration; it creates
its own local test identities, signs fixture records, and drives the real app through
HTTP. For your own server, do not paste any signing keys or analyst tokens into chat.

In a second PowerShell window:

```powershell
$base = 'http://127.0.0.1:8000'
$analystId = Read-Host 'Existing analyst ID'
$credential = [pscredential]::new($analystId, (Read-Host 'Analyst token' -AsSecureString))
$headers = @{'X-Analyst-Id'=$analystId; 'X-Analyst-Token'=$credential.GetNetworkCredential().Password}
$apiCredential = [pscredential]::new('api', (Read-Host 'Server API key' -AsSecureString))
$apiHeaders = @{'X-API-Key'=$apiCredential.GetNetworkCredential().Password}
$body = @{source_ip='8.8.8.8';event_type='failed_login';target='demo-login';details='Controlled simulation';severity='high'} | ConvertTo-Json
$alert = Invoke-RestMethod -Method Post -Uri "$base/webhook/alert" -Headers $apiHeaders -ContentType 'application/json' -Body $body
$incident = Invoke-RestMethod -Method Post -Uri "$base/alerts/$($alert.id)/investigate" -Headers $apiHeaders
$incidentId = $incident.incident_id
```

The default investigation has placeholder/synthetic evidence and cannot authorize
a block. Obtain two fresh incident-bound signed envelopes from your enrolled demo
collector. The evidence object inside each signed record must have exactly these
fields (the signatures/timestamps are generated by the collector, not invented):

```json
{"source_ip":"8.8.8.8","tool":"authentication_logs","observations":{"login_attempts":5,"failed_logins":4,"successful_login":true,"session_created":true}}
```

```json
{"source_ip":"8.8.8.8","tool":"application_logs","observations":{"unauthorized_access_observed":true,"http_status":200}}
```

These are controlled demonstration observations, not evidence that a real attack
occurred. HMAC establishes collector origin and integrity; it cannot establish that
a collector's assertions are true. Use the existing enrolled collector signing
workflow to sign the actual record containing incident_id, collector_id, collected_at
and evidence. Both source IPs must match the incident alert. Boolean fields are
strict booleans, counts are bounded integers and failed_logins cannot exceed attempts.
Duplicate tool records, missing corroboration, untrusted/expired records, arbitrary
payload schemas and mismatches are rejected. More evidence is not silently ignored.

Submit both complete envelope JSON files:

```powershell
foreach ($tool in @('authentication_logs','application_logs')) {
    $path = Read-Host "Path to the signed $tool envelope for incident $incidentId"
    $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $submission = @{envelope=$envelope} | ConvertTo-Json -Depth 30
    Invoke-RestMethod -Method Post -Uri "$base/incidents/$incidentId/evidence/submit" -Headers $apiHeaders -ContentType 'application/json' -Body $submission
}
Invoke-RestMethod -Method Post -Uri "$base/incidents/$incidentId/investigate-authenticated" -Headers $headers
$proposal = Invoke-RestMethod -Method Post -Uri "$base/response-requests/for-incident/$incidentId" -Headers $headers
$requestId = $proposal.request_id
$decision = @{decision='APPROVED';reason='Reviewed current corroborating authenticated observations'} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$base/response-requests/$requestId/decision" -Headers $headers -ContentType 'application/json' -Body $decision
$headers['Idempotency-Key'] = [guid]::NewGuid().ToString('N')
Invoke-RestMethod -Method Post -Uri "$base/response-requests/$requestId/execute" -Headers $headers
Invoke-RestMethod -Method Post -Uri "$base/response-requests/$requestId/verify" -Headers $headers
# Use a fresh operation key for rollback. Retain it for rollback retries.
$headers['Idempotency-Key'] = [guid]::NewGuid().ToString('N')
$rollback = @{reason='Demo complete; release simulated response'} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$base/response-requests/$requestId/rollback" -Headers $headers -ContentType 'application/json' -Body $rollback
Invoke-RestMethod -Method Get -Uri "$base/audit-history?request_id=$requestId" -Headers $headers
$headers.Clear(); $apiHeaders.Clear()
$credential = $null; $apiCredential = $null
```

Authenticated investigation uses the existing deterministic validator and returns
ai_status=fallback_rules. It does not call Gemini, approve or execute. It is frozen
once a response proposal exists, so incident evidence cannot be overwritten after
review. This is the missing API bridge, not a client-provided trusted=True flag.

## Simulation state, verification and recovery

The persisted SQLite adapter is the authoritative simulated firewall. The old
in-memory demonstration module remains unchanged and is never called by these
execution routes. Synthetic telemetry is explicitly labeled synthetic_sqlite_probe
and checks only the simulated table, not real packets, connectivity or firewall rules.

Request PENDING/APPROVED/REJECTED behavior remains. Successful request status remains
SIMULATED_EXECUTED for compatibility; the separate lifecycle_state is VERIFIED.
Execution failure is SIMULATION_FAILED/FAILED; rollback is SIMULATED_ROLLED_BACK/
ROLLED_BACK. An explicit probe of a missing effect is VERIFICATION_FAILED. EXECUTING
and ROLLING_BACK audit events, telemetry, the final state, receipts, and effect changes
are written inside one main transaction. They commit together. In-progress states
are audit transitions, not a durable work queue: a crash before commit leaves the
original state and no external effect, making a retry safe without recovery workers.

Execution verification failure compensates a newly created simulated block in the
same transaction and records the failure. Its idempotency receipt is terminal;
retrying the same key returns that failure, never another action. Rollback verification
or audit-write failure aborts rollback, preserving the original effect and allowing
the same key to retry. Authorized rollback denials are separately audited when the
database is available; credentials and internal exceptions are excluded.

Each response request has its own effect reference. Rolling back one of several
requests for the same IP retains the shared block; the final active reference removes
it. Unknown legacy block ownership is preserved. A retained shared effect is reported
as block_retained=true, and synthetic verification checks that expected retained state.
Do not interpret that result as a claim that all blocks for the IP were removed.

Keys are 16–128 ASCII letters, digits, hyphens or underscores. Execution and rollback
have separate key namespaces. Every retry reauthenticates the analyst. Historical
execution replay after rollback returns the original receipt and does NOT reapply
the effect; read the current request/lifecycle endpoint for current state.

Pre-Step-6 unbound APPROVED requests remain ineligible for execution. The existing
reopen_legacy_step6.py utility can reopen one for review, as documented in Step 6.
Expired evidence still requires a fresh authenticated investigation; this release
does not bypass the ten-minute evidence freshness limit.

## Safety and upgrade boundaries

- No live firewall operations, GitHub changes, public analyst provisioning or collector
  administration endpoints. Administrative changes remain local trusted operations.
- Reads require enabled roles; decisions, execution, verification and rollback require
  analyst/admin roles. Execution retains the Step 6 authorization reservations across
  identity/registry databases. Rollback checks identity even if collector evidence has
  expired or the collector is revoked, so the operator can still undo a simulation.
- Validation errors omit supplied input. Unexpected handler failures return generic
  503 bodies. Public JSON responses redact known configured/request credential values
  and sensitive key names, including tokens, signatures and signing-key fields.
  Evidence summaries do not expose raw envelopes. This is not a general data-loss
  prevention system for arbitrary personal data inside collector payloads.
- Database administrators/server process owners remain trusted. SQLite audits are
  persistent but not externally immutable. No production security certification or
  real network protection is claimed. Roadmap Steps 8–12 remain separate work.

To roll back the upgrade, stop all processes and restore the matched pre-Step-7 source
and database backups. The installer lists source originals/new files in its backup
installation.json. Retain copies of current databases before restoring older ones,
because restoring a snapshot discards later activity. Earlier code does not support
the new rollback statuses, so source-only rollback after use is insufficient.
