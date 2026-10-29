> Historical step guide. This organized source uses `python manage.py`; see the root README for current commands. Old overlay-install paths below describe earlier deliveries.

# SentinelOps SOC 2.0 — Step 10: analyst dashboard

The local FastAPI application now serves an analyst workspace at /dashboard.
It includes incident and alert lists, a case timeline, current evidence provenance,
recorded Gemini/fallback labels, explicit analyst response controls, synthetic
effect telemetry, rollback and audit history. It always displays
**SIMULATED / NOT PRODUCTION**. No real firewall adapters are added.

## Install safely

Download SentinelOps_Step10_Complete.zip into Downloads. Stop the API server.
Extract the package outside your project, then use its installer:

```powershell
$zip = "$env:USERPROFILE\Downloads\SentinelOps_Step10_Complete.zip"
$package = "$env:USERPROFILE\Downloads\SentinelOps_Step10_Complete"
if (!(Test-Path -LiteralPath $zip -PathType Leaf)) { throw "Download the Step 10 ZIP first: $zip" }
Expand-Archive -LiteralPath $zip -DestinationPath $package -Force
if (!(Test-Path -LiteralPath "$package\install_step10.py")) { throw 'Wrong extracted package folder' }

Set-Location 'C:\Users\tripa\OneDrive\Desktop\sentinel ops 14 10 2026\sentinelops-gemini'
.\.venv\Scripts\python.exe "$package\install_step10.py" --project . --check
if ($LASTEXITCODE -ne 0) { throw 'Baseline or package check failed; nothing installed' }
.\.venv\Scripts\python.exe "$package\install_step10.py" --project .
if ($LASTEXITCODE -ne 0) { throw 'Step 10 installation failed' }
```

Only **app/main.py** is replaced, as a complete file. It adds the dashboard router
and dashboard response headers, and updates the application title/version.
The package adds these complete files:

- app/dashboard_routes.py
- app/dashboard/index.html
- app/dashboard/dashboard.css
- app/dashboard/dashboard.js
- app/dashboard/sample.js
- run_step10_checks.py and run_step10_demo.py
- test_step10_dashboard.py, test_step10_frontend.py, test_step10_frontend.cjs, test_step10_demo.py
- ci/step10-regression.yml
- README_STEP10.md

The installer checks the inspected Step 9 baseline and all payload hashes before
writing. Unknown source changes or unrecognized existing new files cause refusal.
Backups go in .step10_backups. Reinstallation makes zero changes. No database
migration, .env replacement, Gemini model change or key rotation is required.
Existing Steps 1–9 application services and tests are preserved.

## Run the full gate

Node.js 20+ is needed for the framework-free frontend tests. Node is already
installed on the inspected computer. No npm packages or frontend build are needed.
The existing Step 9 Python environment/dependencies are sufficient.

```powershell
.\.venv\Scripts\python.exe .\run_step10_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Step 10 gate failed; inspect STEP10_TEST_RESULTS.txt' }
```

Expected: **24/24 test jobs passed; cleanup: PASSED**.
This includes all 21 Step 9 jobs, the 12-case dashboard API suite, the frontend
wrapper running 12 Node DOM contract tests, and the isolated demo bootstrap suite.
It is a count of test jobs, not individual assertions. Concurrency still repeats
three times and retains strict assertions. The gate clears credentials, uses
disposable source copies/SQLite databases, blocks external Python socket egress,
and treats failed cleanup as failure.

If Node cannot be found through PATH, pass its executable explicitly:

```powershell
.\.venv\Scripts\python.exe .\run_step10_checks.py --socket-free-http --node 'C:\Program Files\nodejs\node.exe'
```

The gate writes STEP10_TEST_RESULTS.txt and STEP10_TEST_RESULTS.json. Live Gemini
authentication is deliberately not run; your prior LIVE_VERIFIED result is separate.
The old run_step9_checks.py command also remains available and unchanged.

## Try the complete flow with temporary demo data

This is the easiest first run. It creates fresh temporary databases under work/,
generates demo-only analyst/collector credentials, seeds synthetic observations
through the actual ASGI routes, and starts a localhost server. Existing project
databases and .env are not read or changed by demo setup. Gemini calls are disabled.

```powershell
.\.venv\Scripts\python.exe .\run_step10_demo.py
```

Open **http://127.0.0.1:8765/dashboard**. The initial sample view makes no API calls.
Choose **Connect analyst** and enter demo_analyst with the generated one-session
demo token printed by the launcher. Do not paste a Gemini API key or signing key.
The banner then explicitly identifies the isolated demo databases.

1. Select the identity-gateway case. Review its timeline and two signed evidence cards.
2. Choose Approve, enter a reason, and confirm. The simulated block must still be absent.
3. Choose Run simulation and confirm. Inspect the verified synthetic SQLite probe.
4. Choose Verify effect to create an additional verification audit.
5. Choose Roll back, enter a reason, and confirm. Inspect the rollback receipt,
   effect state and recorded audit events.
6. Disconnect, reconnect as demo_viewer with its printed token, and confirm all
   response controls are disabled. Server authorization independently enforces this.

The customer-api case demonstrates a failed attempt. The admin-console case
already includes a historical executed-and-rolled-back flow. All demo observations
are synthetic; valid demo signatures do not make them real security telemetry.
Evidence expires after ten minutes. Restart the demo for fresh signed observations.
Use --port 8766 if 8765 is occupied. Press Ctrl+C to stop. On normal shutdown the
temporary databases are removed. A forced process kill may leave a work/step10-demo-*
folder; no project database is inside it.

The in-process demo seed uses the existing test loop to avoid wakeup sockets.
The demo's actual Uvicorn server uses its normal event loop. This does not change
the event loop of your existing API server.

## Use your existing project records

Keep your existing server environment, analyst identities, registered collector
and database paths. Start the app from the project folder using your established
command, or this localhost command:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If your server configuration is maintained in the existing .env, add
--env-file .env to that command. Do not add it when no such file exists.
Open **http://127.0.0.1:8000/dashboard**, choose Connect analyst, and use an existing
analyst ID/token from Step 5. Existing provisioning remains unchanged; a new local
viewer can be created, if needed, with provision_analyst.py and a new unique ID.
The dashboard does not provision collectors, accept signing keys, or ingest alerts.
Continue to use the established authenticated ingestion API for those operations.

Public HTML/CSS/JS contain only the shell and illustrative sample records. Every
operational dashboard read requires analyst headers. A viewer can read; analyst
and admin roles can request the existing server-authorized operations. The token
is held only in this tab's JavaScript memory, never in URLs, localStorage,
sessionStorage or cookies. Reload, disconnect, page exit and revoked sessions
clear credentials. Your browser's own password-manager settings remain independent.

Sample walkthrough is always read-only and never writes records. Connected mode
fetches real SQLite records from the selected server, including the isolated demo
when launched on its separate port. The label "LIVE DATABASE" means a current
database read, not live network enforcement or a Gemini authentication check.

## Response and trust behavior

- Approval never executes. Every response operation has its own confirmation.
- The existing decision/execution/verification/rollback services remain authoritative;
  the frontend cannot supply dependencies, collector keys or approval bindings.
- Eligibility is an advisory snapshot. The server checks current identity, evidence,
  registry state and approval binding again before executing. Malformed evidence
  fails closed. A stale UI snapshot disables actions after sixty seconds until refresh.
- Execution/rollback retries reuse their session-memory idempotency keys. A network
  interruption can leave the result unknown; refresh before retrying. Closing the
  tab clears those keys. If a receipt committed, refresh shows its current state.
- Expired/revoked collector evidence prevents new execution. Authorized rollback of
  an existing effect remains available, including shared-block retention semantics.
- Read snapshots have no state-changing side effects. Viewing telemetry does not
  run another probe; Verify effect is an explicit audited operation.
- Reasoning badges describe the persisted result's actual ai_status. Gemini
  disagreement is shown as fallback_rules. Unknown legacy source is labeled
  Not recorded. Current provider availability is never inferred from stored badges.
- The UI uses textContent for records, explanations and audit text. It loads no
  third-party scripts, fonts or analytics. Dashboard responses have a self-only
  content security policy, no-store caching, no-referrer and frame restrictions.
- Snapshots omit signatures, signed envelopes, idempotency keys and arbitrary
  evidence fields. Evidence observations are allowlisted typed counts/booleans.

## Read limits and errors

The incident queue initially loads 30 newest incidents. Load older cases uses an
ID cursor. Search and state filters apply to loaded cases; metrics are database-wide
counts. Recent signals shows the latest ten alerts. A case shows at most 100 evidence
records, 100 most recent audit events and 20 telemetry entries (the overview tab
displays the latest three probes). Truncation is labeled; a truncated evidence set
cannot enable approval/execution. Use existing paginated API reads for older audit.

Loading, empty, no-match, unavailable-server, expired-session and action-denial
states are handled. Failed initial live loading clears all illustrative rows.
Cancelled or late sign-in/refresh responses cannot restore disconnected data.
IDs outside JavaScript's safe integer range are refused for actions; use the API
directly for such unusual legacy IDs. All displayed dates are labeled UTC.
Tabs support arrow/Home/End keys, forms have labels, and reduced-motion preference
is respected. Mobile and desktop layouts are included in CSS.

## Verification limits and manual browser check

Automated verification covers the real ASGI API, frontend DOM contracts and demo
setup. **Rendered browser layout and browser-driven end-to-end clicks were not
verified in the agent runtime:** localhost connections were refused/timed out under
its networking restrictions. No firewall or browser security settings were changed.
The Node DOM harness does not emulate layout, browser form validation or rendering.
It must not be described as a browser test.

After starting the demo, check these in your own browser:

- Sample page, incident selection, case search and response-state filter.
- Overview/Evidence/Audit tabs; no overflowing page at desktop and phone widths.
- Keyboard navigation and labeled confirmation forms.
- Explicit approve → execute → verify → rollback sequence and fresh audit entries.
- Viewer controls disabled, disconnect clearing the session, and useful empty/error states.

The report preserves this visual verification limit. The supplied
ci/step10-regression.yml template runs the same offline gate on Windows and Ubuntu
with Python and Node. It is not enabled or run on GitHub by this delivery; remote
CI and Ubuntu execution remain unverified. No GitHub changes are performed.

## Step 10 roadmap alignment

| Item | Delivered behavior |
| --- | --- |
| 10.1 Synthetic alerts/timeline | Read-only sample cases, isolated seeded demo, live incident queue/recent signals/timeline |
| 10.2 Evidence/outcome | Provenance, collector, UTC collection time, freshness, allowlisted observations, outcome and steps |
| 10.3 Actual reasoning source | Separate triage/outcome Gemini/fallback/unknown labels; sample badges explicitly marked |
| 10.4 Analyst decisions/eligibility | Role-aware pending state and explicit proposal/decision/execution controls; authoritative server rechecks |
| 10.5 Response lifecycle/audit | Block presence, synthetic probes, verification, rollback, actor/reason/audit timeline |
| 10.6 UX states/simulation label | Loading/error/empty/search states, responsive layout, persistent simulation markings; visual browser QA pending as described above |
