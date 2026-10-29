> Historical step guide. This organized source uses `python manage.py`; see the root README for current commands. Old overlay-install paths below describe earlier deliveries.

# SentinelOps SOC 2.0 — Step 11: deployment and operational hygiene

Supported local setup: **Windows PowerShell, Python 3.15 (tested 3.15.0), Node.js
20+ (tested 26.7.0)**. Python dependencies are pinned to the complete 35-package
Step 9 environment. No package upgrade or Gemini model change is required in
your already verified .venv. This remains SIMULATED / NOT PRODUCTION.

## Install the overlay

Stop the API. Save SentinelOps_Step11_Complete.zip in Downloads, then:

```powershell
$zip = "$env:USERPROFILE\Downloads\SentinelOps_Step11_Complete.zip"
$package = "$env:USERPROFILE\Downloads\SentinelOps_Step11_Complete"
if (!(Test-Path -LiteralPath $zip -PathType Leaf)) { throw "Download the Step 11 ZIP first: $zip" }
Expand-Archive -LiteralPath $zip -DestinationPath $package -Force
Set-Location 'C:\Users\tripa\OneDrive\Desktop\sentinel ops 14 10 2026\sentinelops-gemini'
.\.venv\Scripts\python.exe "$package\install_step11.py" --project . --check
if ($LASTEXITCODE -ne 0) { throw 'Baseline or package verification failed; nothing installed' }
.\.venv\Scripts\python.exe "$package\install_step11.py" --project .
if ($LASTEXITCODE -ne 0) { throw 'Step 11 installation failed' }
.\.venv\Scripts\python.exe .\run_step11_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Step 11 gate failed; inspect STEP11_TEST_RESULTS.txt' }
```

Expected: **28/28 test jobs passed; cleanup: PASSED**. The original 24 jobs remain,
including all Step 1–10 gates and three strict concurrency repetitions. Four new
jobs cover seven database-operation tests, three log tests, six hygiene tests,
and a clean-source checkout/demo test. The count describes jobs, not assertions.

Replaced complete files: app/main.py (logging middleware/version), .env.example,
.gitignore, requirements.txt and Dockerfile. Added files: app/structured_logging.py,
run_sentinelops.py, opsctl.py, ops_databases.py, ops_hygiene.py,
ops/uvicorn_logging.json, .dockerignore, release-files.json, run_step11_checks.py,
four test_step11_*.py suites, ci/step11-regression.yml and this guide.
The installer verifies source/payload hashes before changes, backs up replaced
files in .step11_backups, refuses unknown changes and repeats as a no-op.
**Your .env and databases are not read or changed by installation.**

## Clean-source setup for another developer

SentinelOps_Step11_Clean_Source.zip contains the complete allowlisted application,
tests, fixed dependencies, assets and guides. It contains no .env, databases,
virtual environment, collector signing keys, analyst tokens, backups or Git history.
Extract it into a new empty project directory. A clean checkout means these source
files, not a clone of an unmodified older GitHub repository; this delivery does not
change GitHub. RELEASE_MANIFEST.json records hashes of all exported source files.

In the extracted source directory:

```powershell
py -3.15 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
.\.venv\Scripts\python.exe -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency check failed' }
node --version
.\.venv\Scripts\python.exe .\run_step11_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Clean-source gate failed' }
.\.venv\Scripts\python.exe .\run_step10_demo.py
```

Dependency installation needs package-index access or compatible cached wheels.
No npm install or frontend build is required. Open http://127.0.0.1:8765/dashboard.
Use demo_analyst with the launcher's generated one-session token. Demo setup
creates temporary synthetic databases, disables live Gemini, and never opens
existing project databases. See README_STEP10.md for the explicit analyst workflow.
The automated clean-source check verifies the actual ASGI demo bootstrap, not
rendered browser layout or a TCP listener in the restricted agent runtime.

## Safe configuration and startup

Existing installations: keep your existing .env, credentials and database paths.
The new .env.example has blank credential fields and Gemini disabled by default.
For a NEW setup needing persistent project records, copy the example only if
.env does not exist, then fill values locally using your established provisioning:

```powershell
if (Test-Path -LiteralPath .\.env) { throw 'Existing .env preserved; edit it deliberately if needed' }
Copy-Item -LiteralPath .\.env.example -Destination .\.env
```

Never put real credentials in .env.example. Analyst tokens come from
provision_analyst.py; collector keys must match an explicitly registered collector.
The simulation demo needs no .env. To enable optional live AI, set your own local
GEMINI_API_KEY, your selected GEMINI_MODEL (previously gemini-3.5-flash-lite), and
SENTINELOPS_GEMINI_ENABLED=1. Preserve 15000 ms per-attempt timeout and 60000 ms
workflow budget unless deliberately choosing other supported bounds. Never paste
these credentials into dashboard forms, source files or the chat.

The supported persistent-server launcher loads only an explicit setting allowlist,
does not interpolate dotenv values, preserves existing process-variable precedence,
checks the exact dependency set and distinct persistent DB paths, and binds localhost:

```powershell
.\.venv\Scripts\python.exe .\run_sentinelops.py --env-file .\.env --check
if ($LASTEXITCODE -ne 0) { throw 'Configuration rejected' }
.\.venv\Scripts\python.exe .\run_sentinelops.py --env-file .\.env
```

Omit --env-file when using existing process variables and no .env. --check performs
no database initialization and no provider authentication. Relative database paths
are resolved against the project directory. The API, analyst and collector stores
must be three distinct files. Missing collector configuration permits read-only
setup but cannot authorize response execution; partial collector ID/key configuration
is rejected. Use --port 8001 if needed. It uses one Uvicorn worker and no reload.

## Structured operational logs

Operational JSON includes timestamp, event, method, server-owned route template,
HTTP status, duration, generated request ID and SIMULATION_ONLY. Incoming request
IDs are not trusted. X-Request-Id is returned to correlate a response with a log.
Raw URLs/queries, source IPs, headers, request bodies, tokens, signing material,
model prompts/responses, arbitrary log messages and exception stacks are omitted.
Unknown routes do not log the caller's path. Uvicorn access logging is disabled;
the supported launcher's lifecycle/error messages use the same safe formatter.
Operational log failure cannot turn a denied action into success or change an
already committed response. Transactional response_audit remains authoritative.

Logs go to the console; no automatic log-file rotation, retention or remote log
shipping is configured. If you redirect logs, protect the destination and choose
retention deliberately. Do not enable raw debug logging for third-party clients
or use an alternate Uvicorn log configuration when expecting these guarantees.

## Coordinated SQLite backup

Stop every API/demo/maintenance writer first. Back up all three stores together,
using their actual configured paths. Do not guess missing registry paths or create
an empty replacement registry to make a backup pass. The following filenames are
examples matching the default persistent setup; substitute your existing paths.
The output folder must NOT already exist. Its parent must exist.

```powershell
New-Item -ItemType Directory -Path .\backups -Force | Out-Null
.\.venv\Scripts\python.exe .\opsctl.py backup `
  --incidents .\sentinelops.db `
  --analysts .\analysts.sqlite `
  --registry .\collector_registry.db `
  --output .\backups\before-upgrade-001 `
  --server-stopped
if ($LASTEXITCODE -ne 0) { throw 'Backup refused or failed; inspect its safe reason code' }
.\.venv\Scripts\python.exe .\opsctl.py verify --snapshot .\backups\before-upgrade-001
if ($LASTEXITCODE -ne 0) { throw 'Backup validation failed' }
```

The tool validates known tables/columns and integrity, obtains writer reservations
on all three stores, then uses SQLite's backup API through separate read connections.
It includes committed WAL records; copying just a .db file while writers run is not
equivalent. Locks have a short timeout and conflicts fail closed. The stop flag is
an operator assertion, not a process detector; do not run this against active writers.
Only a complete verified bundle is published. Source application rows are not edited.

The snapshot contains incidents/evidence/audit records, identity token digests and
collector key fingerprints. It contains no plaintext bearer tokens or signing keys,
but the data is still private. Store snapshots using your normal protected/encrypted
backup storage. Hash verification detects corruption; it does not authenticate an
attacker-rewritten manifest. Keep the trusted bundle and hash records together.
Signing keys and bearer tokens require separate trusted credential storage.

## Recovery and schema staging

Recovery writes NEW files in a NEW directory. It never overwrites or activates
your working databases. Keep the server stopped during review and activation.

```powershell
New-Item -ItemType Directory -Path .\recovery -Force | Out-Null
.\.venv\Scripts\python.exe .\opsctl.py restore `
  --snapshot .\backups\before-upgrade-001 `
  --output .\recovery\restored-001
if ($LASTEXITCODE -ne 0) { throw 'Recovery staging failed' }
```

For an older known Step 5+ schema, stage an upgrade into a separate new directory:

```powershell
.\.venv\Scripts\python.exe .\opsctl.py stage-upgrade `
  --snapshot .\backups\before-upgrade-001 `
  --output .\recovery\upgraded-001
if ($LASTEXITCODE -ne 0) { throw 'Upgrade staging failed; original bundle preserved' }
```

The established application initializers create missing supported tables, preserve
data and are repeatable. They do not repair arbitrary columns or infer unknown schemas.
Missing core tables/columns are refused. Legacy execution receipts become
LEGACY_UNVERIFIED; staging does not grant fresh approval or execution permission.
There is no new application schema migration required for Step 11 itself.

Review integrity, schema, row counts and the persisted audit/receipts in the staged
copy. Restoring an old identity/registry backup can resurrect old enabled roles or
collector state; reconcile revocations, rotations and incident state before reuse.
Token digests/fingerprints cannot recover lost plaintext credentials. Existing
signed evidence may be expired even when the restored database is intact.

After review, deliberately change the three database paths in your local server
configuration to the staged files, preserve a verified pre-change snapshot, then
restart and validate with a viewer before enabling analyst operations. Do not edit
audit rows or replay old actions to compensate for missing state. Rolling back a
software upgrade should use a compatible, coordinated database snapshot; an older
binary is not guaranteed to understand newly created schema. Automatic data repair,
live replacement, downgrade migration and automatic restart are not implemented.

## Syntax, secret exposure and release checks

```powershell
.\.venv\Scripts\python.exe .\ops_hygiene.py check --node 'C:\Program Files\nodejs\node.exe'
if ($LASTEXITCODE -ne 0) { throw 'Source hygiene failed' }
```

The check parses Python without importing it, checks JS syntax when Node is supplied,
requires fixed dependencies/blank example credentials, and detects known Google,
GitHub, AWS and private-key formats plus likely embedded generic credentials.
Findings show only relative file, line and rule; matching values are never printed.
Known provider formats are rejected even in tests. Generic dummy fixture strings
are permitted only in test-named files and the established test-worker module.
This is a focused source gate, not a scan of Git history, every encoding or all
possible secret formats. Review source changes too; a clean result is not proof
that no conceivable secret exists. Real .env/runtime databases are intentionally
not read or exported. Existing unlisted private files are not a release manifest.

To create another allowlisted source-only ZIP, choose a new output path:

```powershell
.\.venv\Scripts\python.exe .\ops_hygiene.py export --output .\SentinelOps_Source_Copy.zip
if ($LASTEXITCODE -ne 0) { throw 'Source export refused' }
```

The release allowlist must be updated deliberately when adding public source files.
Path traversal, credential/DB paths, symlinks and missing entries are refused.
Archive CRC and per-file SHA-256 are checked. Existing output ZIPs are not replaced.

## CI and deployment limits

ci/step11-regression.yml adds pinned-environment setup, dependency checks, Python/JS
syntax and source-secret checks, the full gate and report artifacts. It is provided
as a template in ci/, not enabled or run on GitHub. No GitHub modifications occur.
Remote CI, Ubuntu, Docker builds and container runtime have NOT been verified here.
The Windows source-only checkout and isolated ASGI demo bootstrap are verified.
The earlier localhost browser/TCP restrictions still prevent visual browser QA and
normal listener verification in the agent runtime; use the Step 10 manual checklist.

The Dockerfile is an experimental non-root recipe using Python 3.15.0 and fixed
dependencies, three explicit /data paths and safe logging. Its deny-by-default
.dockerignore excludes environment/runtime material from the build context. It
requires a writable volume owned by UID 10001; it does not provision users or
collectors. Container binding is internal 0.0.0.0; any future host publishing must
be restricted deliberately to localhost. No container was built, started or exposed
by this delivery. Base-image digests, Linux wheel compatibility and deployment
hardening require separate validation before treating a container as reproducible.

This local simulation is not a production SOC, HA service, queue, real firewall,
network traffic verifier or multi-worker deployment. SQLite locks and in-process
AI concurrency bounds are designed for the documented single local worker.
TLS, centralized secrets, external observability and production access policy are
outside this deliverable. Real enforcement adapters remain absent.

## Roadmap alignment

| Item | Delivered |
| --- | --- |
| 11.1 | Blank-credential .env.example; existing .env preserved |
| 11.2 | Fixed dependency entry point, supported/tested Python/Node versions, clean PowerShell setup |
| 11.3 | Coordinated SQLite backup, verification, new-directory restore/schema staging and reconciliation procedures |
| 11.4 | Allowlisted request/lifecycle logs with no raw credentials, URLs or exception text |
| 11.5 | Syntax/secret gate, regression integration and local CI template |
| 11.6 | Verified source-only checkout/demo bootstrap; browser/network/container/remote-CI limits explicitly retained |
