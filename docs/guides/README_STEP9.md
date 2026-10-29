> Historical step guide. This organized source uses `python manage.py`; see the root README for current commands. Old overlay-install paths below describe earlier deliveries.

# SentinelOps SOC 2.0 — Step 9

This package adds an offline security regression gate. It preserves the existing
Steps 1–8 application files, the Gemini deadline fix, .env and databases. It performs
no firewall operations and sends no requests to Gemini. A live success already
reported separately is not rechecked by this gate.

## Install in PowerShell

Stop the API server. Extract the ZIP into Downloads, outside the application.
Adjust $zip only if your browser saved it with a different filename.

```powershell
$zip = "$env:USERPROFILE\Downloads\SentinelOps_Step9_Complete.zip"
$package = "$env:USERPROFILE\Downloads\SentinelOps_Step9_Complete"
if (!(Test-Path -LiteralPath $zip -PathType Leaf)) { throw "Download the Step 9 ZIP first: $zip" }
Expand-Archive -LiteralPath $zip -DestinationPath $package -Force
if (!(Test-Path -LiteralPath "$package\install_step9.py" -PathType Leaf)) { throw 'Wrong package folder' }

Set-Location 'C:\Users\tripa\OneDrive\Desktop\sentinel ops 14 10 2026\sentinelops-gemini'
.\.venv\Scripts\python.exe "$package\install_step9.py" --project . --check
if ($LASTEXITCODE -ne 0) { throw 'Baseline or package check failed; nothing installed' }
.\.venv\Scripts\python.exe "$package\install_step9.py" --project .
if ($LASTEXITCODE -ne 0) { throw 'Step 9 installation failed' }
```

The installer verifies the inspected baseline and every payload hash before writing.
Unknown existing files cause refusal. File backups go in .step9_backups. Repeat
installation makes zero changes. No database migration or environment change is required.

## One verification command

From the project folder:

```powershell
.\.venv\Scripts\python.exe .\run_step9_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Step 9 regression gate failed; inspect STEP9_TEST_RESULTS.txt' }
```

Expected final result: **21/21 test jobs passed; cleanup: PASSED**.
This means the original 17 suites, one six-case gate-safety suite, and three
independent runs of the five-case concurrency suite. It is not a count of
individual assertions. The last line correctly says live Gemini was not run.

The flag uses actual in-process HTTPX/ASGI requests, routes, validation and app
lifespan. It avoids a listening TCP server. Uvicorn, browser behavior and external
network transport are outside this gate. The normal application event loop is unchanged.

Each job receives its own disposable source copy and temporary database paths.
Production .env, databases, backups and virtual environments are not copied. AI,
collector and common credential environment variables are cleared. External DNS,
TCP connections and UDP datagrams through Python sockets are blocked in children
and inherited Python subprocesses; local IPC/loopback remains available. This is
a test guard for the trusted suite, not an operating-system sandbox for arbitrary code.
Reports contain test output and local paths; they never copy .env or runtime keys.
Failure, timeout, missing catalog entries and failed Windows cleanup return nonzero.

For more stress, use --repeat-concurrency 5 (allowed: 3 through 10). Three is the
default and minimum. A different-key race may choose any worker as its winner;
the assertion still requires exactly one success, seven denials, one receipt,
one block and one success audit. Same-key races require one first execution and
seven historical retries. Rollback races require one rollback and no recreated block.
Collector-key rotation also requires one persistent winner, exactly two key-history
entries and one rotation audit; revocation must wait for an active execution reservation.
No assertions depend on thread order and failed runs are never retried into a pass.

## Coverage mapped to the roadmap

| Requirement | Gate coverage |
| --- | --- |
| 9.1 Group tests | unit_and_security, sqlite_and_transactions, api_integration, gate_safety, concurrency; JSON group labels |
| 9.2 Security regressions | Step 2 malformed input, HMAC tampering, replay and freshness; Step 3 revocation, rotation and key history; Step 4 provenance/trust; Steps 5–8 identity, evidence binding, role changes and AI cannot authorize |
| 9.3 Failure injection | Step 6 execution audit trigger abort restores receipt, block, request and incident; Step 7 rollback audit failure and abrupt child-process exit before commit; AI quota/timeout/invalid JSON |
| 9.4 Windows cleanup | separate SQLite files, existing handle cleanup assertions, per-job recursive removal and final cleanup checked as part of gate success |
| 9.5 Concurrency | existing tests retained; execution, rollback, collector-key rotation and revocation-reservation assertions repeated three times in independent processes and temporary directories |
| 9.6 One command and CI | run_step9_checks.py; ci/step9-regression.yml for Windows and Ubuntu |

The JSON and text reports overwrite prior reports in the project root. Database
and source files in the real application remain untouched. Temporary copies are
removed after each job; cleanup errors fail the run and may leave a work/step9-checks-*
folder for diagnosis. A deliberately forced operating-system shutdown is outside
the test runner's cleanup guarantee.

## Fresh Python environment (optional)

Keep the working .venv. For a separate dependency check using installed Python 3.15:

```powershell
py -3.15 -m venv .venv-step9-check
.\.venv-step9-check\Scripts\python.exe -m pip install -r .\requirements-step9-lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
.\.venv-step9-check\Scripts\python.exe -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency check failed' }
.\.venv-step9-check\Scripts\python.exe .\run_step9_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Clean-environment regression failed' }
```

requirements-step9.txt records exact direct test dependencies. The lock file also
pins the complete resolved Python 3.15 Windows dependency set. It includes
python-dotenv and httpx explicitly; the old requirements.txt remains unchanged.
Dependency installation requires package-index access or a local wheel cache;
the subsequent gate runs offline. Native dependencies on other platforms must
be available there; the Ubuntu CI job is supplied but has not been executed here.

## CI supplied without changing GitHub

ci/step9-regression.yml is a complete workflow template. It checks out the source,
installs pinned dependencies, runs the same command on Windows and Ubuntu, and
uploads reports even on failure. No API keys or GitHub write token are needed.
To enable it later, place it at .github/workflows/step9-regression.yml in a
repository containing the complete installed application and tests, then publish
those files yourself. This delivery does not edit GitHub or enable a remote job.
Remote CI success remains unverified until that workflow runs.

## Files added (complete files)

- run_step9_checks.py — grouped runner and reports
- step9_offline_guard.py — external network guard for test subprocesses
- test_step9_gate.py — runner isolation and failure-handling tests
- test_step9_concurrency.py — four strict barrier races and a revocation-reservation test
- requirements-step9.txt and requirements-step9-lock.txt — fixed test dependencies
- ci/step9-regression.yml — CI workflow template
- README_STEP9.md — this guide

No existing application or Step 1–8 test file is replaced. Package-root installer,
manifest and verification reports stay in the extracted package folder.
