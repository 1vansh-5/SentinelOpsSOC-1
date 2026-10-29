> Historical step guide. This organized source uses `python manage.py`; see the root README for current commands. Old overlay-install paths below describe earlier deliveries.

# SentinelOps SOC 2.0 — Step 8: Gemini reliability and fallback transparency

Implementation plus offline verification for your installed Step 7 baseline. Your
selected model is **gemini-3.5-flash-lite**. No real firewall actions or GitHub edits.

**Live authentication is a separate checkpoint.** The build environment had no
configured Gemini key/model. Offline tests cannot establish provider credentials,
model access or quota. Run the live check below locally; only LIVE_VERIFIED with
exit code 0 completes that part of roadmap item 8.1. Fallback is never called a live
success. Model availability is not assumed or silently replaced with another model.

## Extract outside the project

Download the ZIP to Downloads and extract into a new folder:

```powershell
$package = "$env:USERPROFILE\Downloads\SentinelOps_Step8_Complete"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SentinelOps_Step8_Complete.zip" -DestinationPath $package
Test-Path -LiteralPath "$package\install_step8.py"
```

Test-Path must print True. If not, locate the actual installer and set `$package`
to its containing folder (there may be an extra folder from extraction):

```powershell
Get-ChildItem -LiteralPath "$env:USERPROFILE\Downloads" -Filter install_step8.py -Recurse | Select-Object FullName
```

Do not extract into app or copy snippets into modules. Use the checked installer.

## Back up and install

Stop Uvicorn and other writers. Back up your current project and separately located
databases before the upgrade:

```powershell
Set-Location -LiteralPath 'C:\Users\tripa\OneDrive\Desktop\sentinel ops 14 10 2026\sentinelops-gemini'
$project = (Get-Location).Path
$backup = $project + '-before-step8-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -LiteralPath $project -Destination $backup -Recurse
& .\.venv\Scripts\python.exe "$package\install_step8.py" --project "$project" --check
if ($LASTEXITCODE -ne 0) { throw 'Unknown source or damaged package; nothing installed' }
```

The checked environment has google-genai 1.75.0 and python-dotenv 1.2.4. Install the
supplied tested versions if needed; this changes virtual-environment packages only:

```powershell
& .\.venv\Scripts\python.exe -m pip install -r "$package\requirements-step8.txt"
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
& .\.venv\Scripts\python.exe "$package\install_step8.py" --project "$project"
if ($LASTEXITCODE -ne 0) { throw 'Installation failed; do not restart the API' }
```

The installer replaces five complete app modules: main.py, agent_loop.py,
ai_reasoner.py, gemini_planner.py and outcome_reasoner.py. It adds gemini_config.py,
gemini_models.py and gemini_runtime.py. It also adds the Step 8 runner, test files,
offline worker fixture, live-check utility, this guide and .env.step8.example at
project root. Originals are backed up under `.step8_backups`.

**Your actual .env, database files and earlier tests are not overwritten.** There
is no database schema migration in this release. Unknown source revisions cause
refusal before copying; provide the changed files for integration instead of forcing
an overwrite. A second identical installation requires zero file changes.

## Run all offline regressions

```powershell
& .\.venv\Scripts\python.exe .\run_step8_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Regression tests failed; do not restart the API' }
```

Expected: **16/16 suites passed**. All earlier 14 suites are unchanged. The two new
suites contain 19 configuration/SDK/schema/retry/deadline cases and seven actual
ASGI HTTP integration cases. STEP8_TEST_RESULTS.txt contains the output. This gate
deliberately prints that live authentication was not run.

No real provider is contacted by these tests. They include the actual installed SDK
request/response conversion over an offline HTTPX MockTransport, actual child-process
timeout/cleanup tests, and production FastAPI routes via in-process HTTPX/ASGI.
The inherited --socket-free-http flag is test-only and avoids asyncio wakeup sockets
on restricted Windows; it does not change Uvicorn's production event loop.

## Configure Gemini locally

Either merge the AI settings from .env.step8.example into your existing local .env,
or set environment variables in the SAME PowerShell window that will launch Uvicorn.
Do not replace your existing .env because it may also contain database/collector
configuration. Never commit or paste a real API key into chat.

For a key kept only in the current PowerShell session:

```powershell
$secureKey = Read-Host 'Gemini API key (hidden)' -AsSecureString
$geminiCredential = [pscredential]::new('gemini', $secureKey)
$env:GEMINI_API_KEY = $geminiCredential.GetNetworkCredential().Password
$env:GEMINI_MODEL = 'gemini-3.5-flash-lite'
$env:SENTINELOPS_GEMINI_ENABLED = '1'
$env:SENTINELOPS_AI_TIMEOUT_MS = '5000'
$env:SENTINELOPS_AI_MAX_ATTEMPTS = '2'
$env:SENTINELOPS_AI_BUDGET_MS = '20000'
$geminiCredential = $null
$secureKey = $null
```

The .env loader reads only GEMINI_API_KEY, GEMINI_MODEL and the four SENTINELOPS
AI settings shown above. It does not load/override database, collector or API-server
credentials. Existing process environment variables, including explicit empty values,
take precedence. Interpolation such as ${OTHER_VARIABLE} is disabled. Only the
project-root .env is read; no search through parent folders occurs.

The preceding triage code contained a credential-like literal in a fallback message.
This release removes it entirely. If that literal was a real credential, rotate it
with the provider; the archive and diagnostics do not reproduce it.

## Verify real authentication and model access

This optional command makes **one actual provider generation request** with a fixed,
non-sensitive connectivity prompt. It can consume provider quota. It sends no SOC
alert, incident, signing key or collector evidence, and prints no key or model text.

```powershell
& .\.venv\Scripts\python.exe .\verify_gemini_live.py
if ($LASTEXITCODE -ne 0) { throw 'Gemini live check did not verify; inspect its safe reason code' }
```

Only this form is a successful live checkpoint:

```json
{"status":"LIVE_VERIFIED","reason":"OK","model":"gemini-3.5-flash-lite","attempts":1}
```

Without a local key it exits nonzero with LIVE_NOT_VERIFIED / KEY_NOT_CONFIGURED.
Other safe reasons include PROVIDER_AUTHENTICATION, MODEL_UNAVAILABLE, PROVIDER_QUOTA,
PROVIDER_TIMEOUT, INVALID_RESPONSE and PROVIDER_REQUEST_REJECTED. These do not expose
provider exception messages. If a cold call needs longer, increase the bounded
timeout and workflow budget locally, for example 15000 and 20000 milliseconds, then
rerun deliberately. The diagnostic never automatically retries a billed request.

After the offline gate and chosen live/fallback mode are verified, start Uvicorn in
the same configured window:

```powershell
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

To run deliberately without Gemini, set SENTINELOPS_GEMINI_ENABLED=0 before starting.
The deterministic SOC workflows and earlier trust/approval/rollback controls remain
available. That mode does not satisfy the live-authentication checkpoint.

## Public reasoning labels and safe diagnostics

Triage, planner trace steps and outcomes persist the actual reasoning source. The
API exposes the same validated metadata; raw provider responses are never stored.

| Field | Meaning |
|---|---|
| ai_status=gemini | Valid provider proposal agreed with deterministic assessment or selected an allowed unused read-only tool |
| ai_status=fallback_rules | Deterministic result used; fallback_reason states why |
| ai_status=gemini_overridden | Provider proposal validated but disagreed with policy; deterministic assessment won |
| reasoning_source | Actual chosen explanation source: gemini or fallback_rules |
| evidence_refs | Valid references to supplied alert fields, prior trace steps or eligible observation tools |
| ai_metadata.provider_status | Safe transport/schema outcome, not a raw exception |
| ai_metadata.attempts | Actual outer provider attempts, zero when no request was started |
| ai_metadata.live_authentication | verified_this_call only on a validated provider response; otherwise not_verified_this_call |

For compatibility planner_status retains gemini/fallback/completed; use ai_status
and reasoning_source for uniform source display. An outcome with no eligible
observations returns NO_ELIGIBLE_EVIDENCE without a provider request. Authenticated
collector assessment remains the separate Step 7 deterministic, registry-backed
service; this advisory Gemini function cannot accept an arbitrary trusted flag.

GET /ai/status requires the existing analyst headers for any enabled viewer,
analyst or admin. It reports model, configuration state, timeout/attempt/budget bounds
and live_authentication=not_checked. It never contacts Gemini or returns the key.
Use existing analyst headers when inspecting it, as with the Step 7 read routes.

Common fallback reason codes:

| Code | Meaning/action |
|---|---|
| KEY_NOT_CONFIGURED, MODEL_NOT_CONFIGURED | Set local configuration; no network call made |
| DISABLED | Explicit deterministic mode |
| INVALID_CONFIGURATION, CONFIGURATION_UNAVAILABLE | Fix bounded settings or local dotenv dependency/file |
| SDK_UNAVAILABLE | Install the supplied tested SDK dependencies |
| PROVIDER_AUTHENTICATION | Check local credentials/permissions; not retried |
| MODEL_UNAVAILABLE | Selected model not accessible/available; no silent replacement |
| PROVIDER_QUOTA | Quota/rate denial; not automatically retried |
| PROVIDER_TIMEOUT, PROVIDER_TRANSPORT | Timeout/network problem; not automatically retried |
| PROVIDER_TRANSIENT | Server 500/502/503/504; at most one retry within budget |
| PROVIDER_BLOCKED, PROVIDER_INCOMPLETE, PROVIDER_EMPTY | Safety/empty/truncated output; deterministic fallback |
| INVALID_RESPONSE | Invalid JSON, schema, extra keys, duplicate keys or field types/lengths |
| INVALID_EVIDENCE_REFERENCE | Unknown/missing refs or repeated/disallowed tool proposal |
| MODEL_DISAGREEMENT | Deterministic policy overrode a validated proposal |
| BUDGET_EXHAUSTED, LOCAL_CAPACITY | Stop provider work immediately; deterministic fallback |
| PROMPT_TOO_LARGE, RESPONSE_TOO_LARGE | Bounded payload rejected |

## Reliability and safety boundaries

- The configured model is passed explicitly to the Gemini Developer API host. Ambient
  Vertex/enterprise settings cannot select another account or endpoint. No model
  default, discovery request, provider tool or function execution is enabled.
- Every proposal has a strict Pydantic schema with bounded strings/lists and forbidden
  extra fields. Finish status must be STOP. Duplicate JSON keys, NaN/Infinity, invalid
  roots, malformed JSON, bad types, oversized payloads and invalid refs are rejected.
- References establish what data a proposal cites; they do not prove that free-form
  model text is true. Summaries/reasons are advisory. Returned triage evidence is built
  from the referenced input fields, not accepted as newly observed model facts.
  The existing deterministic detector fixes triage assessment/confidence; outcome
  validation fixes the final conclusion. A disagreement is clearly labeled.
- Four read-only evidence tools remain allowlisted; a planner cannot repeat a used
  tool or introduce a command. Planner prompts include bounded step summaries, not
  raw prior envelopes/HMACs. Known configured secret values are redacted from prompts
  and provider text. This is not a general personal-data redaction service.
- SDK retries are disabled (attempts=1). The outer runtime permits at most two attempts
  and retries only selected transient server statuses, with a 100 ms backoff that
  consumes the same budget. Read-only generation retries cannot execute a response,
  but may incur another provider charge; use MAX_ATTEMPTS=1 if you want none.
- Default attempt deadline is 5000 ms; the investigation/planner/triage/outcome share
  one 20000 ms provider-work budget. Allowed timeout is 100–30000 ms, attempts 1–2,
  budget 500–60000 ms. Each attempt uses the lesser of its timeout and remaining budget.
- Calls run in spawned child processes. The parent enforces the deadline, terminates
  hung children and reaps handles. Cleanup can add up to roughly one second after the
  provider deadline, plus local process-start/scheduling overhead. This bounds provider
  work, not unrelated database/OS latency. Two provider workers per Python server
  process are allowed; excess work falls back immediately without queuing.
- Provider error messages/prompts/keys are not logged. Third-party worker debug
  logging is suppressed; SDK clients close before returning. Provider requests that
  were already accepted remotely might continue after local cancellation; no retry
  is made for ambiguous timeout/transport failures.
- A Gemini conclusion, including ATTACK_CONFIRMED on synthetic observations, still
  cannot authorize a simulated block. Steps 4–7 registry provenance, current evidence,
  human approval, execution idempotency and rollback checks are unchanged.
- .env and local filesystem administration remain trusted. This release adds no
  production monitoring, external audit immutability, live firewall control or
  compliance certification. Steps 9–12 remain later roadmap work.

## Verification and rollback

Read STEP8_TEST_RESULTS.txt, VERIFICATION.txt and SOURCE_PROVENANCE.json in the ZIP.
The installer and payload hashes were checked against a separate copy of the current
Step 7 project, followed by the full offline gate. Real provider authentication is
explicitly pending your local check.

For source rollback, stop Uvicorn and restore replaced files from the pre-Step-8
backup or `.step8_backups`; installation.json lists originals and new files. Restore
the earlier dependency versions too if you changed them. Step 8 makes no schema or
response-state migration, so a data restore is not inherently required; keep current
data unless you deliberately intend to restore an older database snapshot.

Implementation references: [Google structured-output documentation](https://ai.google.dev/gemini-api/docs/generate-content/structured-output)
and the installed Google GenAI SDK 1.75.0 model fields (HttpOptions timeout is in
milliseconds; HttpRetryOptions attempts includes the original request). The offline
SDK wire tests check the actual installed serializer and disabled hidden retries.
