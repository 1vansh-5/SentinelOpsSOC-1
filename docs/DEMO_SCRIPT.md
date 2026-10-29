# Three-minute demonstration and capture plan

Start in the installed source directory:

```powershell
.\.venv\Scripts\python.exe .\manage.py demo
```

Open http://127.0.0.1:8765/dashboard. Enter the generated demo_analyst credentials
locally. Start recording only after connecting, with the credential form closed
and token-bearing terminal hidden. Do not record clipboard, credential entry or
other private windows. Keep SIMULATED / NOT PRODUCTION visible. The launcher uses
fresh temporary synthetic data and disables live Gemini.

| Time | Action | Expected state / explanation |
| --- | --- | --- |
| 0:00–0:25 | Show overview and three cases | Synthetic alert → investigation → explicit review |
| 0:25–0:55 | Open identity-gateway | ATTACK_CONFIRMED, two current authenticated records, PENDING request, no effect |
| 0:55–1:20 | Review and approve with a synthetic reason | APPROVED; block still absent; approval does not execute |
| 1:20–1:50 | Explicitly execute and verify | SIMULATED_EXECUTED, synthetic_sqlite_probe; SQLite only |
| 1:50–2:20 | Show audit and receipt | Persisted analyst decisions and simulated lifecycle |
| 2:20–2:45 | Roll back with a reason | ROLLED_BACK; block absent; rollback in audit |
| 2:45–3:00 | Show overview | Zero active effects, history retained; Ctrl+C cleans temporary databases |

Refresh before acting if the snapshot is over sixty seconds old. Evidence expires
after ten minutes: restart rather than changing clocks or freshness checks. If
needed choose --port 8766 and use that address. Do not change firewall rules.

Capture three actual dashboard images: 01-pending.png, 02-simulated-execution.png,
03-rolled-back.png. Record the dashboard with your operating system screen recorder.
Inspect images/video for tokens, private tabs, paths and notifications before
sharing. Keep captures outside the clean-source ZIP until reviewed. Do not use an
illustration in place of an actual dashboard screenshot.

## Automated API proof

```powershell
$report = ".\walkthrough-$((Get-Date).ToString('yyyyMMdd-HHmmss')).json"
.\.venv\Scripts\python.exe .\manage.py walkthrough --output $report
if ($LASTEXITCODE -ne 0) { throw 'Walkthrough failed' }
Get-Content -LiteralPath $report
```

Expected: 9/9 stages passed and cleanup PASSED. The replay uses real in-process
ASGI routes, current signed evidence and temporary databases. It also checks
authorization denials, execution retries and historical replay after rollback.
It refuses to overwrite an existing report. This is synthetic API evidence,
not a browser video, listening-server check or live Gemini authentication.

Capture status: NOT CAPTURED. Browser connections were unavailable in the
restricted build runtime. The roadmap's media item remains open until actual
screenshots/video are captured and reviewed locally.
