# Synthetic demo: start here

This complete source package preserves Steps 1–12. No VM is required.
The demo generates three fictional cases in disposable databases, disables live
Gemini, and performs SQLite-only responses. No real firewall collector or attack
runner is included. Fixture IP addresses are labels; no attack traffic is sent.

## Windows setup
Extract into a new folder. Open PowerShell there. Python 3.15 and Node.js are
prerequisites (the regression gate includes JavaScript tests).

```powershell
py -3.15 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
.\.venv\Scripts\python.exe .\manage.py checks --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
.\.venv\Scripts\python.exe .\manage.py demo
```

Open http://127.0.0.1:8765/dashboard. Connect using demo_analyst and the generated
one-session token printed in the terminal. No .env or API key is required.

## Present the flow
1. Show the three synthetic cases.
2. Open identity-gateway: current signed synthetic evidence and a pending request.
3. Approve with a reason, then explicitly execute the simulated response.
4. Verify the SQLite effect and show the audit record.
5. Roll back with a reason and show the final state.

The other cases demonstrate a failed attack and historical execution/rollback.
Finish within ten minutes; restart for fresh evidence. Keep tokens out of
recordings. Ctrl+C stops the server and cleans up temporary databases.
See [the demonstration script](docs/DEMO_SCRIPT.md).

## Automated end-to-end proof
```powershell
.\.venv\Scripts\python.exe .\manage.py walkthrough --output synthetic-proof.json
```
Use a new output filename each run. This checks nine stages through in-process
HTTP routes, not browser rendering or live network integration.

## GitHub
Upload the extracted source including .gitignore and .env.example. Exclude .venv,
runtime databases, .env, tokens and work folders. This archive excludes those.
Optional Gemini integration remains in source for compatibility; the synthetic
demo disables it. See [GITHUB_UPLOAD.md](GITHUB_UPLOAD.md).
