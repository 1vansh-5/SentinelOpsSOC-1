# Upload the organized source to GitHub

This is a complete source tree through Step 12. Extract into a new empty folder.
Upload the extracted contents to the repository root, including .gitignore,
.dockerignore and .env.example. No earlier ZIP or patch installer is needed.
Do not merge this layout over the old flat working directory: keep its private
configuration and databases separately. This delivery does not push to GitHub.

The application is in app/, tests in tests/, commands in scripts/, logging config
in ops/, and documentation, presentation and redacted reports in docs/.
See docs/FILE_STRUCTURE.md for the full map. Keep the folder structure intact.

## Fresh local setup

Open PowerShell at the extracted repository root:

```powershell
py -3.15 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
.\.venv\Scripts\python.exe -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency check failed' }
node --version
.\.venv\Scripts\python.exe .\manage.py checks --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Regression gate failed' }
.\.venv\Scripts\python.exe .\manage.py demo
```

Use Python 3.15 and Node 20+ (tested 3.15.0 and 26.7.0). Expected gate: 30/30 jobs
passed with cleanup PASSED. The isolated demo creates temporary data and tokens,
disables live Gemini, and requires no .env. Keep its token-bearing terminal private.

| Command | Purpose |
| --- | --- |
| python manage.py checks --socket-free-http | Complete offline regression |
| python manage.py demo | Temporary synthetic dashboard demo |
| python manage.py walkthrough --output proof.json | Nine-stage redacted API proof; new filename required |
| python manage.py serve --env-file .env --check | Validate local persistent configuration |
| python manage.py serve --env-file .env | Start supported localhost server |
| python manage.py ops --help | Backup, verify, restore and staged-upgrade utilities |
| python manage.py hygiene check --node node | Source credential/syntax gate |
| python manage.py provision --help | Local analyst provisioning |
| python manage.py test test_step12_walkthrough.py | One suite from tests/ |

Configure persistent credentials locally using README.md and the operations guide
in docs/guides/. Historical guides use old flat-folder commands; the table above
gives the current entry points. Do not upload a real .env or database file.

ci/regression.yml is an optional Step 12 workflow template, not an enabled workflow.
Docker and remote CI have not been executed here. No license has been chosen.
Actual dashboard screenshots/video still require capture using docs/DEMO_SCRIPT.md.

SOURCE_MANIFEST.json hashes every delivered file except itself. The source export
allowlist remains separate from the companion PPTX and redacted evidence. Excluded:
credentials, databases, backups, caches, logs, virtual environments and Git history.
All response effects remain SQLite-only. An offline gate does not verify current
Gemini authentication or real network containment.
