> Historical step guide. This organized source uses `python manage.py`; see the root README for current commands. Old overlay-install paths below describe earlier deliveries.

# Step 12: final validation and portfolio handoff

Includes the final integrated gate, nine-stage synthetic API replay, replacement
README, architecture, threat model, release checklist and demo/capture plan.
The editable presentation is a separate companion. Actual dashboard screenshots
and video remain pending local capture because browser connections were unavailable
in the restricted build runtime.

## Install on the verified Step 11 project

Stop the API. Save SentinelOps_Step12_Complete.zip in Downloads, then paste:

```powershell
$zip = "$env:USERPROFILE\Downloads\SentinelOps_Step12_Complete.zip"
$package = "$env:USERPROFILE\Downloads\SentinelOps_Step12_Complete"
if (!(Test-Path -LiteralPath $zip -PathType Leaf)) { throw "Download the Step 12 ZIP first: $zip" }
Expand-Archive -LiteralPath $zip -DestinationPath $package -Force
if (!(Test-Path -LiteralPath "$package\install_step12.py" -PathType Leaf)) { throw 'Installer missing; check the extracted folder' }
Set-Location 'C:\Users\tripa\OneDrive\Desktop\sentinel ops 14 10 2026\sentinelops-gemini'
.\.venv\Scripts\python.exe "$package\install_step12.py" --project . --check
if ($LASTEXITCODE -ne 0) { throw 'Unknown source or damaged package; nothing installed' }
.\.venv\Scripts\python.exe "$package\install_step12.py" --project .
if ($LASTEXITCODE -ne 0) { throw 'Step 12 installation failed' }
.\.venv\Scripts\python.exe .\run_step12_checks.py --socket-free-http
if ($LASTEXITCODE -ne 0) { throw 'Gate failed; inspect STEP12_TEST_RESULTS.txt' }
$report = ".\walkthrough-$((Get-Date).ToString('yyyyMMdd-HHmmss')).json"
.\.venv\Scripts\python.exe .\run_step12_walkthrough.py --output $report
if ($LASTEXITCODE -ne 0) { throw 'Final walkthrough failed' }
```

Expected: **30/30 test jobs passed; cleanup: PASSED**, then **9/9 walkthrough stages
passed; cleanup: PASSED**. No dependency changes are needed for your verified .venv.

Extract into its own Downloads folder; run that installer against the project
root. Do not replace the entire project with the outer package folder.
Replaced complete files: **README.md and release-files.json**. Originals are backed
up under .step12_backups. Added: run_step12_checks.py, run_step12_walkthrough.py,
test_step12_walkthrough.py, test_step12_contracts.py, README_STEP12.md and five docs/
files. Application modules, prior tests, .env, databases and credentials are
unchanged. Unknown source differences are refused before any write.

## Local capture

```powershell
.\.venv\Scripts\python.exe .\run_step10_demo.py
```

Open http://127.0.0.1:8765/dashboard and follow docs/DEMO_SCRIPT.md. Connect locally,
then close the credential form and hide the token-bearing terminal before recording.
Capture pending evidence, execution/verification and completed rollback. Ctrl+C
removes temporary demo databases. Offline reports do not substitute for media.

For a fresh source folder, use SentinelOps_Step12_Clean_Source.zip and README.md.
It excludes runtime secrets/data and Git history. No GitHub modification, real
firewall change or live provider request was performed.
