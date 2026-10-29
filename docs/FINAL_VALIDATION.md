# Organized source validation

This is a complete source tree through Step 12, arranged for a repository. It is
not an overlay for the original flat project. Extract into a new empty folder.
The application modules and dashboard assets remain unchanged. Tests, utilities,
historical guides and CI templates have dedicated folders. Shared repository paths
and manage.py keep imports, child processes, clean exports and launchers consistent.

Run `python manage.py checks --socket-free-http` in the pinned Python 3.15
environment with Node 20+ (tested 26.7.0). The default requires 30 jobs: seventeen
baseline suites, one gate-safety suite, three dashboard suites, four operations
suites, two handoff suites and three concurrency repetitions. Each runs in a
separate disposable source tree. Failures, timeouts and cleanup failures keep the
gate red. STEP12_TEST_RESULTS.json and .txt contain full local diagnostic reports.

The original assertions remain, with path/documentation checks adapted to the
organized layout. A source-only export is tested by the clean-setup suite, including
syntax/credential checks and an isolated synthetic HTTP demo bootstrap.

`python manage.py walkthrough --output proof.json` writes a nine-stage synthetic
API proof and refuses an existing report filename. It checks signed evidence,
authorization denials, approval, execution, retry, synthetic verification, rollback
and historical replay without recreating a removed effect. It removes temporary
databases before publishing the report.

| Evidence | Establishes | Limit |
| --- | --- | --- |
| docs/evidence/validation.json | Results of the organized source's 30 jobs and cleanup | Redacted summary, not raw logs |
| docs/evidence/walkthrough.json | Nine checked synthetic API stages | In-process ASGI, not a browser/TCP listener |
| SOURCE_MANIFEST.json | SHA-256 for delivered files except itself | Corruption detection, not signed provenance |
| Source hygiene | Allowlisted source syntax and focused credential scan | Not exhaustive or a Git-history scan |
| Editable presentation | Technical handoff and clearly stated scope | Does not establish actual browser capture |

Remaining local media task: capture and review actual dashboard screenshots and
a short video using DEMO_SCRIPT.md. Browser connections were unavailable in the
restricted build environment. The package includes no fabricated captures.
Remote CI, Docker execution and live Gemini authentication are not verified by
the offline gate. No GitHub modification or real firewall action is performed.

Runtime credentials, databases, keys, tokens, virtual environments, local logs,
backups and Git history are excluded. Share the clean source and redacted evidence,
not your private working directory. Review independently before publication.
