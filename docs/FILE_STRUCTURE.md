# Repository layout

```text
SentinelOps/
├── README.md                 Current setup, API overview and demo instructions
├── GITHUB_UPLOAD.md          Upload and fresh-checkout instructions
├── manage.py                 Common command entry point
├── project_paths.py          Shared repository paths and test-copy support
├── requirements.txt          Dependency entry point
├── requirements-step9-lock.txt
├── release-files.json        Allowlisted application source
├── SOURCE_MANIFEST.json      Hashes for the delivered archive
├── .env.example              Blank credential template
├── .gitignore
├── .dockerignore
├── Dockerfile                Experimental, unexecuted recipe
├── app/                      Backend services, models and API routes
│   └── dashboard/            HTML, CSS and JavaScript assets
├── tests/                    Regression suites and offline test helpers
├── scripts/                  Launchers, gate runners and operator utilities
├── ops/                      Safe server logging configuration
├── ci/                       Optional regression workflow template
└── docs/
    ├── ARCHITECTURE.md
    ├── THREAT_MODEL.md
    ├── DEMO_SCRIPT.md
    ├── FINAL_VALIDATION.md
    ├── PRESENTATION.md
    ├── FILE_STRUCTURE.md
    ├── SentinelOps_Technical_Handoff.pptx
    ├── evidence/             Redacted validation and walkthrough results
    └── guides/               Historical step-by-step delivery guides
```

Run commands from the repository root. `manage.py --help` lists the commands.
Use `manage.py checks --socket-free-http` for the complete gate, `manage.py demo`
for the temporary dashboard demonstration, and `manage.py serve` for the supported
persistent launcher. `manage.py ops --help` covers database operations.

All original application modules remain in app/. Tests and operator scripts have
dedicated folders. Historical guides describe earlier flat-folder overlays and
are clearly labeled; README.md and GITHUB_UPLOAD.md describe this layout.

Runtime data is private and created locally. The archive excludes .env, keys,
tokens, databases, caches, virtual environments, logs, backups and Git history.
