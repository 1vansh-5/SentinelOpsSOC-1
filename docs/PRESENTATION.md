# SentinelOps technical presentation

1. A reviewed response, from alert to rollback: a local SOC prototype with
   synthetic observations and SQLite effects.
2. Trust crosses explicit boundaries: ingestion credentials, registered collector
   signatures and analyst identity have separate responsibilities.
3. Approval never executes by itself: recheck fresh evidence and current identity
   before the effect, receipt and audit commit together.
4. Retries preserve history: idempotent execution/rollback and historical replay
   prevent duplicate effects or recreation after rollback.
5. Validation is reproducible: thirty offline jobs, three concurrency repetitions
   and nine end-to-end ASGI stages provide local evidence.
6. Claims have limits: no real firewall, real collector telemetry, production
   deployment, SOC 2 compliance claim or live provider test in this gate. Actual
   browser screenshots/video remain to be captured locally.

The companion PPTX contains editable text and diagrams. Facts derive from this
source tree, integrated tests and the supplied roadmap. No invented performance
metrics or third-party assets are used. Show the current report during a demo;
do not call an earlier run a current live check.
