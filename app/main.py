from .api_contracts import PositiveID
"""SentinelOps simulation-first API with authenticated collector ingestion."""
import hmac
import json
import os
from contextlib import asynccontextmanager, closing
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from .api_contracts import (ERRORS, HealthOut, AlertOut, AlertCreated, IncidentOut,
                            InvestigationOut, EvidenceAccepted, AuthInvestigationOut, SignedEnvelopeIn)
from .api_security import operator, register_errors, PublicBoundary
from .authenticated_investigation import investigate_authenticated
from .gemini_runtime import workflow_budget
from .gemini_config import public_settings
from .gemini_models import AIStatusOut

from .database import connect, init_db
from .schemas import AlertIn, SimulateIn
from .detection import classify_alert
from .ai_reasoner import analyze_alert
from .agent_loop import run_investigation
from .outcome_reasoner import assess_outcome
from .incident_evidence_store import init_incident_evidence_store
from .authenticated_evidence_service import ingest_authenticated_evidence
from .persistent_collector_registry import PersistentCollectorRegistry

ALLOWED_ORIGINS = [x.strip() for x in os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500"
).split(",") if x.strip()]


class SignedEvidenceSubmission(BaseModel):
    """Untrusted client envelope; signature and incident ID are verified server-side."""
    model_config = ConfigDict(extra='forbid')
    envelope: SignedEnvelopeIn


def build_registry():
    """Load only server-configured collector credentials; never accept keys in requests."""
    collector_id = os.getenv("SENTINELOPS_COLLECTOR_ID", "").strip()
    collector_key = os.getenv("SENTINELOPS_COLLECTOR_KEY", "")
    if not collector_id or not collector_key:
        return None
    if len(collector_key) < 32:
        raise RuntimeError("Collector key must be at least 32 characters")
    path = Path(os.getenv("SENTINELOPS_REGISTRY_DB", "collector_registry.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    registry = PersistentCollectorRegistry(str(path))
    # load_collector_key() returns None on success and raises ValueError
    # on a missing, revoked, or mismatched collector. Do not interpret
    # its successful None return as an authentication failure.
    try:
        registry.load_collector_key(collector_id, collector_key)
    except ValueError as exc:
        raise RuntimeError(
            "Configured collector is not registered or active with this key"
        ) from exc
    return registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from .response_execution import init_execution_store
    init_execution_store()
    init_incident_evidence_store()
    app.state.collector_registry = build_registry()
    yield
    app.state.collector_registry = None


app = FastAPI(title="SentinelOps SOC 2.0", version="0.11.0", lifespan=lifespan,
              responses=ERRORS,description='Simulation-only SOC. Analyst credentials protect operational reads and decisions. See README_STEP7.md for the HTTP walkthrough; /docs provides typed contracts. No live firewall actions.')
register_errors(app)
app.add_middleware(PublicBoundary)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "X-Analyst-Id", "X-Analyst-Token", "Idempotency-Key"],
)


def require_key(x_api_key: str | None):
    api_key = os.getenv("SENTINELOPS_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="Server API key is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key.encode('utf-8'), api_key.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


def save_alert(payload: AlertIn):
    result = classify_alert(payload.event_type, payload.details, payload.severity)
    with closing(connect()) as conn:
        with conn:
            cur = conn.execute(
                "INSERT INTO alerts (source_ip,event_type,target,details,severity,status) VALUES (?,?,?,?,?,?)",
                (payload.source_ip, payload.event_type, payload.target, payload.details,
                 payload.severity, "needs_review" if result["needs_review"] else "new"),
            )
            alert_id = cur.lastrowid
    return {"id": alert_id, "detection": result}


@app.get("/health",response_model=HealthOut)
def health():
    return {"status": "ok", "service": "sentinelops-api", "mode": "simulation-first"}


@app.get("/alerts",response_model=list[AlertOut])
def list_alerts(after_id: int = Query(default=0,ge=0,le=9223372036854775807),limit: int = Query(default=100,ge=1,le=100),
                x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
    operator(analyst_store,x_analyst_id,x_analyst_token)
    with closing(connect()) as conn:
        rows = conn.execute("SELECT * FROM alerts WHERE id>? ORDER BY id LIMIT ?",(after_id,limit)).fetchall()
    return [dict(r) for r in rows]


@app.get("/incidents",response_model=list[IncidentOut])
def list_incidents(after_id: int = Query(default=0,ge=0,le=9223372036854775807),limit: int = Query(default=100,ge=1,le=100),
                   x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
    operator(analyst_store,x_analyst_id,x_analyst_token)
    with closing(connect()) as conn:
        rows = conn.execute("SELECT * FROM incidents WHERE id>? ORDER BY id LIMIT ?",(after_id,limit)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            item["evidence"] = json.loads(item["evidence"])
            if not isinstance(item['evidence'],dict):
                item['evidence'] = {'error':'Invalid stored evidence'}
        except (TypeError, ValueError):
            item["evidence"] = {"error": "Invalid stored evidence"}
        output.append(item)
    return output


@app.post("/webhook/alert",response_model=AlertCreated)
def receive_sensor_alert(payload: AlertIn, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    return save_alert(payload)


@app.post("/simulate/attack",response_model=AlertCreated)
def simulate_attack(payload: SimulateIn, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    if payload.scenario == "brute_force":
        alert = AlertIn(source_ip=payload.source_ip, event_type="failed_login",
                        target=payload.target, details="Synthetic demo: repeated failed logins",
                        severity="high")
    elif payload.scenario == "sql_injection":
        alert = AlertIn(source_ip=payload.source_ip, event_type="sql_injection",
                        target=payload.target, details="Synthetic demo: possible SQL injection pattern",
                        severity="high")
    else:
        alert = AlertIn(source_ip=payload.source_ip, event_type="successful_login",
                        target=payload.target, details="Synthetic demo: normal login; no preceding failures",
                        severity="low")
    return save_alert(alert)


@app.post('/alerts/{alert_id}/investigate',response_model=InvestigationOut)
@app.post("/incidents/{alert_id}/investigate",response_model=InvestigationOut)
def investigate(alert_id: PositiveID, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = dict(row)
    with workflow_budget():
        investigation = run_investigation(alert, max_steps=4, scenario=None)
        triage = analyze_alert(alert)
        outcome = assess_outcome(investigation)
    final_assessment = outcome["assessment"]
    response_action = "NO_AUTOMATIC_ACTION"
    response_status = "SIMULATED_ONLY"
    if triage["assessment"] in ("SUSPICIOUS_ACTIVITY", "POSSIBLE_COMPROMISE", "ATTACK_CONFIRMED"):
        response_action = "RECOMMEND_ANALYST_REVIEW"
    stored_evidence = {"triage": triage, "investigation": investigation, "outcome": outcome}
    with closing(connect()) as conn:
        with conn:
            cur = conn.execute(
                """INSERT INTO incidents
                   (alert_id,assessment,confidence,evidence,response_action,response_status)
                   VALUES (?,?,?,?,?,?)""",
                (alert_id, final_assessment, "low", json.dumps(stored_evidence),
                 response_action, response_status),
            )
            incident_id = cur.lastrowid
            conn.execute("UPDATE alerts SET status='investigated' WHERE id=?", (alert_id,))
    return {"incident_id": incident_id, "alert_id": alert_id, "triage": triage,
            "investigation": investigation, "outcome": outcome,
            "assessment": final_assessment, "response_action": response_action,
            "response_status": response_status}


@app.post("/incidents/{incident_id}/evidence/submit",response_model=EvidenceAccepted)
def submit_authenticated_evidence(
    incident_id: PositiveID,
    submission: SignedEvidenceSubmission,
    x_api_key: str | None = Header(default=None),
):
    """Authenticated submission for an EXISTING incident. No automatic response.

    Uses the existing API key for endpoint access; a collector's independent
    HMAC signature is still mandatory and checked by the registry.
    """
    require_key(x_api_key)
    if incident_id <= 0:
        raise HTTPException(status_code=422, detail="Invalid incident ID")
    registry = getattr(app.state, "collector_registry", None)
    if registry is None:
        raise HTTPException(status_code=503, detail="Collector registry is not configured")
    # Preflight: avoid consuming a valid signature when the incident is absent.
    with closing(connect()) as conn:
        incident = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = ingest_authenticated_evidence(incident_id, submission.envelope.model_dump(), registry)
    if not result.get("accepted") or not result.get("stored"):
        # Never expose signing material, database internals or envelope contents.
        raise HTTPException(status_code=409, detail="Evidence rejected or could not be stored")
    return {"accepted": True, "stored": True,
            "incident_id": incident_id, "evidence_id": result["evidence_id"]}


# Step 5 decisions and Step 6 execution use only server-owned dependencies.
from .analyst_identity import AnalystIdentityStore
from .response_routes import build_response_router
analyst_store = AnalystIdentityStore(os.getenv('SENTINELOPS_ANALYST_DB', 'analysts.sqlite'))
app.include_router(build_response_router(
    analyst_store, lambda: getattr(app.state, 'collector_registry', None)))

from .api_read_routes import build_read_router
app.include_router(build_read_router(analyst_store,lambda:getattr(app.state,'collector_registry',None)))


@app.post('/incidents/{incident_id}/investigate-authenticated',response_model=AuthInvestigationOut)
def authenticated_review(incident_id: PositiveID,
                         x_analyst_id: str | None = Header(default=None),x_analyst_token: str | None = Header(default=None)):
    """Assess two signed collector observations; never approve or execute a response."""
    operator(analyst_store,x_analyst_id,x_analyst_token,'decide')
    return investigate_authenticated(incident_id,getattr(app.state,'collector_registry',None),x_analyst_id)


@app.get('/ai/status',response_model=AIStatusOut)
def ai_configuration_status(x_analyst_id: str | None = Header(default=None),
                            x_analyst_token: str | None = Header(default=None)):
    """Configuration metadata only; this endpoint never contacts Gemini."""
    operator(analyst_store,x_analyst_id,x_analyst_token)
    return public_settings()


from .dashboard_routes import build_dashboard_router, DashboardHeaders
app.include_router(build_dashboard_router(analyst_store,lambda:getattr(app.state,'collector_registry',None)))
app.add_middleware(DashboardHeaders)

from .structured_logging import OperationalLogging
app.add_middleware(OperationalLogging)
