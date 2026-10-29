"""FastAPI router factory: explicit server-controlled dependencies only."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field
from .response_approval import decide_response

class DecisionPayload(BaseModel):
    decision: str
    reason: str = Field(min_length=3, max_length=500)


def build_response_router(identity_store, registry_provider):
    """Call once during app setup. Never pass dependencies from HTTP input."""
    router = APIRouter(prefix='/response-requests', tags=['analyst-approvals'])

    @router.post('/{request_id}/decision')
    def submit_decision(request_id: int, payload: DecisionPayload,
                        x_analyst_id: str | None = Header(default=None),
                        x_analyst_token: str | None = Header(default=None)):
        if not x_analyst_id or not x_analyst_token:
            raise HTTPException(status_code=401, detail='Analyst credentials required')
        result = decide_response(request_id, payload.decision, x_analyst_id,
                                 x_analyst_token, identity_store,
                                 registry_provider(), payload.reason)
        if result['status'] == 'DENIED':
            raise HTTPException(status_code=403, detail=result['reason'])
        return result

    return router
