from .api_contracts import PositiveID
"""FastAPI router factory: explicit server-controlled dependencies only."""
from fastapi import APIRouter, Header, HTTPException, Path
from pydantic import BaseModel, Field, ConfigDict
from typing import Literal
from .api_contracts import ERRORS, DecisionOut, ExecutionOut, ProposalOut, RollbackIn, RollbackOut, VerificationOut
from .simulation_lifecycle import rollback_response, verify_response
from .response_approval import decide_response
from .response_execution import execute_response
from .response_service import create_response_request

class DecisionPayload(BaseModel):
    model_config = ConfigDict(extra='forbid',json_schema_extra={'examples':[{'decision':'APPROVED','reason':'Current authenticated evidence reviewed'}]})
    decision: Literal['APPROVED','REJECTED']
    reason: str = Field(min_length=3, max_length=500)


def build_response_router(identity_store, registry_provider):
    """Call once during app setup. Never pass dependencies from HTTP input."""
    router = APIRouter(prefix='/response-requests', tags=['analyst-approvals'],responses=ERRORS)

    @router.post('/{request_id}/decision',response_model=DecisionOut)
    def submit_decision(request_id: PositiveID, payload: DecisionPayload,
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

    @router.post('/{request_id}/execute',response_model=ExecutionOut)
    def submit_execution(request_id: PositiveID,
                         idempotency_key: str | None = Header(default=None),
                         x_analyst_id: str | None = Header(default=None),
                         x_analyst_token: str | None = Header(default=None)):
        if not x_analyst_id or not x_analyst_token:
            raise HTTPException(status_code=401, detail='Analyst credentials required')
        result = execute_response(request_id, idempotency_key, x_analyst_id,
                                  x_analyst_token, identity_store, registry_provider())
        if result['status'] == 'DENIED':
            raise HTTPException(status_code=403, detail=result['reason'])
        return result

    @router.post('/for-incident/{incident_id}',response_model=ProposalOut)
    def propose_response(incident_id: PositiveID,
                         x_analyst_id: str | None = Header(default=None),
                         x_analyst_token: str | None = Header(default=None)):
        if not x_analyst_id or not x_analyst_token:
            raise HTTPException(status_code=401, detail='Analyst credentials required')
        if identity_store.authorize(x_analyst_id, x_analyst_token, 'decide') is None:
            raise HTTPException(status_code=403, detail='Analyst not authorized')
        result = create_response_request(incident_id, registry_provider())
        if result['status'] == 'REJECTED':
            raise HTTPException(status_code=403, detail=result['reason'])
        return result

    @router.post('/{request_id}/verify',response_model=VerificationOut)
    def verify_simulation(request_id: PositiveID,
                          x_analyst_id: str | None = Header(default=None),
                          x_analyst_token: str | None = Header(default=None)):
        if not x_analyst_id or not x_analyst_token:
            raise HTTPException(status_code=401,detail='Analyst credentials required')
        result = verify_response(request_id,x_analyst_id,x_analyst_token,identity_store)
        if result['status']=='DENIED':
            raise HTTPException(status_code=403,detail=result['reason'])
        return result

    @router.post('/{request_id}/rollback',response_model=RollbackOut)
    def rollback_simulation(request_id: PositiveID, payload: RollbackIn,
                            idempotency_key: str | None = Header(default=None),
                            x_analyst_id: str | None = Header(default=None),
                            x_analyst_token: str | None = Header(default=None)):
        if not x_analyst_id or not x_analyst_token:
            raise HTTPException(status_code=401,detail='Analyst credentials required')
        result = rollback_response(request_id,idempotency_key,x_analyst_id,x_analyst_token,
                                   identity_store,payload.reason)
        if result['status']=='DENIED':
            raise HTTPException(status_code=403,detail=result['reason'])
        return result

    return router
