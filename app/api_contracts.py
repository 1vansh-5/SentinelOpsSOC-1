"""Public API models. Internal database rows and credentials are never contracts."""
from typing import Any, Literal, Annotated
from fastapi import Path as APIPath
from pydantic import BaseModel, ConfigDict, Field, field_validator
from ipaddress import ip_address

PositiveID = Annotated[int,APIPath(ge=1,le=9223372036854775807)]


class Output(BaseModel):
    model_config = ConfigDict(extra='ignore')


class ErrorOut(Output):
    detail: str
    code: str


ERRORS = {code:{'model':ErrorOut} for code in (401,403,404,409,413,422,503)}


class HealthOut(Output):
    status: Literal['ok']
    service: str
    mode: Literal['simulation-first']


class AlertCreated(Output):
    id: int
    detection: dict[str,Any]


class AlertOut(Output):
    id: int
    created_at: str
    source_ip: str
    event_type: str
    target: str
    details: str
    severity: str
    status: str


class IncidentOut(Output):
    id: int
    alert_id: int
    created_at: str
    assessment: str
    confidence: str
    evidence: dict[str,Any]
    response_action: str
    response_status: str


class InvestigationOut(Output):
    incident_id: int
    alert_id: int
    triage: dict[str,Any]
    investigation: dict[str,Any]
    outcome: dict[str,Any]
    assessment: str
    response_action: str
    response_status: str


class EvidenceAccepted(Output):
    accepted: bool
    stored: bool
    incident_id: int
    evidence_id: int


class SignedRecordIn(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    incident_id: int = Field(gt=0,le=9223372036854775807)
    collector_id: str = Field(min_length=1,max_length=128)
    collected_at: str = Field(min_length=1,max_length=64)
    evidence: dict[str,Any] = Field(min_length=1)


class SignedEnvelopeIn(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    record: SignedRecordIn
    signature: str = Field(pattern='^[a-f0-9]{64}$')
    algorithm: Literal['HMAC-SHA256']


class EvidenceSummary(Output):
    id: int
    incident_id: int
    collector_id: str
    collected_at: str | None = None
    provenance: Literal['authenticated_current','untrusted_or_expired','malformed']


class ProposalOut(Output):
    status: str
    request_id: int
    incident_id: int | None = None
    source_ip: str | None = None
    requires_approval: bool | None = None
    reason: str | None = None


class DecisionOut(Output):
    status: Literal['APPROVED','REJECTED']
    request_id: int
    incident_id: int
    decided_by: str
    executed: Literal[False]


class TelemetryOut(Output):
    source: Literal['synthetic_sqlite_probe']
    expected_blocked: bool
    observed_blocked: bool
    matched: bool


class ExecutionOut(Output):
    model_config = ConfigDict(extra='ignore',json_schema_extra={'examples':[{
        'status':'SIMULATED_EXECUTED','request_id':1,'incident_id':1,'source_ip':'8.8.8.8',
        'mode':'SIMULATION_ONLY','executed':True,'block_created':True,'executed_by':'analyst_01',
        'replayed':False,'verification_status':'VERIFIED',
        'telemetry':{'source':'synthetic_sqlite_probe','expected_blocked':True,'observed_blocked':True,'matched':True}}]})
    status: Literal['SIMULATED_EXECUTED','SIMULATION_FAILED']
    request_id: int
    incident_id: int
    source_ip: str
    mode: Literal['SIMULATION_ONLY']
    executed: bool
    block_created: bool
    executed_by: str
    replayed: bool
    verification_status: Literal['VERIFIED','FAILED'] | None = None
    telemetry: TelemetryOut | None = None
    compensated: bool | None = None


class VerificationOut(Output):
    status: Literal['SIMULATION_VERIFIED','SIMULATION_VERIFICATION_FAILED']
    request_id: int
    mode: Literal['SIMULATION_ONLY']
    verification_status: str
    telemetry: TelemetryOut


class RollbackIn(BaseModel):
    model_config = ConfigDict(extra='forbid',json_schema_extra={'examples':[{'reason':'Demo complete; remove the simulated effect'}]})
    reason: str = Field(min_length=3,max_length=500)


class RollbackOut(Output):
    status: Literal['SIMULATED_ROLLED_BACK']
    request_id: int
    mode: Literal['SIMULATION_ONLY']
    rolled_back_by: str
    reason: str
    block_retained: bool
    verification_status: Literal['VERIFIED']
    telemetry: TelemetryOut
    replayed: bool


class RequestOut(Output):
    id: int
    incident_id: int
    source_ip: str
    action: str
    status: str
    requested_at: str
    decided_at: str | None
    decided_by: str | None
    lifecycle_state: str | None = None


class AuditOut(Output):
    id: int
    response_request_id: int | None
    incident_id: int
    action: str
    actor: str
    details: dict[str,Any]
    created_at: str


class BlockOut(Output):
    source_ip: str
    response_request_id: int
    blocked_at: str


class AuthObservations(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    login_attempts: int = Field(ge=1,le=1000000)
    failed_logins: int = Field(ge=0,le=1000000)
    successful_login: bool
    session_created: bool


class AppObservations(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    unauthorized_access_observed: bool
    http_status: int = Field(ge=100,le=599)


class CollectorObservation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_ip: str
    tool: Literal['authentication_logs','application_logs']
    observations: dict[str,Any]

    @field_validator('source_ip')
    @classmethod
    def address(cls,value):
        return str(ip_address(value))


class AuthInvestigationOut(Output):
    incident_id: int
    assessment: Literal['ATTACK_CONFIRMED','ATTACK_FAILED','INCONCLUSIVE']
    ai_status: Literal['fallback_rules']
    provenance: Literal['authenticated_current']
    response_action: Literal['RECOMMEND_ANALYST_REVIEW']
    executed: Literal[False]
