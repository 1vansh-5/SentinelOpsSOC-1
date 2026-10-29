"""Strict bounded provider proposals; validated before storage or use."""
from typing import Literal, Annotated
from pydantic import BaseModel, ConfigDict, Field

Text = Annotated[str,Field(min_length=1,max_length=500)]
AlertRef = Literal['source_ip','event_type','target','details','severity']
Tool = Literal['asset_inventory','authentication_logs','application_logs','vulnerability_lookup']


class Proposal(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True,str_strip_whitespace=True)


class TriageProposal(Proposal):
    assessment: Literal['ATTEMPT_DETECTED','SUSPICIOUS_ACTIVITY','POSSIBLE_COMPROMISE','ATTACK_CONFIRMED','ATTACK_FAILED','INCONCLUSIVE']
    confidence: Literal['low','medium','high']
    summary: str = Field(min_length=1,max_length=1200)
    evidence: list[Text] = Field(min_length=1,max_length=10)
    evidence_refs: list[AlertRef] = Field(min_length=1,max_length=5)
    recommended_next_steps: list[Text] = Field(min_length=1,max_length=10)


class PlannerProposal(Proposal):
    tool: Tool
    reason: Text
    evidence_refs: list[Annotated[str,Field(pattern=r'^(alert\.(source_ip|event_type|target|details|severity)|trace\.[1-4])$')]] = Field(min_length=1,max_length=5)


class OutcomeProposal(Proposal):
    assessment: Literal['ATTACK_CONFIRMED','ATTACK_FAILED','INCONCLUSIVE']
    reason: str = Field(min_length=1,max_length=800)
    evidence_refs: list[Tool] = Field(min_length=1,max_length=4)


class LiveProbe(Proposal):
    status: Literal['OK']


class AIStatusOut(BaseModel):
    configured: bool
    configuration_status: str
    model: str | None
    attempt_timeout_ms: int
    max_attempts: int
    workflow_budget_ms: int
    live_authentication: Literal['not_checked']
    mode: Literal['SIMULATION_ONLY']
