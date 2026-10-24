from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any
from datetime import datetime

SourceType = Literal[
    "email_body",
    "email_subject",
    "user_prompt",
    "retrieved_document",
    "tool_output",
    "unknown",
]

RiskBand = Literal["low", "medium", "high", "critical"]
PolicyDecision = Literal["allow", "flag", "review", "block"]

AttackCategory = Literal[
    "instruction_override",
    "prompt_extraction",
    "data_exfiltration",
    "unauthorized_action",
    "obfuscation",
    "benign",
]

ReviewerLabel = Literal["true_positive", "false_positive", "false_negative", "uncertain"]


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Untrusted text payload to inspect")
    source_type: SourceType = Field(default="email_body", description="Origin channel of the text")
    application_id: Optional[str] = Field(default="default_app", description="Identifier of calling application")


class EvidenceSpan(BaseModel):
    category: str
    start: int = Field(..., ge=0, description="0-indexed start character offset")
    end: int = Field(..., ge=0, description="0-indexed end character offset")
    reason: str = Field(..., description="Human-readable justification for the flag")


class AnalyzeResponse(BaseModel):
    analysis_id: str
    application_id: str
    timestamp: str
    source_type: str
    label: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_band: RiskBand
    decision: PolicyDecision
    categories: List[str]
    evidence: List[EvidenceSpan]
    explanation: str
    detector_version: str
    policy_version: str
    latency_ms: float
    text: Optional[str] = None


class FeedbackRequest(BaseModel):
    analysis_id: str
    reviewer_label: ReviewerLabel
    notes: Optional[str] = None
    reviewer_id: Optional[str] = "analyst_admin"


class FeedbackResponse(BaseModel):
    feedback_id: str
    analysis_id: str
    reviewer_label: str
    status: str = "recorded"
    timestamp: str


class PolicyUpdate(BaseModel):
    low_max: int = Field(..., ge=0, le=50)
    medium_max: int = Field(..., ge=20, le=80)
    high_max: int = Field(..., ge=50, le=95)
    store_raw_text: Optional[bool] = False


class PolicyResponse(BaseModel):
    policy_version: str
    low_max: int
    medium_max: int
    high_max: int
    store_raw_text: bool
    updated_at: str


class HealthResponse(BaseModel):
    status: str
    version: str
    models_ready: bool
    database_connected: bool
    uptime_seconds: float
