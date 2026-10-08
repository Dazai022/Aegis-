from __future__ import annotations

import enum
import uuid
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ToolName(str, enum.Enum):
    GITHUB   = "github"
    TERMINAL = "terminal"


class DecisionAction(str, enum.Enum):
    ALLOW            = "ALLOW"
    BLOCK            = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RiskLevel(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyEffect(str, enum.Enum):
    ALLOW            = "ALLOW"
    BLOCK            = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


# -- Execution request / response ------------------------------------------

class ExecuteRequest(BaseModel):
    tool: ToolName
    action: str = Field(..., min_length=1, max_length=255)
    parameters: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=128)

    @field_validator("action")
    @classmethod
    def _no_blank_action(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("action must not be blank")
        return cleaned


class ExecuteResponse(BaseModel):
    request_id: uuid.UUID
    correlation_id: str
    decision: DecisionAction
    reason: str
    risk_score: int
    risk_level: RiskLevel
    policy_name: str | None = None
    matched_rule_id: str | None = None
    requires_approval: bool
    approval_id: uuid.UUID | None = None


# -- Policy schemas ---------------------------------------------------------

class PolicyRule(BaseModel):
    rule_id: str
    name: str
    description: str = ""
    priority: int = Field(..., ge=0)
    enabled: bool = True
    tool: ToolName | None = None
    action_pattern: str | None = None
    parameter_constraints: dict[str, Any] = Field(default_factory=dict)
    effect: PolicyEffect
    reason: str = ""


class PolicyEvalResult(BaseModel):
    matched: bool
    effect: PolicyEffect
    rule: PolicyRule | None = None
    reason: str


# -- Risk schemas -----------------------------------------------------------

class RiskSignal(BaseModel):
    name: str
    weight: int
    triggered: bool
    reason: str
    evidence: str = ""


class RiskResult(BaseModel):
    score: int = Field(..., ge=0, le=100)
    level: RiskLevel
    signals: list[RiskSignal]
    reasoning: str


# -- Context schemas --------------------------------------------------------

class ContextFinding(BaseModel):
    name: str
    description: str
    severity: str = "info"
    evidence: str = ""


class ContextResult(BaseModel):
    findings: list[ContextFinding]
    first_time_tool: bool
    high_frequency: bool
    unusual_action_pattern: bool
    prior_failures: bool
    recent_blocks: bool
    history_window_requests: int = 0
    summary: str


# -- Decision schemas -------------------------------------------------------

class DecisionPrecedence(int, enum.Enum):
    BLOCK_POLICY       = 1
    HIGH_CRITICAL_RISK = 2
    APPROVAL_POLICY    = 3
    ALLOW_LOW_RISK     = 4
    FAIL_CLOSED        = 5


class DecisionResult(BaseModel):
    action: DecisionAction
    precedence: DecisionPrecedence
    reason: str
    policy_result: PolicyEvalResult
    risk_result: RiskResult
    context_result: ContextResult
    error: str | None = None
