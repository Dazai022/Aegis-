from __future__ import annotations
import hashlib, json, uuid
from datetime import datetime, timedelta
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.audit.logger import audit_logger
from app.context.engine import context_engine
from app.decisions.engine import decision_engine
from app.models.agent import Agent
from app.models.api_key import ApiKey, ApiKeyStatus
from app.models.approval import Approval, ApprovalStatus
from app.models.context_assessment import ContextAssessment
from app.models.decision import Decision
from app.models.execution_request import ExecutionRequest, ExecutionState
from app.models.risk_assessment import RiskAssessment
from app.models.tool_execution import ToolExecution, ToolExecutionStatus
from app.policies.engine import policy_engine
from app.risk.engine import risk_engine
from app.schemas.execution import (
    ContextResult, DecisionAction, DecisionPrecedence, DecisionResult,
    ExecuteRequest, ExecuteResponse, PolicyEffect, PolicyEvalResult,
    RiskLevel, RiskResult, ToolName,
)
from app.security.crypto import HmacHelper
from app.core import logging as aegis_logging
from app.core.config import settings

log = aegis_logging.logger

_REDACT = frozenset(["password","passwd","token","secret","api_key","apikey","private_key","jwt","bearer","authorization","access_key"])


class AuthenticationError(Exception): pass


def _input_digest(tool: str, action: str, params: dict[str, Any]) -> str:
    canonical = json.dumps({"tool": tool, "action": action, "params": params}, sort_keys=True, separators=(",",":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _sanitize_params(params: dict[str, Any], depth: int = 4) -> dict[str, Any]:
    if depth <= 0: return {}
    result: dict[str, Any] = {}
    for k, v in params.items():
        if k.lower() in _REDACT: result[k] = "[REDACTED]"
        elif isinstance(v, dict): result[k] = _sanitize_params(v, depth - 1)
        else: result[k] = v
    return result


class GatewayService:
    """Full Aegis security pipeline: authenticate -> intercept -> policy -> risk -> context -> decide -> execute -> audit."""

    async def authenticate_agent(self, api_key_plain: str, session: AsyncSession) -> Agent:
        if not api_key_plain: raise AuthenticationError("Missing API key")
        key_hash = HmacHelper.api_key_hash(api_key_plain)
        r = await session.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
        api_key_obj = r.scalar_one_or_none()
        if not api_key_obj: raise AuthenticationError("Invalid API key")
        if api_key_obj.status != ApiKeyStatus.ACTIVE: raise AuthenticationError(f"API key is {api_key_obj.status.value}")
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow(): raise AuthenticationError("API key expired")
        ar = await session.execute(select(Agent).where(Agent.id == api_key_obj.agent_id))
        agent = ar.scalar_one_or_none()
        if not agent or agent.status.value != "active": raise AuthenticationError("Agent inactive")
        return agent

    async def _history(self, agent_id: uuid.UUID, tool: ToolName, session: AsyncSession) -> dict:
        tr = await session.execute(select(ExecutionRequest.tool_name).where(ExecutionRequest.agent_id == agent_id).distinct())
        tools_ever = [r[0] for r in tr.all()]
        tar = await session.execute(select(ExecutionRequest.tool_name).where(ExecutionRequest.agent_id == agent_id, ExecutionRequest.tool_name == tool.value).order_by(ExecutionRequest.created_at.desc()).limit(100))
        recent_tool = [r[0] for r in tar.all()]
        aar = await session.execute(select(ExecutionRequest.tool_name, ExecutionRequest.tool_name).where(ExecutionRequest.agent_id == agent_id).order_by(ExecutionRequest.created_at.desc()).limit(100))
        recent_all = [(r[0], r[1]) for r in aar.all()]
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        cr = await session.execute(select(func.count(ExecutionRequest.id)).where(ExecutionRequest.agent_id == agent_id, ExecutionRequest.created_at >= one_hour_ago))
        requests_last_hour = cr.scalar_one() or 0
        fr = await session.execute(select(func.count(ExecutionRequest.id)).where(ExecutionRequest.agent_id == agent_id, ExecutionRequest.state == ExecutionState.FAILED))
        recent_failures = fr.scalar_one() or 0
        br = await session.execute(select(func.count(ExecutionRequest.id)).where(ExecutionRequest.agent_id == agent_id, ExecutionRequest.state == ExecutionState.BLOCKED))
        recent_blocks = br.scalar_one() or 0
        return dict(tools_ever_used=tools_ever, recent_tool_actions=recent_tool, recent_all_actions=recent_all, requests_last_hour=requests_last_hour, recent_failures=recent_failures, recent_blocks=recent_blocks)

    async def _run_tool(self, tool: ToolName, action: str, params: dict, exec_req: ExecutionRequest, decision_row: Decision, approval: Approval | None, session: AsyncSession) -> ToolExecution:
        """Actually dispatch to the tool adapter after ALLOW decision."""
        te = ToolExecution(
            id=uuid.uuid4(), request_id=exec_req.id, decision_id=decision_row.id,
            approval_id=approval.id if approval else None,
            adapter_name=tool.value, command=action,
            args_snapshot=_sanitize_params(params),
            status=ToolExecutionStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.add(te)
        await session.flush()
        try:
            result_data = await self._dispatch(tool, action, params, session)
            te.status = ToolExecutionStatus.SUCCESS
            te.exit_code = result_data.get("exit_code", 0)
            te.output_preview = str(result_data.get("output", ""))[:500]
        except Exception as exc:
            log.exception("Tool execution error")
            te.status = ToolExecutionStatus.FAILED
            te.exit_code = -1
            te.error_message = str(exc)[:500]
        te.finished_at = datetime.utcnow()
        return te

    async def _dispatch(self, tool: ToolName, action: str, params: dict, session: AsyncSession) -> dict:
        if tool == ToolName.GITHUB:
            from app.tools.github.adapter import github_adapter
            conn_id = params.get("connection_id")
            if not conn_id: return {"output": "No connection_id in parameters", "exit_code": 1}
            try:
                import uuid as _uuid
                result = await github_adapter.execute(session, _uuid.UUID(str(conn_id)), action, params)
                return {"output": result, "exit_code": 0}
            except Exception as e:
                return {"output": str(e), "exit_code": 1}
        elif tool == ToolName.TERMINAL:
            from app.tools.terminal.adapter import terminal_adapter
            cmd = params.get("command", "")
            result = terminal_adapter.execute(cmd)
            if result.blocked:
                return {"output": result.error or "Hard-blocked", "exit_code": -1, "blocked": True}
            return {"output": result.stdout or result.stderr, "exit_code": result.exit_code, "duration_ms": result.duration_ms}
        return {"output": f"Unknown tool: {tool}", "exit_code": 1}

    async def process(self, request: ExecuteRequest, agent: Agent, correlation_id: str, session: AsyncSession) -> ExecuteResponse:
        safe_params = _sanitize_params(request.parameters)
        digest = _input_digest(request.tool.value, request.action, request.parameters)
        exec_req = ExecutionRequest(
            id=uuid.uuid4(), agent_id=agent.id, correlation_id=correlation_id,
            idempotency_key=request.idempotency_key, tool_name=request.tool.value,
            tool_args=safe_params, state=ExecutionState.EVALUATING, input_digest=digest,
        )
        session.add(exec_req)
        await session.flush()

        history = await self._history(agent.id, request.tool, session)
        decision: DecisionResult | None = None
        policy_result: PolicyEvalResult | None = None
        risk_result: RiskResult | None = None
        context_result: ContextResult | None = None

        try:
            policy_result = policy_engine.evaluate(tool=request.tool, action=request.action, parameters=request.parameters)
            risk_result = risk_engine.assess(tool=request.tool, action=request.action, parameters=request.parameters, recent_tool_actions=history["recent_tool_actions"], tools_ever_used=history["tools_ever_used"], requests_last_hour=history["requests_last_hour"])
            context_result = context_engine.analyse(tool=request.tool, action=request.action, tools_ever_used=history["tools_ever_used"], recent_tool_actions=history["recent_tool_actions"], recent_all_actions=history["recent_all_actions"], requests_last_hour=history["requests_last_hour"], recent_failures=history["recent_failures"], recent_blocks=history["recent_blocks"])
            decision = decision_engine.decide(policy_result=policy_result, risk_result=risk_result, context_result=context_result)
        except Exception as exc:
            log.exception("Pipeline error for request %s", exec_req.id)
            from app.schemas.execution import DecisionPrecedence
            policy_result = PolicyEvalResult(matched=False, effect=PolicyEffect.BLOCK, rule=None, reason="evaluation error")
            risk_result = RiskResult(score=100, level=RiskLevel.CRITICAL, signals=[], reasoning="evaluation error")
            context_result = ContextResult(findings=[], first_time_tool=False, high_frequency=False, unusual_action_pattern=False, prior_failures=False, recent_blocks=False, summary="evaluation error")
            decision = DecisionResult(action=DecisionAction.BLOCK, precedence=DecisionPrecedence.FAIL_CLOSED, reason="Security evaluation error - blocked (fail-closed)", policy_result=policy_result, risk_result=risk_result, context_result=context_result, error=str(exc))

        # Persist risk assessment
        risk_row = RiskAssessment(id=uuid.uuid4(), request_id=exec_req.id, total_score=risk_result.score, risk_level=risk_result.level.value, signals=[s.model_dump() for s in risk_result.signals], reasoning=risk_result.reasoning)
        session.add(risk_row)
        await session.flush()

        # Persist context assessment
        ctx_row = ContextAssessment(id=uuid.uuid4(), request_id=exec_req.id, history_summary=context_result.summary, recent_actions=[{"t": t, "a": a} for t, a in history["recent_all_actions"][:20]], sensitive_indicators=[f.name for f in context_result.findings])
        session.add(ctx_row)
        await session.flush()

        # Persist decision
        decision_row = Decision(id=uuid.uuid4(), request_id=exec_req.id, risk_assessment_id=risk_row.id, action=decision.action.value, reason=decision.reason, precedence=decision.precedence.value, matched_rule_id=(decision.policy_result.rule.rule_id if decision.policy_result.rule else None), matched_rule=(decision.policy_result.rule.model_dump() if decision.policy_result.rule else None))
        session.add(decision_row)
        await session.flush()

        # Route on decision
        approval_row: Approval | None = None
        tool_exec_row: ToolExecution | None = None
        approval_id: uuid.UUID | None = None

        if decision.action == DecisionAction.BLOCK:
            exec_req.state = ExecutionState.BLOCKED

        elif decision.action == DecisionAction.REQUIRE_APPROVAL:
            exec_req.state = ExecutionState.APPROVAL_PENDING
            expires = datetime.utcnow() + timedelta(seconds=settings.APPROVAL_EXPIRE_SECONDS)
            param_digest = _input_digest(request.tool.value, request.action, request.parameters)
            approval_row = Approval(id=uuid.uuid4(), request_id=exec_req.id, decision_id=decision_row.id, status=ApprovalStatus.PENDING, expires_at=expires, param_digest=param_digest, double_spend_nonce=str(uuid.uuid4()))
            session.add(approval_row)
            await session.flush()
            approval_id = approval_row.id

        elif decision.action == DecisionAction.ALLOW:
            exec_req.state = ExecutionState.RUNNING
            await session.flush()
            tool_exec_row = await self._run_tool(request.tool, request.action, request.parameters, exec_req, decision_row, None, session)
            exec_req.state = ExecutionState.SUCCEEDED if tool_exec_row.status == ToolExecutionStatus.SUCCESS else ExecutionState.FAILED

        await session.flush()

        # Audit
        await audit_logger.append(
            session=session, actor_type="agent", actor_id=str(agent.id),
            action="execution.decision", resource_type="execution_request", resource_id=str(exec_req.id),
            record_data={"request_id": str(exec_req.id), "correlation_id": correlation_id, "agent_id": str(agent.id), "tool": request.tool.value, "action": request.action, "decision": decision.action.value, "risk_score": risk_result.score, "risk_level": risk_result.level.value, "policy_effect": policy_result.effect.value, "context_findings": [f.name for f in context_result.findings], "precedence": decision.precedence.value, "error": decision.error},
            comment=decision.reason,
        )

        return ExecuteResponse(
            request_id=exec_req.id, correlation_id=correlation_id,
            decision=decision.action, reason=decision.reason,
            risk_score=risk_result.score, risk_level=risk_result.level,
            policy_name=(decision.policy_result.rule.name if decision.policy_result.rule else None),
            matched_rule_id=(decision.policy_result.rule.rule_id if decision.policy_result.rule else None),
            requires_approval=(decision.action == DecisionAction.REQUIRE_APPROVAL),
            approval_id=approval_id,
        )


gateway_service = GatewayService()
