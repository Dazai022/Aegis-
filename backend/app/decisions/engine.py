from __future__ import annotations
import logging
from app.schemas.execution import (
    ContextResult, DecisionAction, DecisionPrecedence, DecisionResult,
    PolicyEvalResult, PolicyEffect, RiskLevel, RiskResult,
)
log = logging.getLogger("aegis.decisions")

class DecisionEngine:
    def decide(self, policy_result, risk_result, context_result):
        try:
            return self._apply_precedence(policy_result, risk_result, context_result)
        except Exception as exc:
            log.exception("Decision engine error - blocking (fail-closed)")
            return DecisionResult(
                action=DecisionAction.BLOCK,
                precedence=DecisionPrecedence.FAIL_CLOSED,
                reason="Security evaluation error - blocking request (fail-closed)",
                policy_result=policy_result if policy_result else _null_policy(),
                risk_result=risk_result if risk_result else _null_risk(),
                context_result=context_result if context_result else _null_context(),
                error=type(exc).__name__ + ": " + str(exc),
            )

    def _apply_precedence(self, policy_result, risk_result, context_result):
        if policy_result.effect == PolicyEffect.BLOCK:
            rule_name = policy_result.rule.name if policy_result.rule else "block rule"
            return DecisionResult(
                action=DecisionAction.BLOCK,
                precedence=DecisionPrecedence.BLOCK_POLICY,
                reason=f"Policy BLOCK: {rule_name}. {policy_result.reason}",
                policy_result=policy_result, risk_result=risk_result,
                context_result=context_result,
            )
        if risk_result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return DecisionResult(
                action=DecisionAction.REQUIRE_APPROVAL,
                precedence=DecisionPrecedence.HIGH_CRITICAL_RISK,
                reason=f"Risk {risk_result.level.value} (score {risk_result.score}) requires approval. {risk_result.reasoning}",
                policy_result=policy_result, risk_result=risk_result,
                context_result=context_result,
            )
        if policy_result.effect == PolicyEffect.REQUIRE_APPROVAL:
            rule_name = policy_result.rule.name if policy_result.rule else "default"
            return DecisionResult(
                action=DecisionAction.REQUIRE_APPROVAL,
                precedence=DecisionPrecedence.APPROVAL_POLICY,
                reason=f"Policy requires approval: {rule_name}. {policy_result.reason}",
                policy_result=policy_result, risk_result=risk_result,
                context_result=context_result,
            )
        if policy_result.effect == PolicyEffect.ALLOW:
            rule_name = policy_result.rule.name if policy_result.rule else "allow"
            return DecisionResult(
                action=DecisionAction.ALLOW,
                precedence=DecisionPrecedence.ALLOW_LOW_RISK,
                reason=f"Allowed by policy '{rule_name}' with {risk_result.level.value} risk (score {risk_result.score})",
                policy_result=policy_result, risk_result=risk_result,
                context_result=context_result,
            )
        return DecisionResult(
            action=DecisionAction.BLOCK,
            precedence=DecisionPrecedence.FAIL_CLOSED,
            reason=f"No precedence rule matched effect={policy_result.effect} - fail-closed",
            policy_result=policy_result, risk_result=risk_result,
            context_result=context_result,
        )

def _null_policy():
    return PolicyEvalResult(matched=False, effect=PolicyEffect.BLOCK, rule=None, reason="evaluation error")

def _null_risk():
    return RiskResult(score=100, level=RiskLevel.CRITICAL, signals=[], reasoning="evaluation error")

def _null_context():
    return ContextResult(findings=[], first_time_tool=False, high_frequency=False,
        unusual_action_pattern=False, prior_failures=False, recent_blocks=False,
        history_window_requests=0, summary="evaluation error")

decision_engine = DecisionEngine()