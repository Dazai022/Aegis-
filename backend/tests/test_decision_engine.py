from __future__ import annotations
import pytest
from unittest.mock import patch
from app.decisions.engine import DecisionEngine
from app.schemas.execution import (
    ContextResult, DecisionAction, DecisionPrecedence,
    PolicyEffect, PolicyEvalResult, PolicyRule,
    RiskLevel, RiskResult, RiskSignal, ToolName,
)


def _policy(effect: PolicyEffect, rule_name: str = 'test') -> PolicyEvalResult:
    rule = None
    if effect != PolicyEffect.REQUIRE_APPROVAL:
        rule = PolicyRule(rule_id='t1', name=rule_name, priority=1, enabled=True,
            tool=None, action_pattern=None, effect=effect, reason='test rule')
    return PolicyEvalResult(matched=effect != PolicyEffect.REQUIRE_APPROVAL,
        effect=effect, rule=rule, reason='test')


def _risk(level: RiskLevel, score: int | None = None) -> RiskResult:
    default_scores = {RiskLevel.LOW: 10, RiskLevel.MEDIUM: 45,
                       RiskLevel.HIGH: 65, RiskLevel.CRITICAL: 90}
    return RiskResult(score=score or default_scores[level],
        level=level, signals=[], reasoning='test')


def _context(no_flags: bool = True) -> ContextResult:
    return ContextResult(findings=[], first_time_tool=False, high_frequency=False,
        unusual_action_pattern=False, prior_failures=False, recent_blocks=False,
        summary='test')


@pytest.fixture()
def engine():
    return DecisionEngine()


class TestBlockPolicyPrecedence:
    def test_block_policy_always_blocks(self, engine):
        r = engine.decide(_policy(PolicyEffect.BLOCK), _risk(RiskLevel.LOW), _context())
        assert r.action == DecisionAction.BLOCK
        assert r.precedence == DecisionPrecedence.BLOCK_POLICY

    def test_block_policy_overrides_low_risk(self, engine):
        r = engine.decide(_policy(PolicyEffect.BLOCK), _risk(RiskLevel.LOW), _context())
        assert r.action == DecisionAction.BLOCK

    def test_block_policy_overrides_allow_effect(self, engine):
        # If somehow both block and allow rules exist, BLOCK takes priority 1
        r = engine.decide(_policy(PolicyEffect.BLOCK), _risk(RiskLevel.LOW), _context())
        assert r.action == DecisionAction.BLOCK


class TestHighRiskRequiresApproval:
    def test_high_risk_requires_approval(self, engine):
        r = engine.decide(_policy(PolicyEffect.ALLOW), _risk(RiskLevel.HIGH), _context())
        assert r.action == DecisionAction.REQUIRE_APPROVAL
        assert r.precedence == DecisionPrecedence.HIGH_CRITICAL_RISK

    def test_critical_risk_requires_approval(self, engine):
        r = engine.decide(_policy(PolicyEffect.ALLOW), _risk(RiskLevel.CRITICAL), _context())
        assert r.action == DecisionAction.REQUIRE_APPROVAL
        assert r.precedence == DecisionPrecedence.HIGH_CRITICAL_RISK

    def test_medium_risk_does_not_trigger_approval(self, engine):
        r = engine.decide(_policy(PolicyEffect.ALLOW), _risk(RiskLevel.MEDIUM), _context())
        assert r.action == DecisionAction.ALLOW


class TestApprovalPolicyPrecedence:
    def test_require_approval_policy_respected(self, engine):
        r = engine.decide(_policy(PolicyEffect.REQUIRE_APPROVAL), _risk(RiskLevel.LOW), _context())
        assert r.action == DecisionAction.REQUIRE_APPROVAL
        assert r.precedence == DecisionPrecedence.APPROVAL_POLICY


class TestAllowPath:
    def test_allow_policy_with_low_risk_allows(self, engine):
        r = engine.decide(_policy(PolicyEffect.ALLOW), _risk(RiskLevel.LOW), _context())
        assert r.action == DecisionAction.ALLOW
        assert r.precedence == DecisionPrecedence.ALLOW_LOW_RISK

    def test_allow_policy_with_medium_risk_allows(self, engine):
        r = engine.decide(_policy(PolicyEffect.ALLOW), _risk(RiskLevel.MEDIUM), _context())
        assert r.action == DecisionAction.ALLOW


class TestFailClosed:
    def test_exception_in_inner_logic_blocks(self, engine):
        # Inject an exception by passing invalid inputs
        with patch.object(engine, '_apply_precedence', side_effect=RuntimeError('injected')):
            r = engine.decide(_policy(PolicyEffect.ALLOW), _risk(RiskLevel.LOW), _context())
        assert r.action == DecisionAction.BLOCK
        assert r.precedence == DecisionPrecedence.FAIL_CLOSED
        assert 'injected' in (r.error or '')

    def test_fail_closed_reason_says_blocked(self, engine):
        with patch.object(engine, '_apply_precedence', side_effect=ValueError('oops')):
            r = engine.decide(_policy(PolicyEffect.ALLOW), _risk(RiskLevel.LOW), _context())
        assert 'fail-closed' in r.reason.lower() or 'blocked' in r.reason.lower()


class TestDecisionContainsEvidence:
    def test_block_result_has_reason(self, engine):
        r = engine.decide(_policy(PolicyEffect.BLOCK), _risk(RiskLevel.LOW), _context())
        assert r.reason
        assert r.policy_result is not None
        assert r.risk_result is not None
        assert r.context_result is not None
