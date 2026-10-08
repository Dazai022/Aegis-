from __future__ import annotations
import pytest
from app.policies.engine import PolicyEngine, DEFAULT_RULES, SAFE_GITHUB_READ_RULE, DESTRUCTIVE_TERMINAL_RULE, TERMINAL_APPROVAL_RULE
from app.schemas.execution import PolicyEffect, PolicyRule, ToolName


@pytest.fixture()
def engine():
    return PolicyEngine()


class TestDefaultRules:
    def test_github_read_allows(self, engine):
        r = engine.evaluate(ToolName.GITHUB, 'read_file', {'path': 'README.md'})
        assert r.effect == PolicyEffect.ALLOW
        assert r.matched is True

    def test_github_read_repository_allows(self, engine):
        r = engine.evaluate(ToolName.GITHUB, 'read_repository', {})
        assert r.effect == PolicyEffect.ALLOW

    def test_github_non_read_action_requires_approval(self, engine):
        r = engine.evaluate(ToolName.GITHUB, 'create_branch', {})
        assert r.effect == PolicyEffect.REQUIRE_APPROVAL

    def test_destructive_terminal_rm_blocks(self, engine):
        r = engine.evaluate(ToolName.TERMINAL, 'execute', {'command': 'rm -rf /tmp/test'})
        assert r.effect == PolicyEffect.BLOCK
        assert r.matched is True

    def test_destructive_terminal_del_blocks(self, engine):
        r = engine.evaluate(ToolName.TERMINAL, 'execute', {'command': 'del /f /s /q C:\\test'})
        assert r.effect == PolicyEffect.BLOCK

    def test_terminal_non_destructive_requires_approval(self, engine):
        r = engine.evaluate(ToolName.TERMINAL, 'execute', {'command': 'echo hello'})
        assert r.effect == PolicyEffect.REQUIRE_APPROVAL

    def test_no_matching_rule_returns_require_approval(self, engine):
        r = engine.evaluate(ToolName.GITHUB, 'unknown_action', {}, rules=[])
        assert r.effect == PolicyEffect.REQUIRE_APPROVAL
        assert r.matched is False
        assert r.rule is None


class TestPriorityOrdering:
    def test_lower_priority_number_wins(self, engine):
        block_rule = PolicyRule(rule_id='t1', name='Block', priority=1, enabled=True,
            tool=ToolName.GITHUB, action_pattern='read_*',
            effect=PolicyEffect.BLOCK, reason='block')
        allow_rule = PolicyRule(rule_id='t2', name='Allow', priority=2, enabled=True,
            tool=ToolName.GITHUB, action_pattern='read_*',
            effect=PolicyEffect.ALLOW, reason='allow')
        r = engine.evaluate(ToolName.GITHUB, 'read_file', {}, rules=[allow_rule, block_rule])
        assert r.effect == PolicyEffect.BLOCK, 'priority 1 should win over priority 2'

    def test_higher_priority_number_loses(self, engine):
        allow_rule = PolicyRule(rule_id='t3', name='Allow', priority=1, enabled=True,
            tool=ToolName.GITHUB, action_pattern='read_*',
            effect=PolicyEffect.ALLOW, reason='allow')
        block_rule = PolicyRule(rule_id='t4', name='Block', priority=5, enabled=True,
            tool=ToolName.GITHUB, action_pattern='read_*',
            effect=PolicyEffect.BLOCK, reason='block')
        r = engine.evaluate(ToolName.GITHUB, 'read_file', {}, rules=[block_rule, allow_rule])
        assert r.effect == PolicyEffect.ALLOW, 'priority 1 should win over priority 5'


class TestDisabledRules:
    def test_disabled_rule_is_ignored(self, engine):
        disabled = PolicyRule(rule_id='d1', name='Disabled Block', priority=1,
            enabled=False, tool=ToolName.GITHUB, action_pattern='read_*',
            effect=PolicyEffect.BLOCK, reason='should not fire')
        active = PolicyRule(rule_id='d2', name='Active Allow', priority=2,
            enabled=True, tool=ToolName.GITHUB, action_pattern='read_*',
            effect=PolicyEffect.ALLOW, reason='allow')
        r = engine.evaluate(ToolName.GITHUB, 'read_file', {}, rules=[disabled, active])
        assert r.effect == PolicyEffect.ALLOW, 'disabled rule must be skipped'


class TestParameterConstraints:
    def test_pattern_match_fires(self, engine):
        rule = PolicyRule(rule_id='p1', name='Block rm', priority=1, enabled=True,
            tool=ToolName.TERMINAL, action_pattern=None,
            parameter_constraints={'command': {'matches_any_pattern': ['rm *']}},
            effect=PolicyEffect.BLOCK, reason='rm blocked')
        r = engine.evaluate(ToolName.TERMINAL, 'run', {'command': 'rm -rf /'}, rules=[rule])
        assert r.effect == PolicyEffect.BLOCK

    def test_pattern_no_match_falls_through(self, engine):
        rule = PolicyRule(rule_id='p2', name='Block rm', priority=1, enabled=True,
            tool=ToolName.TERMINAL, action_pattern=None,
            parameter_constraints={'command': {'matches_any_pattern': ['rm *']}},
            effect=PolicyEffect.BLOCK, reason='rm blocked')
        r = engine.evaluate(ToolName.TERMINAL, 'run', {'command': 'echo hello'}, rules=[rule])
        assert r.effect == PolicyEffect.REQUIRE_APPROVAL, 'no match -> default'

    def test_missing_param_key_no_match(self, engine):
        rule = PolicyRule(rule_id='p3', name='Needs command', priority=1, enabled=True,
            tool=ToolName.TERMINAL, action_pattern=None,
            parameter_constraints={'command': {'contains': 'rm'}},
            effect=PolicyEffect.BLOCK, reason='rm')
        r = engine.evaluate(ToolName.TERMINAL, 'run', {}, rules=[rule])
        assert r.effect == PolicyEffect.REQUIRE_APPROVAL
