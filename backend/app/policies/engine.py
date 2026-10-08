"""
Policy Engine — deterministic, first-match-wins evaluation.

Rules are evaluated in ascending priority order (lower number = higher
precedence).  The first rule whose tool/action/parameter constraints all
match wins.  If no rule matches the default effect is REQUIRE_APPROVAL.

All logic is pure-Python with no DB I/O; the caller loads rules from the
database (or uses the built-in defaults) and passes them in.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any

from app.schemas.execution import (
    PolicyEffect,
    PolicyEvalResult,
    PolicyRule,
    ToolName,
)


# ---------------------------------------------------------------------------
# Built-in default policy rules
# ---------------------------------------------------------------------------

SAFE_GITHUB_READ_RULE = PolicyRule(
    rule_id="builtin-001",
    name="Safe GitHub Read",
    description="Allow read-only GitHub operations",
    priority=10,
    enabled=True,
    tool=ToolName.GITHUB,
    action_pattern="read_*",
    parameter_constraints={},
    effect=PolicyEffect.ALLOW,
    reason="GitHub read operations are safe for autonomous agents",
)

DESTRUCTIVE_TERMINAL_RULE = PolicyRule(
    rule_id="builtin-002",
    name="Destructive Terminal Operations",
    description="Block destructive terminal commands",
    priority=5,
    enabled=True,
    tool=ToolName.TERMINAL,
    action_pattern=None,
    parameter_constraints={
        "command": {
            "matches_any_pattern": [
                "rm *", "rm\t*", "rm", "del *", "rmdir *",
                "mkfs*", "dd if=*", "shred *", "shutdown*",
                "reboot*", "halt*", "poweroff*", "destroy*",
                "drop table*", ":(){*", "format *",
            ]
        }
    },
    effect=PolicyEffect.BLOCK,
    reason="Destructive terminal commands are never permitted without explicit review",
)

TERMINAL_APPROVAL_RULE = PolicyRule(
    rule_id="builtin-003",
    name="Terminal Execution Requires Approval",
    description="All terminal executions require human approval",
    priority=20,
    enabled=True,
    tool=ToolName.TERMINAL,
    action_pattern=None,
    parameter_constraints={},
    effect=PolicyEffect.REQUIRE_APPROVAL,
    reason="Terminal execution touches the host environment and requires human review",
)

DEFAULT_RULES: list[PolicyRule] = sorted(
    [SAFE_GITHUB_READ_RULE, DESTRUCTIVE_TERMINAL_RULE, TERMINAL_APPROVAL_RULE],
    key=lambda r: r.priority,
)


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _match_tool(rule: PolicyRule, tool: ToolName) -> bool:
    """None means the rule matches any tool."""
    if rule.tool is None:
        return True
    return rule.tool == tool


def _match_action(rule: PolicyRule, action: str) -> bool:
    """None pattern means match any action; otherwise fnmatch glob."""
    if rule.action_pattern is None:
        return True
    return fnmatch.fnmatch(action.lower(), rule.action_pattern.lower())


def _match_parameters(rule: PolicyRule, parameters: dict[str, Any]) -> bool:
    """
    Evaluate parameter_constraints against the request parameters.

    Supported constraint forms per key:
      {"matches_any_pattern": [...]}   fnmatch glob against stringified value
      {"contains": "..."}              substring (case-insensitive)
      {"equals": "..."}               exact equality (case-insensitive)
      {"regex": "..."}                re.search (case-insensitive)

    A missing parameter means the constraint for that key cannot fire,
    so the rule does NOT match on that constraint.
    """
    constraints = rule.parameter_constraints
    if not constraints:
        return True

    for param_key, constraint in constraints.items():
        raw_value = parameters.get(param_key)
        if raw_value is None:
            # Constraint specifies a key that isn't in the request — no match
            return False
        value_str = str(raw_value).lower()

        if "matches_any_pattern" in constraint:
            patterns: list[str] = constraint["matches_any_pattern"]
            matched_any = any(
                fnmatch.fnmatch(value_str, pat.lower()) for pat in patterns
            )
            if not matched_any:
                return False

        if "contains" in constraint:
            if str(constraint["contains"]).lower() not in value_str:
                return False

        if "equals" in constraint:
            if value_str != str(constraint["equals"]).lower():
                return False

        if "regex" in constraint:
            if not re.search(constraint["regex"], value_str, re.IGNORECASE):
                return False

    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Pure, stateless policy evaluator.

    Pass in a list of PolicyRule objects (sorted or unsorted — the engine
    re-sorts by priority) and the engine returns the first matching result,
    or a default REQUIRE_APPROVAL if nothing matches.

    This class has no DB dependencies; it operates only on the data it is
    given, making it fully unit-testable without a database.
    """

    def evaluate(
        self,
        tool: ToolName,
        action: str,
        parameters: dict[str, Any],
        rules: list[PolicyRule] | None = None,
    ) -> PolicyEvalResult:
        """
        Evaluate policies in ascending priority order (first-match-wins).

        Args:
            tool:       The tool being invoked.
            action:     The action string (e.g. "read_file", "execute").
            parameters: The tool parameters dict from the request.
            rules:      Override the default built-in rules; pass None to
                        use DEFAULT_RULES.

        Returns:
            PolicyEvalResult with the winning effect and matched rule (or
            the no-match default of REQUIRE_APPROVAL).
        """
        effective_rules = rules if rules is not None else DEFAULT_RULES
        active_rules = sorted(
            [r for r in effective_rules if r.enabled],
            key=lambda r: r.priority,
        )

        for rule in active_rules:
            if not _match_tool(rule, tool):
                continue
            if not _match_action(rule, action):
                continue
            if not _match_parameters(rule, parameters):
                continue
            return PolicyEvalResult(
                matched=True,
                effect=rule.effect,
                rule=rule,
                reason=rule.reason or f"Matched rule: {rule.name}",
            )

        return PolicyEvalResult(
            matched=False,
            effect=PolicyEffect.REQUIRE_APPROVAL,
            rule=None,
            reason="No policy matched; defaulting to REQUIRE_APPROVAL",
        )


# Module-level singleton — stateless and thread-safe
policy_engine = PolicyEngine()
