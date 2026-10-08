"""
Risk Engine — deterministic, explainable 0-100 risk scoring.

Each signal has a fixed weight and a deterministic trigger condition.
Signals are evaluated independently and the total is capped at 100.
Thresholds come from settings so they are configurable without code changes.

Signals (name, weight, trigger):
  destructive_action   +30  action/command contains destructive keywords
  sensitive_resource   +25  parameters reference sensitive paths/keys
  privileged_tool      +15  tool=terminal (always elevated)
  unusual_action       +20  action not seen in last 100 requests for agent
  first_time_tool      +15  agent has never used this tool before
  high_frequency       +10  >30 requests in last 60 minutes
  suspicious_params    +20  path traversal or shell meta-characters in params
  prompt_injection     +15  injection keywords in action or params
  sensitive_data       +20  params reference credential/token/PII keys
"""
from __future__ import annotations

import re
from typing import Any

from app.core.config import settings
from app.schemas.execution import RiskLevel, RiskResult, RiskSignal, ToolName


# ---------------------------------------------------------------------------
# Keyword / pattern sets  (all lowercase for case-insensitive matching)
# ---------------------------------------------------------------------------

_DESTRUCTIVE_KEYWORDS = frozenset([
    "rm", "remove", "delete", "del", "drop", "destroy", "wipe",
    "mkfs", "format", "shred", "truncate", "overwrite",
    "shutdown", "reboot", "halt", "poweroff", "kill",
    "unlink", "rmdir", "purge", "erase", "obliterate",
])

_SENSITIVE_PATHS = frozenset([
    "/etc", "/root", "/proc", "/sys", "c:\\windows", "c:/windows",
    ".aws", ".ssh", ".gnupg", ".env", "production", "prod",
    "credentials", "secrets", "vault", ".kube", "kubeconfig",
])

_SENSITIVE_PARAM_KEYS = frozenset([
    "password", "passwd", "token", "secret", "api_key", "apikey",
    "private_key", "privatekey", "credential", "auth", "access_key",
    "client_secret", "bearer", "jwt", "session_token",
])

_SHELL_META = re.compile(r"[;&|`$<>]|\.\./|\.\.\\")

_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+previous",
    r"ignore\s+all\s+previous",
    r"disregard\s+previous",
    r"system\s*:",
    r"jailbreak",
    r"forget\s+(your|all)\s+(instructions|rules)",
    r"new\s+instructions",
    r"you\s+are\s+now",
    r"act\s+as\s+(if|though)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"do\s+anything\s+now",
    r"dan\s+mode",
]
_PROMPT_INJECTION_RE = re.compile(
    "|".join(_PROMPT_INJECTION_PATTERNS), re.IGNORECASE
)

_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]")


# ---------------------------------------------------------------------------
# Score → RiskLevel mapping (reads from settings)
# ---------------------------------------------------------------------------

def _score_to_level(score: int) -> RiskLevel:
    lvl = settings.RISK_LEVELS
    if score <= lvl.LOW_MAX:
        return RiskLevel.LOW
    if score <= lvl.MEDIUM_MAX:
        return RiskLevel.MEDIUM
    if score <= lvl.HIGH_MAX:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Individual signal evaluators
# ---------------------------------------------------------------------------

def _sig_destructive_action(
    tool: ToolName, action: str, parameters: dict[str, Any]
) -> RiskSignal:
    """Fires when the action name or command parameter contains destructive verbs."""
    triggered = False
    evidence = ""

    action_lower = action.lower()
    for kw in _DESTRUCTIVE_KEYWORDS:
        pattern = r"(?<![a-z])" + re.escape(kw) + r"(?![a-z])"
        if re.search(pattern, action_lower):
            triggered = True
            evidence = f"action contains '{kw}'"
            break

    if not triggered:
        cmd = str(parameters.get("command", "")).lower()
        for kw in _DESTRUCTIVE_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", cmd):
                triggered = True
                evidence = f"command contains '{kw}'"
                break

    return RiskSignal(
        name="destructive_action",
        weight=30,
        triggered=triggered,
        reason="Action or command contains destructive keywords",
        evidence=evidence,
    )


def _sig_sensitive_resource(parameters: dict[str, Any]) -> RiskSignal:
    """Fires when any parameter value references sensitive paths or resources."""
    triggered = False
    evidence = ""
    all_values = " ".join(str(v).lower() for v in _flatten_values(parameters))
    for path in _SENSITIVE_PATHS:
        if path in all_values:
            triggered = True
            evidence = f"references '{path}'"
            break
    return RiskSignal(
        name="sensitive_resource",
        weight=25,
        triggered=triggered,
        reason="Parameters reference sensitive paths or resources",
        evidence=evidence,
    )


def _sig_privileged_tool(tool: ToolName) -> RiskSignal:
    """Fires for tools that have direct host access (terminal)."""
    triggered = tool == ToolName.TERMINAL
    return RiskSignal(
        name="privileged_tool",
        weight=15,
        triggered=triggered,
        reason="Terminal tool has direct host access",
        evidence=tool.value if triggered else "",
    )


def _sig_unusual_action(
    action: str,
    tool: ToolName,
    recent_tool_actions: list[str],
) -> RiskSignal:
    """Fires when the action has not been seen in recent history for this tool."""
    if not recent_tool_actions:
        triggered = True
        evidence = "no history available"
    else:
        triggered = action.lower() not in {a.lower() for a in recent_tool_actions}
        evidence = f"'{action}' not in last {len(recent_tool_actions)} actions" if triggered else ""
    return RiskSignal(
        name="unusual_action",
        weight=20,
        triggered=triggered,
        reason="Action not seen in recent history for this tool",
        evidence=evidence,
    )


def _sig_first_time_tool(tool: ToolName, tools_ever_used: list[str]) -> RiskSignal:
    """Fires when the agent has never used this tool before."""
    triggered = tool.value not in {t.lower() for t in tools_ever_used}
    return RiskSignal(
        name="first_time_tool",
        weight=15,
        triggered=triggered,
        reason="Agent has never used this tool before",
        evidence=tool.value if triggered else "",
    )


def _sig_high_frequency(requests_last_hour: int) -> RiskSignal:
    """Fires when the agent has made more than 30 requests in the last hour."""
    threshold = 30
    triggered = requests_last_hour > threshold
    return RiskSignal(
        name="high_frequency",
        weight=10,
        triggered=triggered,
        reason=f"Agent made more than {threshold} requests in the last hour",
        evidence=f"{requests_last_hour} requests" if triggered else "",
    )


def _sig_suspicious_params(parameters: dict[str, Any]) -> RiskSignal:
    """Fires on path traversal or shell meta-characters in any parameter value."""
    triggered = False
    evidence = ""
    all_values = " ".join(str(v) for v in _flatten_values(parameters))
    if _PATH_TRAVERSAL_RE.search(all_values):
        triggered = True
        evidence = "path traversal detected (../)"
    elif _SHELL_META.search(all_values):
        triggered = True
        m = _SHELL_META.search(all_values)
        evidence = f"shell meta-character: {m.group(0)!r}" if m else "shell meta-character"
    return RiskSignal(
        name="suspicious_params",
        weight=20,
        triggered=triggered,
        reason="Parameters contain path traversal or shell meta-characters",
        evidence=evidence,
    )


def _sig_prompt_injection(action: str, parameters: dict[str, Any]) -> RiskSignal:
    """Fires when action or parameter values contain prompt-injection patterns."""
    combined = action + " " + " ".join(str(v) for v in _flatten_values(parameters))
    m = _PROMPT_INJECTION_RE.search(combined)
    triggered = m is not None
    return RiskSignal(
        name="prompt_injection",
        weight=15,
        triggered=triggered,
        reason="Prompt injection keywords detected in action or parameters",
        evidence=m.group(0) if m else "",
    )


def _sig_sensitive_data(parameters: dict[str, Any]) -> RiskSignal:
    """Fires when parameter keys or values suggest credential/token access."""
    triggered = False
    evidence = ""
    for key in parameters:
        if key.lower() in _SENSITIVE_PARAM_KEYS:
            triggered = True
            evidence = f"parameter key '{key}' indicates sensitive data"
            break
    return RiskSignal(
        name="sensitive_data",
        weight=20,
        triggered=triggered,
        reason="Parameters reference credentials, tokens, or PII",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _flatten_values(d: dict[str, Any], depth: int = 3) -> list[str]:
    """Recursively collect string values from a parameter dict."""
    result: list[str] = []
    if depth <= 0:
        return result
    for v in d.values():
        if isinstance(v, dict):
            result.extend(_flatten_values(v, depth - 1))
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    result.extend(_flatten_values(item, depth - 1))
                else:
                    result.append(str(item))
        else:
            result.append(str(v))
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class RiskEngine:
    """
    Deterministic risk scorer.  All inputs must be supplied by the caller —
    no database access happens inside this class.

    Args for assess():
        tool                  ToolName enum
        action                action string from the request
        parameters            tool parameters dict
        recent_tool_actions   last N action strings for (agent, tool) from DB
        tools_ever_used       list of tool names the agent has ever invoked
        requests_last_hour    count of requests from this agent in last 60 min
    """

    def assess(
        self,
        tool: ToolName,
        action: str,
        parameters: dict[str, Any],
        recent_tool_actions: list[str] | None = None,
        tools_ever_used: list[str] | None = None,
        requests_last_hour: int = 0,
    ) -> RiskResult:
        signals: list[RiskSignal] = [
            _sig_destructive_action(tool, action, parameters),
            _sig_sensitive_resource(parameters),
            _sig_privileged_tool(tool),
            _sig_unusual_action(action, tool, recent_tool_actions or []),
            _sig_first_time_tool(tool, tools_ever_used or []),
            _sig_high_frequency(requests_last_hour),
            _sig_suspicious_params(parameters),
            _sig_prompt_injection(action, parameters),
            _sig_sensitive_data(parameters),
        ]

        raw_score = sum(s.weight for s in signals if s.triggered)
        score = min(raw_score, 100)
        level = _score_to_level(score)

        triggered_names = [s.name for s in signals if s.triggered]
        if triggered_names:
            reasoning = f"Risk score {score} ({level.value}). Triggered signals: {', '.join(triggered_names)}."
        else:
            reasoning = f"Risk score {score} ({level.value}). No risk signals triggered."

        return RiskResult(
            score=score,
            level=level,
            signals=signals,
            reasoning=reasoning,
        )


# Module-level singleton — stateless, thread-safe
risk_engine = RiskEngine()
