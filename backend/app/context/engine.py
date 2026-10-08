"""
Context Engine — deterministic agent behaviour analysis.

Analyses an agent's historical request patterns to detect:
  - first_time_tool      : agent has never used this tool before
  - high_frequency       : burst of requests in a short window
  - unusual_action_pattern: action not seen in recent tool history
  - prior_failures       : recent execution failures for this agent
  - recent_blocks        : recent BLOCK decisions for this agent

All inputs are supplied by the caller from DB queries.
No DB I/O happens inside this class.
"""
from __future__ import annotations

from app.schemas.execution import ContextFinding, ContextResult, ToolName


# ---------------------------------------------------------------------------
# Thresholds (constants; could be moved to settings if tuning is needed)
# ---------------------------------------------------------------------------

FREQUENCY_WINDOW_MINUTES = 60
HIGH_FREQUENCY_THRESHOLD  = 30   # requests per window
HISTORY_WINDOW             = 100  # last N requests to consider


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ContextEngine:
    """
    Pure, stateless context analyser.

    All history data is passed in by the caller (loaded from the DB by the
    gateway service) so the engine remains fully unit-testable without a DB.

    Args for analyse():
        tool                  ToolName enum value for the current request
        action                action string from the current request
        tools_ever_used       list of tool name strings the agent has used
        recent_tool_actions   last N action strings for (agent, tool) combo
        recent_all_actions    last N (tool, action) tuples across all tools
        requests_last_hour    count of requests in the last 60 minutes
        recent_failures       count of failed executions in recent window
        recent_blocks         count of BLOCK decisions in recent window
    """

    def analyse(
        self,
        tool: ToolName,
        action: str,
        tools_ever_used: list[str] | None = None,
        recent_tool_actions: list[str] | None = None,
        recent_all_actions: list[tuple[str, str]] | None = None,
        requests_last_hour: int = 0,
        recent_failures: int = 0,
        recent_blocks: int = 0,
    ) -> ContextResult:
        tools_ever_used = tools_ever_used or []
        recent_tool_actions = recent_tool_actions or []
        recent_all_actions = recent_all_actions or []

        findings: list[ContextFinding] = []

        # ── Finding 1: first-time tool ─────────────────────────────────────
        first_time = tool.value.lower() not in {t.lower() for t in tools_ever_used}
        if first_time:
            findings.append(ContextFinding(
                name="first_time_tool",
                description=f"Agent is using '{tool.value}' for the first time",
                severity="warning",
                evidence=f"tool '{tool.value}' not in history: {tools_ever_used}",
            ))

        # ── Finding 2: high frequency ──────────────────────────────────────
        high_freq = requests_last_hour > HIGH_FREQUENCY_THRESHOLD
        if high_freq:
            findings.append(ContextFinding(
                name="high_frequency",
                description=(
                    f"Agent made {requests_last_hour} requests in the last "
                    f"{FREQUENCY_WINDOW_MINUTES} minutes (threshold: {HIGH_FREQUENCY_THRESHOLD})"
                ),
                severity="warning",
                evidence=f"{requests_last_hour} requests/hour",
            ))

        # ── Finding 3: unusual action pattern ─────────────────────────────
        known_actions = {a.lower() for a in recent_tool_actions}
        unusual = bool(recent_tool_actions) and action.lower() not in known_actions
        if unusual:
            findings.append(ContextFinding(
                name="unusual_action_pattern",
                description=(
                    f"Action '{action}' has not been seen in the last "
                    f"{len(recent_tool_actions)} requests for tool '{tool.value}'"
                ),
                severity="alert",
                evidence=f"known actions: {sorted(list(known_actions))[:10]}",
            ))

        # ── Finding 4: cross-tool unusual pattern ──────────────────────────
        # If agent has only ever used one tool and now uses a different one
        unique_tools_in_history = {t.lower() for t, _ in recent_all_actions}
        if (
            len(unique_tools_in_history) > 0
            and tool.value.lower() not in unique_tools_in_history
            and not first_time  # already flagged above
        ):
            findings.append(ContextFinding(
                name="tool_switch",
                description=(
                    f"Agent switched to '{tool.value}' after exclusively using "
                    f"{unique_tools_in_history}"
                ),
                severity="warning",
                evidence=f"previous tools: {sorted(list(unique_tools_in_history))}",
            ))

        # ── Finding 5: prior failures ──────────────────────────────────────
        has_failures = recent_failures > 0
        if has_failures:
            findings.append(ContextFinding(
                name="prior_failures",
                description=f"Agent had {recent_failures} failed execution(s) recently",
                severity="warning",
                evidence=f"{recent_failures} failures",
            ))

        # ── Finding 6: recent blocks ───────────────────────────────────────
        has_blocks = recent_blocks > 0
        if has_blocks:
            findings.append(ContextFinding(
                name="recent_blocks",
                description=f"Agent received {recent_blocks} BLOCK decision(s) recently",
                severity="alert",
                evidence=f"{recent_blocks} blocks",
            ))

        # ── Summary ────────────────────────────────────────────────────────
        if findings:
            alert_count = sum(1 for f in findings if f.severity == "alert")
            warn_count  = sum(1 for f in findings if f.severity == "warning")
            summary = (
                f"{len(findings)} context finding(s): "
                f"{alert_count} alert(s), {warn_count} warning(s). "
                + "; ".join(f.name for f in findings)
            )
        else:
            summary = "No unusual context findings. Agent behaviour is consistent with history."

        return ContextResult(
            findings=findings,
            first_time_tool=first_time,
            high_frequency=high_freq,
            unusual_action_pattern=unusual,
            prior_failures=has_failures,
            recent_blocks=has_blocks,
            history_window_requests=len(recent_all_actions),
            summary=summary,
        )


# Module-level singleton — stateless, thread-safe
context_engine = ContextEngine()
