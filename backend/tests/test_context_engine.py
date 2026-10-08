from __future__ import annotations
import pytest
from app.context.engine import ContextEngine
from app.schemas.execution import ToolName


@pytest.fixture()
def engine():
    return ContextEngine()


class TestFirstTimeTool:
    def test_flags_first_time(self, engine):
        r = engine.analyse(ToolName.TERMINAL, 'execute', tools_ever_used=[])
        assert r.first_time_tool is True
        assert any(f.name == 'first_time_tool' for f in r.findings)

    def test_no_flag_when_tool_known(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file', tools_ever_used=['github'])
        assert r.first_time_tool is False


class TestHighFrequency:
    def test_burst_flagged(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file', requests_last_hour=50)
        assert r.high_frequency is True
        assert any(f.name == 'high_frequency' for f in r.findings)

    def test_normal_not_flagged(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file', requests_last_hour=5)
        assert r.high_frequency is False


class TestUnusualActionPattern:
    def test_unusual_action_flagged(self, engine):
        # Agent has 50 github reads, now requests terminal delete
        history = ['read_file'] * 50
        r = engine.analyse(ToolName.TERMINAL, 'delete_files',
            recent_tool_actions=history)
        assert r.unusual_action_pattern is True
        assert any(f.name == 'unusual_action_pattern' for f in r.findings)

    def test_known_action_not_flagged(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file',
            recent_tool_actions=['read_file', 'read_repository', 'read_file'])
        assert r.unusual_action_pattern is False

    def test_no_history_not_flagged_as_unusual(self, engine):
        # No history = first_time, but NOT unusual_action_pattern (no baseline)
        r = engine.analyse(ToolName.GITHUB, 'read_file', recent_tool_actions=[])
        assert r.unusual_action_pattern is False


class TestPriorFailures:
    def test_prior_failures_flagged(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file', recent_failures=3)
        assert r.prior_failures is True
        assert any(f.name == 'prior_failures' for f in r.findings)

    def test_no_failures_not_flagged(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file', recent_failures=0)
        assert r.prior_failures is False


class TestRecentBlocks:
    def test_blocks_flagged(self, engine):
        r = engine.analyse(ToolName.TERMINAL, 'execute', recent_blocks=2)
        assert r.recent_blocks is True
        assert any(f.name == 'recent_blocks' for f in r.findings)

    def test_no_blocks_not_flagged(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file', recent_blocks=0)
        assert r.recent_blocks is False


class TestSummary:
    def test_clean_history_no_findings(self, engine):
        r = engine.analyse(ToolName.GITHUB, 'read_file',
            tools_ever_used=['github'],
            recent_tool_actions=['read_file'],
            requests_last_hour=2)
        assert len(r.findings) == 0
        assert 'consistent' in r.summary.lower()
