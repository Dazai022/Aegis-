"""Import smoke test for all Phase 3+ modules."""
from __future__ import annotations
import pytest

def test_gateway_import():
    from app.services.gateway import gateway_service, _sanitize_params, _input_digest
    assert type(gateway_service).__name__ == "GatewayService"
    assert _sanitize_params({"token": "x"}) == {"token": "[REDACTED]"}

def test_gateway_has_tool_execution():
    import inspect, app.services.gateway as gm
    src = inspect.getsource(gm)
    assert "ToolExecution" in src
    assert "github_adapter" in src
    assert "terminal_adapter" in src
    assert "approval_row" in src

def test_github_adapter_import():
    from app.tools.github.adapter import github_adapter, GitHubAdapter
    assert isinstance(github_adapter, GitHubAdapter)

def test_terminal_adapter_import():
    from app.tools.terminal.adapter import terminal_adapter, SecureTerminalAdapter, TerminalResult
    assert isinstance(terminal_adapter, SecureTerminalAdapter)

def test_terminal_hard_block():
    from app.tools.terminal.adapter import terminal_adapter
    r = terminal_adapter.execute("rm -rf /")
    assert r.blocked is True
    assert r.exit_code == -1

def test_terminal_safe_command():
    from app.tools.terminal.adapter import terminal_adapter
    # Harmless echo on any platform
    r = terminal_adapter.execute("echo hello")
    # On Windows sh may not be available - just check it runs without crash
    assert r.blocked is False

def test_websocket_hub_import():
    from app.websocket.hub import hub, PubSubHub
    assert isinstance(hub, PubSubHub)

def test_approvals_import():
    from app.approvals.service import approval_service, ApprovalService
    assert isinstance(approval_service, ApprovalService)

def test_crypto_research_import():
    from app.crypto_research.cipher import AegisX128, _MARKER
    assert "NOT-FOR-PRODUCTION" in _MARKER

def test_crypto_research_roundtrip():
    import os
    from app.crypto_research.cipher import AegisX128
    key = os.urandom(32)
    c = AegisX128(key)
    pt = b"Hello Aegis research cipher"
    ct, tag = c.encrypt(pt)
    recovered = c.decrypt(ct, tag)
    assert recovered == pt

def test_crypto_research_tamper_detected():
    import os
    from app.crypto_research.cipher import AegisX128
    key = os.urandom(32)
    c = AegisX128(key)
    ct, tag = c.encrypt(b"tamper me")
    bad_tag = bytes(b ^ 0xFF for b in tag)
    with pytest.raises(ValueError):
        c.decrypt(ct, bad_tag)

def test_all_api_routes():
    from app.main import app
    paths = {r.path for r in app.routes if hasattr(r, "path")}
    assert "/health" in paths
    assert "/v1/execute" in paths
    assert "/auth/login" in paths
    assert "/agents" in paths
    assert "/approvals" in paths
    assert "/audit" in paths
    assert "/ws/events" in paths
