"""
Tests for model integrity:
- All models import without error
- No circular FK between tool_executions and terminal_sessions
- terminal_sessions has request_id FK (not execution_id)
- tool_executions.terminal_session_id -> terminal_sessions.id exists
- Decision.matched_rule_id has bounded length
- ToolExecution.approval_id has an index
"""
from __future__ import annotations
import pytest


def test_all_models_import():
    from app.core.database import Base
    import app.models
    assert len(Base.metadata.tables) >= 14


def test_no_circular_fk_terminal_tool():
    from app.core.database import Base
    import app.models  # noqa: F401
    ts_table = Base.metadata.tables["terminal_sessions"]
    te_table = Base.metadata.tables["tool_executions"]
    ts_to_te = [fk for fk in ts_table.foreign_keys if fk.column.table.name == "tool_executions"]
    te_to_ts = [fk for fk in te_table.foreign_keys if fk.column.table.name == "terminal_sessions"]
    assert len(ts_to_te) == 0, "terminal_sessions must NOT have FK to tool_executions"
    assert len(te_to_ts) == 1, "tool_executions must have exactly one FK to terminal_sessions"


def test_terminal_sessions_has_request_id_not_execution_id():
    from app.core.database import Base
    import app.models  # noqa: F401
    ts_table = Base.metadata.tables["terminal_sessions"]
    col_names = [c.name for c in ts_table.columns]
    assert "execution_id" not in col_names
    assert "request_id" in col_names


def test_decision_matched_rule_id_is_bounded():
    from app.core.database import Base
    import app.models  # noqa: F401
    d_table = Base.metadata.tables["decisions"]
    col = d_table.c["matched_rule_id"]
    # Must have explicit length <= 128, not unbounded VARCHAR
    assert hasattr(col.type, "length") and col.type.length is not None, "matched_rule_id must have explicit length"
    assert col.type.length <= 128


def test_tool_execution_approval_id_indexed():
    from app.core.database import Base
    import app.models  # noqa: F401
    te_table = Base.metadata.tables["tool_executions"]
    indexed_cols = set()
    for idx in te_table.indexes:
        for col in idx.columns:
            indexed_cols.add(col.name)
    assert "approval_id" in indexed_cols, "approval_id must have an index"


def test_audit_log_has_hash_chain_columns():
    from app.core.database import Base
    import app.models  # noqa: F401
    al_table = Base.metadata.tables["audit_logs"]
    col_names = [c.name for c in al_table.columns]
    assert "previous_hash" in col_names
    assert "current_hash" in col_names
    assert "record_json" in col_names
    # current_hash must be unique
    ch_col = al_table.c["current_hash"]
    assert ch_col.unique is True


def test_api_keys_no_plaintext_column():
    from app.core.database import Base
    import app.models  # noqa: F401
    ak_table = Base.metadata.tables["api_keys"]
    col_names = [c.name for c in ak_table.columns]
    # Must have hmac hash, must NOT have a column called 'key' or 'plaintext'
    assert "key_hash" in col_names
    assert "key" not in col_names
    assert "plaintext" not in col_names
    assert "plaintext_key" not in col_names