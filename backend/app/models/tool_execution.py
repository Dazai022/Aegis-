from __future__ import annotations

import datetime as _dt
import enum
import uuid

from sqlalchemy import (
    TIMESTAMP,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class ToolExecutionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ToolExecution(CoreBase):
    __tablename__ = "tool_executions"

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("execution_requests.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    decision_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("decisions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("approvals.id", ondelete="SET NULL"), nullable=True, index=True
    )
    adapter_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    command: Mapped[str] = mapped_column(String(255), nullable=True)
    args_snapshot: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[ToolExecutionStatus] = mapped_column(
        SQLEnum(ToolExecutionStatus, name="tool_execution_status", native_enum=False),
        nullable=False,
        default=ToolExecutionStatus.PENDING,
        index=True,
    )
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    finished_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    stdout_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stderr_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    output_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    terminal_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("terminal_sessions.id", ondelete="SET NULL"), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_tool_executions_request_id", "request_id"),
        Index("ix_tool_executions_decision_id", "decision_id"),
        Index("ix_tool_executions_approval_id", "approval_id"),
        Index("ix_tool_executions_adapter_name", "adapter_name"),
        Index("ix_tool_executions_status", "status"),
    )
