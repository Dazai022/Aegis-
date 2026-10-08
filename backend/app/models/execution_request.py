from __future__ import annotations

import datetime as _dt
import enum
import uuid

from sqlalchemy import (
    TIMESTAMP,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class ExecutionState(str, enum.Enum):
    PENDING = "pending"
    EVALUATING = "evaluating"
    DECIDED = "decided"
    APPROVAL_PENDING = "approval_pending"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_REJECTED = "approval_rejected"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ExecutionRequest(CoreBase):
    __tablename__ = "execution_requests"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False
    )
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tool_args: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    state: Mapped[ExecutionState] = mapped_column(
        SQLEnum(ExecutionState, name="execution_state", native_enum=False),
        nullable=False,
        default=ExecutionState.PENDING,
        index=True,
    )
    input_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    queued_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    finished_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)

    __table_args__ = (
        Index("ix_execution_requests_agent_created", "agent_id", "created_at"),
        Index("ix_execution_requests_state_created", "state", "created_at"),
    )
