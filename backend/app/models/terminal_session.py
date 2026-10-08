from __future__ import annotations

import datetime as _dt
import enum
import uuid

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class TerminalSessionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    TIMEOUT = "timeout"


class TerminalSession(CoreBase):
    """Docker sandboxed terminal sessions.

    Ownership model (no circular FK):
      ToolExecution.terminal_session_id  →  terminal_sessions.id  (owns)
      TerminalSession.request_id         →  execution_requests.id (correlation)

    TerminalSession does NOT have a back-FK to tool_executions.
    Removing that back-reference is the accepted resolution for the circular
    FK problem: tool_executions must be created FIRST, then terminal_sessions
    is created with the tool_execution PK already known.

    Security defaults (all True / most restrictive):
      network_disabled  = True   (no outbound network)
      read_only_root    = True   (immutable rootfs)
      cap_drop_all      = True   (drop all Linux capabilities)
      no_new_privileges = True   (seccomp / no-new-privileges)
    """

    __tablename__ = "terminal_sessions"

    # Correlation back to the originating execution request (not the tool
    # execution row, avoiding the circular dependency).
    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("execution_requests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    container_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[TerminalSessionStatus] = mapped_column(
        SQLEnum(TerminalSessionStatus, name="term_sess_status", native_enum=False),
        nullable=False,
        default=TerminalSessionStatus.PENDING,
        index=True,
    )

    started_at: Mapped[_dt.datetime | None] = mapped_column(
        TIMESTAMP(timezone=False), nullable=True
    )
    stopped_at: Mapped[_dt.datetime | None] = mapped_column(
        TIMESTAMP(timezone=False), nullable=True
    )

    # Sandbox resource limits (mirrored from settings at spawn time)
    mem_limit_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=256)
    cpu_limit: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    # Security invariants — stored for audit; MUST all be True in normal operation
    network_disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    read_only_root: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cap_drop_all: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    no_new_privileges: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    workspace_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_terminal_sessions_request_id", "request_id"),
        Index("ix_terminal_sessions_status", "status"),
    )
