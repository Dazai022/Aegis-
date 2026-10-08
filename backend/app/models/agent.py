from __future__ import annotations

import datetime as _dt
import enum
import uuid

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class AgentStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    DISABLED = "disabled"


class Agent(CoreBase):
    __tablename__ = "agents"

    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[AgentStatus] = mapped_column(
        SQLEnum(AgentStatus, name="agent_status", native_enum=False),
        nullable=False,
        default=AgentStatus.ACTIVE,
        index=True,
    )
    created_by_admin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    last_used_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)

    __table_args__ = (Index("ix_agents_status_created", "status", "created_at"),)
