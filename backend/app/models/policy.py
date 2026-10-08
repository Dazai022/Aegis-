from __future__ import annotations

import enum
import uuid

from sqlalchemy import (
    Boolean,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class PolicyAction(str, enum.Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Policy(CoreBase):
    """First-match-wins policy container. Versioned rules are in PolicyVersion."""

    __tablename__ = "policies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    default_action: Mapped[PolicyAction] = mapped_column(
        SQLEnum(PolicyAction, name="policy_action", native_enum=False),
        nullable=False,
        default=PolicyAction.REQUIRE_APPROVAL,
    )
    created_by_admin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False
    )
    updated_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_policies_active_priority", "is_active", "priority"),
    )
