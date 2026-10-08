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
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"
    CANCELLED = "cancelled"


class Approval(CoreBase):
    """Double-spend protected approvals: each approval is consumed exactly once."""

    __tablename__ = "approvals"

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("execution_requests.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    decision_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("decisions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[ApprovalStatus] = mapped_column(
        SQLEnum(ApprovalStatus, name="approval_status", native_enum=False),
        nullable=False,
        default=ApprovalStatus.PENDING,
        index=True,
    )
    status_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    requested_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True
    )
    actioned_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True
    )
    expires_at: Mapped[_dt.datetime] = mapped_column(TIMESTAMP(timezone=False), nullable=False, index=True)
    consumed_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    cancelled_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    param_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    double_spend_nonce: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    approval_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_params_snapshot: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_approvals_status_expires", "status", "expires_at"),
        Index("ix_approvals_request_status", "request_id", "status"),
    )
