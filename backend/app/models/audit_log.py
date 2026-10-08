from __future__ import annotations

import uuid

from sqlalchemy import Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class AuditLog(CoreBase):
    """Append-only audit chain. current_hash = SHA256(previous_hash || '|' || record_json_sorted).

    Never DELETE from this table. Append-only.
    """

    __tablename__ = "audit_logs"

    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # admin | agent | system
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)  # UUID stored as hex, allows non-admin actors
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    previous_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=False)
    current_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    record_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_logs_created", "created_at"),
        Index("ix_audit_logs_actor_action", "actor_type", "action"),
    )
