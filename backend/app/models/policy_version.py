from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class PolicyVersion(CoreBase):
    __tablename__ = "policy_versions"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    rules: Mapped[list[dict] | dict] = mapped_column(JSONB, nullable=False, default=list)
    changelog: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_admin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("policy_id", "version", name="uq_policy_versions_policy_version"),
        Index("ix_policy_versions_policy_version", "policy_id", "version"),
    )
