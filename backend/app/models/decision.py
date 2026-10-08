from __future__ import annotations

import enum
import uuid

from sqlalchemy import Enum as SQLEnum, ForeignKey, Integer, String, Text, UniqueConstraint, ForeignKeyConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class DecisionAction(str, enum.Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Decision(CoreBase):
    __tablename__ = "decisions"

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("execution_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,
    )
    policy_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=True
    )
    matched_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[DecisionAction] = mapped_column(
        SQLEnum(DecisionAction, name="decision_action", native_enum=False),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_rule: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    precedence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
