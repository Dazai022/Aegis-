from __future__ import annotations

import enum
import uuid

from sqlalchemy import Enum as SQLEnum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskAssessment(CoreBase):
    __tablename__ = "risk_assessments"

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("execution_requests.id", ondelete="CASCADE"), nullable=False, index=True, unique=True
    )
    total_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(
        SQLEnum(RiskLevel, name="risk_level", native_enum=False), nullable=False
    )
    signals: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
