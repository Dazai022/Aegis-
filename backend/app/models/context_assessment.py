from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class ContextAssessment(CoreBase):
    __tablename__ = "context_assessments"

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("execution_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,
    )
    history_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    recent_actions: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    environment_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    sensitive_indicators: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
