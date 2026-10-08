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
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class ApiKeyStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ApiKey(CoreBase):
    """An HMAC-only agent API key. Never stores plaintext.

    `key_hash` = HMAC-SHA256(secret_bytes, msg=agent_secret_bytes)
    `key_mask` = "****ABCD" for admin display of last 4 chars.
    """

    __tablename__ = "api_keys"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    key_mask: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[ApiKeyStatus] = mapped_column(
        SQLEnum(ApiKeyStatus, name="api_key_status", native_enum=False),
        nullable=False,
        default=ApiKeyStatus.ACTIVE,
    )
    expires_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    revoked_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    revoked_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True
    )
    last_used_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    last_used_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_api_keys_agent_status", "agent_id", "status"),
    )
