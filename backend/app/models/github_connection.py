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
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class GHConnectionStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    PENDING = "pending"


class GithubConnection(CoreBase):
    __tablename__ = "github_connections"

    admin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    installation_id: Mapped[str] = mapped_column(String(128), nullable=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    repo: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    encrypted_token_b64: Mapped[str] = mapped_column(Text, nullable=False)  # AES-GCM of token
    status: Mapped[GHConnectionStatus] = mapped_column(
        SQLEnum(GHConnectionStatus, name="gh_conn_status", native_enum=False),
        nullable=False,
        default=GHConnectionStatus.PENDING,
        index=True,
    )
    last_synced_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    webhook_secret_enc_b64: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_github_connections_admin_owner_repo", "admin_id", "owner", "repo", unique=True),
    )
