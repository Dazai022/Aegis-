from __future__ import annotations

import datetime as _dt
import enum

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Enum as SQLEnum,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import CoreBase


class AdminRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    VIEWER = "viewer"


class Admin(CoreBase):
    __tablename__ = "admins"

    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[AdminRole] = mapped_column(
        SQLEnum(AdminRole, name="admin_role", create_constraint=False, native_enum=False),
        nullable=False,
        default=AdminRole.ADMIN,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    locked_until: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    failed_password_attempts: Mapped[int] = mapped_column(nullable=False, default=0, server_default=text("0"))
    last_login_at: Mapped[_dt.datetime | None] = mapped_column(TIMESTAMP(timezone=False), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
