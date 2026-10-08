from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any, AsyncGenerator

from sqlalchemy import (
    TIMESTAMP,
    ColumnExpressionArgument,
    MetaData,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    declared_attr,
    mapped_column,
)

from app.core.config import settings
from app.core import logging as aegis_logging

log = aegis_logging.logger


NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Base(DeclarativeBase):
    metadata = metadata


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.UTC).replace(tzinfo=None)


class UuidPKMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        default=uuid.uuid4,
    )


class TimestampsMixin:
    created_at: Mapped[_dt.datetime] = mapped_column(
        TIMESTAMP(timezone=False),
        nullable=False,
        server_default=func.now(),
        default=utcnow,
    )
    updated_at: Mapped[_dt.datetime] = mapped_column(
        TIMESTAMP(timezone=False),
        nullable=False,
        server_default=func.now(),
        default=utcnow,
        onupdate=utcnow,
    )


class CoreBase(Base, UuidPKMixin, TimestampsMixin):
    __abstract__ = True


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(
        url or settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
        future=True,
        connect_args={
            "command_timeout": settings.DB_CONNECT_TIMEOUT,
            "server_settings": {
                "jit": "off",
                "application_name": settings.APP_NAME,
            },
        }
        if (url or settings.DATABASE_URL).startswith("postgresql")
        else {},
    )


def engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=engine(),
            expire_on_commit=False,
            autoflush=False,
            future=True,
        )
    return _session_factory


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a transactional session."""
    s = session_factory()()
    try:
        yield s
        await s.commit()
    except Exception:
        await s.rollback()
        raise
    finally:
        await s.close()


async def check_connectivity() -> None:
    """Check DB connectivity with a simple query. Raises on failure."""
    s = session_factory()()
    try:
        await s.execute(text("SELECT 1"))
    finally:
        await s.close()


async def dispose_engine() -> None:
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


__all__ = [
    "Base",
    "CoreBase",
    "TIMESTAMP",
    "UUID",
    "metadata",
    "UuidPKMixin",
    "TimestampsMixin",
    "engine",
    "session_factory",
    "get_session",
    "check_connectivity",
    "dispose_engine",
    "utcnow",
]
