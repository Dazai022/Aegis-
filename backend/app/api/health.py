from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.core import database
from app.core import logging as aegis_logging
from app.core.config import settings

log = aegis_logging.logger
router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness check")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENV,
    }


@router.get("/health/ready", summary="Readiness check (verifies DB connectivity)")
async def ready() -> dict[str, object]:
    try:
        await database.check_connectivity()
    except Exception as exc:  # noqa: BLE001
        log.warning("DB readiness check failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "SERVICE_UNAVAILABLE",
                "message": "Database is not available.",
            },
        ) from exc
    return {"status": "ready", "service": settings.APP_NAME, "database": "ok"}
