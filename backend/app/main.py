from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError, HTTPException as FastAPIHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import api_router
from app.core.config import settings
from app.core import logging as aegis_logging

log = aegis_logging.logger


ERROR_CODE_MAP: dict[int, str] = {
    status.HTTP_400_BAD_REQUEST: "INVALID_REQUEST",
    status.HTTP_401_UNAUTHORIZED: "UNAUTHENTICATED",
    status.HTTP_403_FORBIDDEN: "FORBIDDEN",
    status.HTTP_404_NOT_FOUND: "NOT_FOUND",
    status.HTTP_409_CONFLICT: "CONFLICT",
    status.HTTP_410_GONE: "GONE",
    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE: "REQUEST_TOO_LARGE",
    status.HTTP_422_UNPROCESSABLE_ENTITY: "VALIDATION_ERROR",
    status.HTTP_429_TOO_MANY_REQUESTS: "TOO_MANY_REQUESTS",
    status.HTTP_503_SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
}


def _error_body(code: str, message: str) -> dict[str, object]:
    return {"error": {"code": code, "message": message}}


def _code_for_status(status_code: int, fallback: str = "INTERNAL_ERROR") -> str:
    return ERROR_CODE_MAP.get(status_code, fallback)


application = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Aegis: A Runtime Security Framework for Autonomous AI Agents. "
        "Intercepts and evaluates every tool-call from AI agents before execution."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    servers=[{"url": "/", "description": settings.ENV}],
    debug=not settings.is_production,
)

application.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Authorization",
        "Content-Type",
        "X-Api-Key",
        "X-Request-ID",
        "X-CSRF-Token",
    ],
    expose_headers=["X-Request-ID"],
    max_age=600,
)


@application.middleware("http")
async def security_headers_and_request_id(request: Request, call_next) -> Response:  # noqa: ANN001
    start = time.perf_counter_ns()
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    aegis_logging.bind_request_id(rid)
    body_too_large_error: JSONResponse | None = None
    try:
        # Cap total request bytes at MAX_REQUEST_BYTES using streaming body length.
        max_bytes = settings.MAX_REQUEST_BYTES
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                content_length = int(request.headers.get("Content-Length") or "0")
            except ValueError:
                content_length = 0
            if content_length > max_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content=_error_body(
                        "REQUEST_TOO_LARGE",
                        f"Request body exceeds maximum {max_bytes} bytes.",
                    ),
                    headers={"X-Request-ID": rid},
                )
        response: Response = await call_next(request)
    except Exception as exc:  # noqa: BLE001
        # Fallback to exception handler; but keep request id
        if settings.is_production:
            log.exception("Unhandled error in middleware")
            body = _error_body(
                "INTERNAL_ERROR", "An internal error occurred. Administrators were notified."
            )
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=body
            )
        else:
            raise
    # Security headers
    headers = response.headers
    headers.setdefault("X-Request-ID", rid)
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
    )
    if request.url.scheme == "https":
        headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    headers.setdefault("Referrer-Policy", "same-origin")
    headers.setdefault(
        "Permissions-Policy",
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    )
    try:
        del headers["server"]
    except KeyError:
        pass
    headers["server"] = ""
    # Timing telemetry (logging only, no response header leak)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    log.debug(
        "request",
        extra={
            "aegis_fields": {
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round(elapsed_ms, 2),
            }
        },
    )
    return response


application.include_router(api_router)


@application.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail and "message" in detail:
        body = _error_body(detail["code"], detail["message"])
    else:
        msg = detail if isinstance(detail, str) else "HTTP error"
        body = _error_body(_code_for_status(exc.status_code), msg)
    return JSONResponse(status_code=exc.status_code, content=body)


@application.exception_handler(FastAPIHTTPException)
async def fastapi_http_exception_handler(
    request: Request, exc: FastAPIHTTPException
) -> JSONResponse:
    return await http_exception_handler(request, exc)


@application.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = exc.errors()
    # Keep details minimal to avoid leaking sensitive parsed JSON segments;
    # only include loc + type + msg.
    sanitized = [
        {
            "loc": list(e.get("loc", [])),
            "type": e.get("type"),
            "msg": e.get("msg"),
        }
        for e in errors
    ]
    log.debug(
        "validation error", extra={"aegis_fields": {"validation_errors": sanitized}}
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed.",
                "details": sanitized,
            }
        },
    )


@application.exception_handler(Exception)
async def catch_all_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled exception: %s", type(exc).__name__)
    if settings.is_production:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_body(
                "INTERNAL_ERROR",
                "An internal error occurred. Administrators were notified.",
            ),
        )
    # Re-raise for debugging in dev — the middleware wrapper also catches so
    # we do not leak Traceback but let the developer inspect.
    raise


app = application
__all__ = ["app", "application"]
