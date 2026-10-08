from __future__ import annotations

import json
import logging
import logging.config
import re
import sys
import time
import uuid
from contextvars import ContextVar
from typing import Any

from app.core.config import settings


REQUEST_ID_REDACTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    re.compile(r"(?:^|\s|['\":=])ag-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?:sk|pk|rk|tk)_[A-Za-z0-9_\-]{20,}"),
    re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|private[_-]?key)\s*[=:]\s*['\"]?[^'\",\s]{3,}"),
    re.compile(r"AES_MASTER_KEY_BASE64[=: ]\S+"),
    re.compile(r"PEPPER[=: ]\S+"),
    re.compile(r"JWT_SECRET[=: ]\S+"),
]

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
agent_id_ctx: ContextVar[str | None] = ContextVar("agent_id", default=None)


def _redact(message: str) -> str:
    if not message:
        return message
    out = message
    for p in REQUEST_ID_REDACTION_PATTERNS:
        out = p.sub(lambda m: _mask(m.group(0)), out)
    return out


def _mask(token: str) -> str:
    stripped = token.strip()
    if len(stripped) <= 8:
        return "[REDACTED]"
    head = stripped[: min(3, len(stripped) // 6)]
    tail = stripped[-min(3, len(stripped) // 6) :]
    return f"{head}***{tail}" if head else "[REDACTED]"


class AegisFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        record.message = _redact(record.getMessage())
        if record.exc_info:
            text = self.formatException(record.exc_info)
            record.exc_text = _redact(text)
        else:
            record.exc_text = None
        rec: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
            "request_id": request_id_ctx.get(),
            "agent_id": agent_id_ctx.get(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_text:
            rec["error"] = record.exc_text
        for key, value in getattr(record, "aegis_fields", {}).items() if isinstance(getattr(record, "aegis_fields", None), dict) else {}:
            rec[key] = value
        return json.dumps(rec, ensure_ascii=False, default=str)


def _configure() -> None:
    level = logging.INFO if settings.is_production else logging.DEBUG
    handlers: dict[str, dict[str, Any]] = {
        "console": {
            "class": "logging.StreamHandler",
            "level": level,
            "stream": sys.stderr,
            "formatter": "aegis_json",
        },
    }
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"aegis_json": {"()": AegisFormatter}},
        "handlers": handlers,
        "root": {"level": level, "handlers": ["console"]},
        "loggers": {
            "uvicorn": {"level": logging.INFO, "handlers": ["console"], "propagate": False},
            "uvicorn.access": {"level": logging.WARNING, "handlers": ["console"], "propagate": False},
            "sqlalchemy.engine": {"level": logging.WARNING, "handlers": ["console"], "propagate": False},
        },
    }
    logging.config.dictConfig(config)


_configure()

logger = logging.getLogger("aegis")


def new_request_id() -> str:
    return str(uuid.uuid4())


def bind_request_id(rid: str | None) -> str:
    value = rid or new_request_id()
    request_id_ctx.set(value)
    return value


def bind_agent_id(aid: str | None) -> None:
    agent_id_ctx.set(aid)


def augment(**fields: Any) -> dict[str, Any]:
    return fields
