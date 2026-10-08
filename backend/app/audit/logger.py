from __future__ import annotations
import hashlib
import json
import logging
import uuid
from datetime import datetime, UTC
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

log = logging.getLogger("aegis.audit")

# Keys that must NEVER appear in an audit record even in redacted form.
_SECRET_KEYS = frozenset([
    "password", "passwd", "token", "secret", "api_key", "apikey",
    "private_key", "privatekey", "jwt", "bearer", "authorization",
    "pepper", "aes_key", "master_key", "access_key", "client_secret",
])


def _redact_params(params: dict[str, Any], depth: int = 4) -> dict[str, Any]:
    if depth <= 0:
        return {}
    result: dict[str, Any] = {}
    for k, v in params.items():
        if k.lower() in _SECRET_KEYS:
            result[k] = "[REDACTED]"
        elif isinstance(v, dict):
            result[k] = _redact_params(v, depth - 1)
        elif isinstance(v, (list, tuple)):
            result[k] = [
                _redact_params(i, depth - 1) if isinstance(i, dict) else i
                for i in v
            ]
        else:
            result[k] = v
    return result


def _canonical_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _compute_hash(previous_hash: str | None, record: dict[str, Any]) -> str:
    prev = previous_hash or ""
    canonical = _canonical_json(record)
    raw = (prev + "|" + canonical).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AuditLogger:
    async def get_last_hash(self, session: AsyncSession) -> str | None:
        from sqlalchemy import select, desc
        from app.models.audit_log import AuditLog as AL
        result = await session.execute(
            select(AL.current_hash).order_by(desc(AL.created_at)).limit(1)
        )
        row = result.scalar_one_or_none()
        return row

    async def append(
        self,
        session: AsyncSession,
        actor_type: str,
        actor_id: str | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        record_data: dict[str, Any],
        comment: str | None = None,
    ) -> AuditLog:
        safe_record = _redact_params(record_data)
        for secret_key in _SECRET_KEYS:
            safe_record.pop(secret_key, None)

        previous_hash = await self.get_last_hash(session)
        current_hash = _compute_hash(previous_hash, safe_record)

        entry = AuditLog(
            id=uuid.uuid4(),
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            previous_hash=previous_hash,
            current_hash=current_hash,
            record_json=safe_record,
            comment=comment,
        )
        session.add(entry)
        await session.flush()
        log.debug(
            "audit record appended",
            extra={"aegis_fields": {
                "audit_id": str(entry.id),
                "action": action,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
            }},
        )
        return entry


audit_logger = AuditLogger()