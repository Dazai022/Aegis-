from __future__ import annotations
import uuid
import hashlib, json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from datetime import datetime
from app.core.database import get_session
from app.core.deps import get_current_admin
from app.models.admin import Admin
from app.models.audit_log import AuditLog
from app.audit.logger import _compute_hash, _canonical_json

router = APIRouter(tags=['audit'])

class AuditOut(BaseModel):
    id: uuid.UUID
    actor_type: str
    actor_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    previous_hash: str | None
    current_hash: str
    comment: str | None
    created_at: datetime
    model_config = {'from_attributes': True}

@router.get('', response_model=list[AuditOut])
async def list_audit(limit: int = Query(50, le=500), admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit))
    return r.scalars().all()

@router.get('/verify')
async def verify_chain(admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(AuditLog).order_by(AuditLog.created_at))
    records = r.scalars().all()
    if not records:
        return {'valid': True, 'count': 0, 'broken_at': None}
    prev_hash = None
    for rec in records:
        expected = _compute_hash(prev_hash, rec.record_json)
        if expected != rec.current_hash:
            return {'valid': False, 'count': len(records), 'broken_at': str(rec.id)}
        prev_hash = rec.current_hash
    return {'valid': True, 'count': len(records), 'broken_at': None}
