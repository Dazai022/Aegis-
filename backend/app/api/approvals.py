from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import datetime
from app.core.database import get_session
from app.core.deps import get_current_admin
from app.models.admin import Admin
from app.models.approval import Approval, ApprovalStatus
from app.approvals.service import approval_service

router = APIRouter(tags=['approvals'])

class ApprovalOut(BaseModel):
    id: uuid.UUID
    request_id: uuid.UUID
    status: str
    expires_at: datetime
    approval_notes: str | None
    model_config = {'from_attributes': True}

class ActionBody(BaseModel):
    notes: str | None = None

@router.get('', response_model=list[ApprovalOut])
async def list_approvals(admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(Approval).order_by(Approval.created_at.desc()))
    return r.scalars().all()

@router.get('/{approval_id}', response_model=ApprovalOut)
async def get_approval(approval_id: uuid.UUID, admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(Approval).where(Approval.id == approval_id))
    a = r.scalar_one_or_none()
    if not a: raise HTTPException(404, detail={'code':'NOT_FOUND','message':'Not found'})
    return a

@router.post('/{approval_id}/approve', response_model=ApprovalOut)
async def approve(approval_id: uuid.UUID, body: ActionBody = ActionBody(), admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    try:
        return await approval_service.approve(session, approval_id, admin.id, body.notes)
    except ValueError as e:
        code = 'CONFLICT' if 'already' in str(e) else 'GONE' if 'expired' in str(e) else 'NOT_FOUND'
        st = 409 if 'already' in str(e) else 410 if 'expired' in str(e) else 404
        raise HTTPException(st, detail={'code': code, 'message': str(e)})

@router.post('/{approval_id}/reject', response_model=ApprovalOut)
async def reject(approval_id: uuid.UUID, body: ActionBody = ActionBody(), admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    try:
        return await approval_service.reject(session, approval_id, admin.id, body.notes)
    except ValueError as e:
        code = 'CONFLICT' if 'already' in str(e) else 'NOT_FOUND'
        raise HTTPException(409 if 'already' in str(e) else 404, detail={'code': code, 'message': str(e)})
