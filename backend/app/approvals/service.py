from __future__ import annotations
import hashlib, json, uuid
from datetime import datetime, timedelta, UTC
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.approval import Approval, ApprovalStatus
from app.models.execution_request import ExecutionRequest, ExecutionState
from app.core.config import settings
from app.core import logging as aegis_logging

log = aegis_logging.logger

def _param_digest(params: dict) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True, separators=(',',':')).encode()).hexdigest()

class ApprovalService:
    async def create(self, session: AsyncSession, request_id: uuid.UUID, decision_id: uuid.UUID, params: dict) -> Approval:
        expires = datetime.utcnow() + timedelta(seconds=settings.APPROVAL_EXPIRE_SECONDS)
        approval = Approval(
            id=uuid.uuid4(), request_id=request_id, decision_id=decision_id,
            status=ApprovalStatus.PENDING,
            expires_at=expires,
            param_digest=_param_digest(params),
            double_spend_nonce=str(uuid.uuid4()),
        )
        session.add(approval)
        await session.flush()
        log.info('approval created', extra={'aegis_fields': {'approval_id': str(approval.id), 'request_id': str(request_id), 'expires_at': str(expires)}})
        return approval

    async def approve(self, session: AsyncSession, approval_id: uuid.UUID, admin_id: uuid.UUID, notes: str | None = None) -> Approval:
        r = await session.execute(select(Approval).where(Approval.id == approval_id))
        approval = r.scalar_one_or_none()
        if not approval: raise ValueError('Approval not found')
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError(f'Approval already {approval.status.value}')
        if datetime.utcnow() > approval.expires_at:
            approval.status = ApprovalStatus.EXPIRED
            raise ValueError('Approval has expired')
        approval.status = ApprovalStatus.APPROVED
        approval.actioned_by_admin_id = admin_id
        approval.consumed_at = datetime.utcnow()
        approval.approval_notes = notes
        # Update execution request state
        er = await session.execute(select(ExecutionRequest).where(ExecutionRequest.id == approval.request_id))
        req = er.scalar_one_or_none()
        if req: req.state = ExecutionState.DECIDED
        return approval

    async def reject(self, session: AsyncSession, approval_id: uuid.UUID, admin_id: uuid.UUID, reason: str | None = None) -> Approval:
        r = await session.execute(select(Approval).where(Approval.id == approval_id))
        approval = r.scalar_one_or_none()
        if not approval: raise ValueError('Approval not found')
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError(f'Approval already {approval.status.value}')
        approval.status = ApprovalStatus.REJECTED
        approval.actioned_by_admin_id = admin_id
        approval.status_reason = reason
        er = await session.execute(select(ExecutionRequest).where(ExecutionRequest.id == approval.request_id))
        req = er.scalar_one_or_none()
        if req: req.state = ExecutionState.APPROVAL_REJECTED
        return approval

approval_service = ApprovalService()
