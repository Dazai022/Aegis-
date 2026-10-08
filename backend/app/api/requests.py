from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from datetime import datetime
from app.core.database import get_session
from app.core.deps import get_current_admin
from app.models.admin import Admin
from app.models.execution_request import ExecutionRequest
from app.models.decision import Decision
from app.models.risk_assessment import RiskAssessment

router = APIRouter(tags=['requests'])

class RequestOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    tool_name: str
    state: str
    input_digest: str
    correlation_id: str | None
    created_at: datetime
    model_config = {'from_attributes': True}

@router.get('', response_model=list[RequestOut])
async def list_requests(limit: int = Query(50, le=500), admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(ExecutionRequest).order_by(desc(ExecutionRequest.created_at)).limit(limit))
    return r.scalars().all()

@router.get('/{request_id}')
async def get_request(request_id: uuid.UUID, admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(ExecutionRequest).where(ExecutionRequest.id == request_id))
    req = r.scalar_one_or_none()
    if not req: return {'error': 'not found'}
    d = await session.execute(select(Decision).where(Decision.request_id == request_id))
    dec = d.scalar_one_or_none()
    rs = await session.execute(select(RiskAssessment).where(RiskAssessment.request_id == request_id))
    risk = rs.scalar_one_or_none()
    return {
        'id': str(req.id), 'agent_id': str(req.agent_id),
        'tool': req.tool_name, 'state': req.state.value,
        'created_at': str(req.created_at),
        'correlation_id': req.correlation_id,
        'decision': {'action': dec.action.value, 'reason': dec.reason, 'precedence': dec.precedence} if dec else None,
        'risk': {'score': risk.total_score, 'level': risk.risk_level, 'signals': risk.signals} if risk else None,
    }
