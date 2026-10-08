from __future__ import annotations
import secrets, uuid
from datetime import datetime, UTC
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_session
from app.core.deps import get_current_admin, get_current_agent
from app.models.admin import Admin
from app.models.agent import Agent, AgentStatus
from app.models.api_key import ApiKey, ApiKeyStatus
from app.security.crypto import HmacHelper

router = APIRouter(tags=['agents'])

class CreateAgentRequest(BaseModel):
    display_name: str
    description: str | None = None

class AgentCreatedResponse(BaseModel):
    id: uuid.UUID
    display_name: str
    status: str
    plaintext_key: str  # shown ONCE, never again
    key_mask: str

class AgentOut(BaseModel):
    id: uuid.UUID
    display_name: str
    status: str
    created_at: datetime
    model_config = {'from_attributes': True}

@router.post('', response_model=AgentCreatedResponse, status_code=201)
async def create_agent(body: CreateAgentRequest,
    admin: Admin = Depends(get_current_admin),
    session: AsyncSession = Depends(get_session)):
    agent = Agent(id=uuid.uuid4(), display_name=body.display_name,
        description=body.description, created_by_admin_id=admin.id)
    session.add(agent)
    await session.flush()
    raw_key = 'ag-' + secrets.token_urlsafe(32)
    key_hash = HmacHelper.api_key_hash(raw_key)
    mask = '****' + raw_key[-4:]
    api_key = ApiKey(id=uuid.uuid4(), agent_id=agent.id,
        name='default', key_hash=key_hash, key_mask=mask)
    session.add(api_key)
    await session.flush()
    return AgentCreatedResponse(id=agent.id, display_name=agent.display_name,
        status=agent.status.value, plaintext_key=raw_key, key_mask=mask)

@router.get('', response_model=list[AgentOut])
async def list_agents(admin: Admin = Depends(get_current_admin),
    session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(Agent))
    return r.scalars().all()

@router.post('/{agent_id}/revoke', status_code=204)
async def revoke_agent(agent_id: uuid.UUID,
    admin: Admin = Depends(get_current_admin),
    session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(ApiKey).where(ApiKey.agent_id == agent_id))
    for key in r.scalars().all():
        key.status = ApiKeyStatus.REVOKED
        key.revoked_at = datetime.now(UTC).replace(tzinfo=None)
        key.revoked_by_admin_id = admin.id
    ar = await session.execute(select(Agent).where(Agent.id == agent_id))
    agent = ar.scalar_one_or_none()
    if agent: agent.status = AgentStatus.REVOKED

@router.get('/me')
async def agent_me(agent: Agent = Depends(get_current_agent)):
    return {'id': str(agent.id), 'display_name': agent.display_name, 'status': agent.status.value}
