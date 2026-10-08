from __future__ import annotations
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_session
from app.models.admin import Admin
from app.models.agent import Agent
from app.models.api_key import ApiKey, ApiKeyStatus
from app.security.jwt import decode_access_token, JWTError
from app.security.crypto import HmacHelper

_401 = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
    detail={'code':'UNAUTHENTICATED','message':'Authentication required'})
_403 = HTTPException(status_code=status.HTTP_403_FORBIDDEN,
    detail={'code':'FORBIDDEN','message':'Insufficient permissions'})

async def get_current_admin(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> Admin:
    if not authorization or not authorization.startswith('Bearer '):
        raise _401
    token = authorization[7:]
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise _401
    admin_id = payload.get('sub')
    if not admin_id:
        raise _401
    r = await session.execute(select(Admin).where(Admin.id == admin_id))
    admin = r.scalar_one_or_none()
    if not admin or not admin.is_active:
        raise _401
    return admin

async def get_current_agent(
    x_api_key: str | None = Header(default=None, alias='X-Api-Key'),
    session: AsyncSession = Depends(get_session),
) -> Agent:
    if not x_api_key:
        raise _401
    key_hash = HmacHelper.api_key_hash(x_api_key)
    r = await session.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
    api_key = r.scalar_one_or_none()
    if not api_key or api_key.status != ApiKeyStatus.ACTIVE:
        raise _401
    ar = await session.execute(select(Agent).where(Agent.id == api_key.agent_id))
    agent = ar.scalar_one_or_none()
    if not agent or agent.status.value != 'active':
        raise _401
    return agent
