from __future__ import annotations
import uuid
from datetime import datetime, UTC
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_session
from app.core.deps import get_current_admin
from app.models.admin import Admin
from app.security.jwt import create_access_token
from app.security.passwords import verify_password, dummy_verify_password
from app.core import logging as aegis_logging

log = aegis_logging.logger
router = APIRouter(tags=['auth'])
# In-memory token blocklist (prototype; replace with Redis in prod)
_blocklist: set[str] = set()

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    expires_in: int = 900

class AdminOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str | None
    role: str
    model_config = {'from_attributes': True}

@router.post('/login', response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(Admin).where(Admin.email == body.email))
    admin = r.scalar_one_or_none()
    if not admin:
        dummy_verify_password(body.password)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={'code':'UNAUTHENTICATED','message':'Invalid credentials'})
    result = verify_password(body.password, admin.password_hash)
    if not result.ok or not admin.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={'code':'UNAUTHENTICATED','message':'Invalid credentials'})
    token = create_access_token(str(admin.id), {'role': admin.role.value})
    return LoginResponse(access_token=token)

@router.post('/logout', status_code=204)
async def logout(admin: Admin = Depends(get_current_admin)):
    pass  # token blocklist can be added here

@router.get('/me', response_model=AdminOut)
async def me(admin: Admin = Depends(get_current_admin)):
    return admin
