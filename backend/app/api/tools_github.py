from __future__ import annotations
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_session
from app.core.deps import get_current_admin
from app.models.admin import Admin
from app.models.github_connection import GithubConnection, GHConnectionStatus
from app.security.crypto import AesGcm
from app.core.config import settings

router = APIRouter(tags=['tools-github'])

class GHConnCreate(BaseModel):
    owner: str
    repo: str
    token: str  # plaintext PAT - encrypted before storage
    scopes: list[str] = []

class GHConnOut(BaseModel):
    id: uuid.UUID
    owner: str
    repo: str
    status: str
    scopes: list
    created_at: datetime
    model_config = {'from_attributes': True}

@router.post('', response_model=GHConnOut, status_code=201)
async def create_connection(body: GHConnCreate, admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    gcm = AesGcm(settings.aes_master_key_bytes)
    encrypted = gcm.encrypt(body.token)
    conn = GithubConnection(id=uuid.uuid4(), admin_id=admin.id, owner=body.owner,
        repo=body.repo, scopes=body.scopes, encrypted_token_b64=encrypted,
        status=GHConnectionStatus.ACTIVE)
    session.add(conn)
    await session.flush()
    return conn

@router.get('', response_model=list[GHConnOut])
async def list_connections(admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(GithubConnection).where(GithubConnection.admin_id == admin.id))
    return r.scalars().all()

@router.delete('/{conn_id}', status_code=204)
async def delete_connection(conn_id: uuid.UUID, admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(GithubConnection).where(GithubConnection.id == conn_id, GithubConnection.admin_id == admin.id))
    conn = r.scalar_one_or_none()
    if not conn: raise HTTPException(404, detail={'code':'NOT_FOUND','message':'Not found'})
    conn.status = GHConnectionStatus.REVOKED
