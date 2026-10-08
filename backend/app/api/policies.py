from __future__ import annotations
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Any
from app.core.database import get_session
from app.core.deps import get_current_admin
from app.models.admin import Admin
from app.models.policy import Policy, PolicyAction
from app.models.policy_version import PolicyVersion

router = APIRouter(tags=['policies'])

class PolicyRuleIn(BaseModel):
    name: str
    priority: int = 10
    enabled: bool = True
    tool: str | None = None
    action_pattern: str | None = None
    parameter_constraints: dict[str, Any] = {}
    effect: str = 'REQUIRE_APPROVAL'
    reason: str = ''

class PolicyCreateRequest(BaseModel):
    name: str
    description: str | None = None
    priority: int = 10
    default_action: str = 'REQUIRE_APPROVAL'
    rules: list[PolicyRuleIn] = []

class PolicyOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    priority: int
    default_action: str
    is_active: bool
    current_version: int
    created_at: datetime
    model_config = {'from_attributes': True}

@router.post('', response_model=PolicyOut, status_code=201)
async def create_policy(body: PolicyCreateRequest, admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    policy = Policy(id=uuid.uuid4(), name=body.name, description=body.description, priority=body.priority, default_action=PolicyAction(body.default_action), created_by_admin_id=admin.id)
    session.add(policy)
    await session.flush()
    pv = PolicyVersion(id=uuid.uuid4(), policy_id=policy.id, version=1, rules=[r.model_dump() for r in body.rules], created_by_admin_id=admin.id)
    session.add(pv)
    return policy

@router.get('', response_model=list[PolicyOut])
async def list_policies(admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(Policy).order_by(Policy.priority))
    return r.scalars().all()

@router.patch('/{policy_id}/toggle', response_model=PolicyOut)
async def toggle_policy(policy_id: uuid.UUID, admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(Policy).where(Policy.id == policy_id))
    p = r.scalar_one_or_none()
    if not p: raise HTTPException(404, detail={'code':'NOT_FOUND','message':'Policy not found'})
    p.is_active = not p.is_active
    return p

@router.delete('/{policy_id}', status_code=204)
async def delete_policy(policy_id: uuid.UUID, admin: Admin = Depends(get_current_admin), session: AsyncSession = Depends(get_session)):
    r = await session.execute(select(Policy).where(Policy.id == policy_id))
    p = r.scalar_one_or_none()
    if not p: raise HTTPException(404, detail={'code':'NOT_FOUND','message':'Policy not found'})
    await session.delete(p)
