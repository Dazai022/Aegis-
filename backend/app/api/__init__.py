from __future__ import annotations
from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.agents import router as agents_router
from app.api.policies import router as policies_router
from app.api.approvals import router as approvals_router
from app.api.audit import router as audit_router
from app.api.requests import router as requests_router
from app.api.tools_github import router as gh_router
from app.api.execute import router as execute_router
from app.websocket.hub import router as ws_router

api_router = APIRouter()
api_router.include_router(health_router, prefix='')
api_router.include_router(auth_router, prefix='/auth')
api_router.include_router(agents_router, prefix='/agents')
api_router.include_router(policies_router, prefix='/policies')
api_router.include_router(approvals_router, prefix='/approvals')
api_router.include_router(audit_router, prefix='/audit')
api_router.include_router(requests_router, prefix='/requests')
api_router.include_router(gh_router, prefix='/tools/github')
api_router.include_router(execute_router, prefix='/v1')
api_router.include_router(ws_router, prefix='')

__all__ = ['api_router']
