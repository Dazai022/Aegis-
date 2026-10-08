from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_session
from app.core.deps import get_current_agent
from app.core import logging as aegis_logging
from app.models.agent import Agent
from app.schemas.execution import ExecuteRequest, ExecuteResponse
from app.services.gateway import gateway_service
from app.websocket.hub import hub

log = aegis_logging.logger
router = APIRouter(tags=['execution'])


@router.post('/execute', response_model=ExecuteResponse, status_code=status.HTTP_200_OK,
             summary='Submit a tool execution request for security evaluation')
async def execute_request(
    body: ExecuteRequest,
    request: Request,
    agent: Agent = Depends(get_current_agent),
    session: AsyncSession = Depends(get_session),
) -> ExecuteResponse:
    correlation_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
    aegis_logging.bind_request_id(correlation_id)
    aegis_logging.bind_agent_id(str(agent.id))

    await hub.publish('requests.new', {
        'tool': body.tool.value, 'action': body.action,
        'agent_id': str(agent.id), 'correlation_id': correlation_id,
    })

    response = await gateway_service.process(
        request=body, agent=agent,
        correlation_id=correlation_id, session=session,
    )

    await hub.publish('requests.decision', {
        'request_id': str(response.request_id),
        'decision': response.decision.value,
        'risk_score': response.risk_score,
        'risk_level': response.risk_level.value,
        'requires_approval': response.requires_approval,
    })

    if response.decision.value == 'BLOCK':
        await hub.publish('requests.blocked', {'request_id': str(response.request_id), 'reason': response.reason})
    elif response.requires_approval:
        await hub.publish('approvals.requested', {'request_id': str(response.request_id)})

    return response
