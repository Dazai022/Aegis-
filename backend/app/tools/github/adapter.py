from __future__ import annotations
import uuid
from typing import Any
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.github_connection import GithubConnection, GHConnectionStatus
from app.security.crypto import AesGcm
from app.core.config import settings
from app.core import logging as aegis_logging

log = aegis_logging.logger
GITHUB_API = 'https://api.github.com'
TIMEOUT = 15.0

class GitHubError(Exception):
    def __init__(self, message: str, status_code: int = 0, category: str = 'GITHUB_ERROR'):
        super().__init__(message)
        self.status_code = status_code
        self.category = category

class GitHubAdapter:
    def _gcm(self) -> AesGcm: return AesGcm(settings.aes_master_key_bytes)

    async def _get_token(self, session: AsyncSession, connection_id: uuid.UUID) -> str:
        r = await session.execute(select(GithubConnection).where(GithubConnection.id == connection_id))
        conn = r.scalar_one_or_none()
        if not conn or conn.status != GHConnectionStatus.ACTIVE:
            raise GitHubError('GitHub connection not found or inactive', category='CONFIG_ERROR')
        return self._gcm().decrypt(conn.encrypted_token_b64)

    def _headers(self, token: str) -> dict[str, str]:
        return {'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3+json', 'X-GitHub-Api-Version': '2022-11-28'}

    def _handle_response(self, resp: httpx.Response) -> Any:
        if resp.status_code == 401: raise GitHubError('Unauthorized', 401, 'AUTH_ERROR')
        if resp.status_code == 403: raise GitHubError('Forbidden/rate limited', 403, 'RATE_LIMITED')
        if resp.status_code == 404: raise GitHubError('Resource not found', 404, 'NOT_FOUND')
        if resp.status_code == 429: raise GitHubError('Rate limited', 429, 'RATE_LIMITED')
        if resp.status_code >= 500: raise GitHubError(f'GitHub server error {resp.status_code}', resp.status_code, 'SERVER_ERROR')
        resp.raise_for_status()
        return resp.json()

    async def read_repository(self, session: AsyncSession, connection_id: uuid.UUID, owner: str, repo: str) -> dict:
        token = await self._get_token(session, connection_id)
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(f'{GITHUB_API}/repos/{owner}/{repo}', headers=self._headers(token))
        data = self._handle_response(resp)
        return {'name': data.get('name'), 'description': data.get('description'), 'default_branch': data.get('default_branch'), 'private': data.get('private'), 'stars': data.get('stargazers_count')}

    async def list_files(self, session: AsyncSession, connection_id: uuid.UUID, owner: str, repo: str, path: str = '') -> list:
        token = await self._get_token(session, connection_id)
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(f'{GITHUB_API}/repos/{owner}/{repo}/contents/{path}', headers=self._headers(token))
        data = self._handle_response(resp)
        if isinstance(data, list):
            return [{'name': f.get('name'), 'type': f.get('type'), 'size': f.get('size'), 'path': f.get('path')} for f in data]
        return [{'name': data.get('name'), 'type': data.get('type'), 'size': data.get('size'), 'path': data.get('path')}]

    async def read_file(self, session: AsyncSession, connection_id: uuid.UUID, owner: str, repo: str, path: str, ref: str | None = None) -> dict:
        import base64
        token = await self._get_token(session, connection_id)
        params = {'ref': ref} if ref else {}
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(f'{GITHUB_API}/repos/{owner}/{repo}/contents/{path}', headers=self._headers(token), params=params)
        data = self._handle_response(resp)
        content_b64 = data.get('content', '')
        try: content = base64.b64decode(content_b64.replace(chr(10), '')).decode('utf-8', errors='replace')
        except Exception: content = '[binary content]'
        return {'path': data.get('path'), 'name': data.get('name'), 'size': data.get('size'), 'content': content, 'sha': data.get('sha')}

    async def list_branches(self, session: AsyncSession, connection_id: uuid.UUID, owner: str, repo: str) -> list:
        token = await self._get_token(session, connection_id)
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(f'{GITHUB_API}/repos/{owner}/{repo}/branches', headers=self._headers(token))
        data = self._handle_response(resp)
        return [{'name': b.get('name'), 'protected': b.get('protected')} for b in data]

    async def execute(self, session: AsyncSession, connection_id: uuid.UUID, action: str, parameters: dict) -> dict:
        action_map = {
            'read_repository': self.read_repository,
            'list_files': self.list_files,
            'read_file': self.read_file,
            'list_branches': self.list_branches,
        }
        fn = action_map.get(action)
        if not fn: raise GitHubError(f'Unsupported action: {action}', category='INVALID_ACTION')
        owner = parameters.get('owner', '')
        repo = parameters.get('repo', '')
        if action == 'read_file': return await fn(session, connection_id, owner, repo, parameters.get('path', ''))
        if action == 'list_files': return await fn(session, connection_id, owner, repo, parameters.get('path', ''))
        return await fn(session, connection_id, owner, repo)

github_adapter = GitHubAdapter()
