from __future__ import annotations
import asyncio, json, time, uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status
from app.security.jwt import decode_access_token, JWTError
from app.core import logging as aegis_logging
from app.core.config import settings

log = aegis_logging.logger
router = APIRouter(tags=['websocket'])


@dataclass
class Event:
    seq: int
    topic: str
    payload: dict[str, Any]
    ts: float = field(default_factory=time.time)


class PubSubHub:
    def __init__(self, ring_size: int = 1024) -> None:
        self._ring: deque[Event] = deque(maxlen=ring_size)
        self._seq = 0
        self._lock = asyncio.Lock()
        self._subscribers: dict[str, asyncio.Queue[Event]] = {}

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            self._seq += 1
            event = Event(seq=self._seq, topic=topic, payload=payload)
            self._ring.append(event)
        dead = []
        for sid, q in list(self._subscribers.items()):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(sid)
        for sid in dead:
            self._subscribers.pop(sid, None)

    def subscribe(self) -> tuple[str, asyncio.Queue[Event]]:
        sid = str(uuid.uuid4())
        self._subscribers[sid] = asyncio.Queue(maxsize=256)
        return sid, self._subscribers[sid]

    def unsubscribe(self, sid: str) -> None:
        self._subscribers.pop(sid, None)

    def catchup(self, since_seq: int) -> list[Event]:
        return [e for e in self._ring if e.seq > since_seq]

    @property
    def current_seq(self) -> int:
        return self._seq


hub = PubSubHub(ring_size=settings.WS_CATCHUP_RING_SIZE)


async def _auth_ws(token: str) -> dict:
    try:
        return decode_access_token(token)
    except JWTError as e:
        raise ValueError(f'WS auth failed: {e}') from e


@router.websocket('/ws/events')
async def ws_events(websocket: WebSocket, token: str = Query(...)):
    try:
        await _auth_ws(token)
    except ValueError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    sid, queue = hub.subscribe()
    try:
        # Send missed events since reconnect
        since = 0
        try:
            init = await asyncio.wait_for(websocket.receive_json(), timeout=1.0)
            since = int(init.get('since_seq', 0))
        except Exception:
            pass
        for ev in hub.catchup(since):
            await websocket.send_text(json.dumps({'seq': ev.seq, 'topic': ev.topic, 'payload': ev.payload, 'ts': ev.ts}))
        # Heartbeat + event loop
        while True:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=settings.WS_HEARTBEAT_SECONDS)
                await websocket.send_text(json.dumps({'seq': ev.seq, 'topic': ev.topic, 'payload': ev.payload, 'ts': ev.ts}))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({'type': 'ping', 'ts': time.time()}))
            except WebSocketDisconnect:
                break
    finally:
        hub.unsubscribe(sid)
