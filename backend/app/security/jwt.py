from __future__ import annotations
import uuid
from datetime import datetime, timedelta, UTC
import jwt as pyjwt
from app.core.config import settings

class JWTError(Exception): pass

def create_access_token(subject: str, extra: dict | None = None) -> str:
    now = datetime.now(UTC)
    payload = {
        'sub': subject,
        'iat': now,
        'exp': now + timedelta(minutes=settings.JWT_EXPIRE_MIN),
        'jti': str(uuid.uuid4()),
        'iss': settings.JWT_ISSUER,
        'aud': settings.JWT_AUDIENCE,
    }
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, settings.JWT_SECRET.get_secret_value(), algorithm='HS256')

def decode_access_token(token: str) -> dict:
    try:
        return pyjwt.decode(
            token,
            settings.JWT_SECRET.get_secret_value(),
            algorithms=['HS256'],
            options={'require': ['exp','iat','sub','jti']},
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
    except pyjwt.ExpiredSignatureError as e:
        raise JWTError('Token expired') from e
    except pyjwt.InvalidTokenError as e:
        raise JWTError(f'Invalid token: {e}') from e
