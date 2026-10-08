from __future__ import annotations

import time
from dataclasses import dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    InvalidHash,
    VerificationError,
    VerifyMismatchError,
)

from app.core.config import settings


_PH = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Synthetic hash used for dummy verification against non-existent accounts,
# so that response timing is similar regardless of whether an email exists
# (defends against username enumeration timing).
_SYNTHETIC_HASH = _PH.hash("synthetic-password-for-timing-balance")


@dataclass(frozen=True)
class PasswordVerificationResult:
    ok: bool
    rehash_needed: bool = False


def hash_password(password: str) -> str:
    if not password or len(password) < settings.ADMIN_MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {settings.ADMIN_MIN_PASSWORD_LENGTH} characters."
        )
    return _PH.hash(password)


def verify_password(password: str, encoded_hash: str) -> PasswordVerificationResult:
    try:
        ok = _PH.verify(encoded_hash, password)
    except VerifyMismatchError:
        return PasswordVerificationResult(ok=False)
    except VerificationError:
        return PasswordVerificationResult(ok=False)
    except InvalidHash:
        return PasswordVerificationResult(ok=False)
    rehash_needed = _PH.check_needs_rehash(encoded_hash)
    return PasswordVerificationResult(ok=bool(ok), rehash_needed=bool(rehash_needed))


def dummy_verify_password(password: str | None = None) -> None:
    """Run a verify against a synthetic hash for timing balance.

    Always swallows exceptions; callers use this when an account lookup has
    already failed in order to keep response-time distributions comparable
    between "user not found" and "password incorrect" responses.
    """
    attempt = password or "dummy-password-for-timing" * 3
    t0 = time.perf_counter_ns()
    try:
        _PH.verify(_SYNTHETIC_HASH, attempt)
    except Exception:  # noqa: BLE001
        pass
    t1 = time.perf_counter_ns()
    # Ensure at least ~1ms of wall-clock work to avoid early-return
    # branches leaking information.
    while time.perf_counter_ns() - t0 < 1_000_000:
        # Simple no-op loop; Argon2id dominates but we guarantee a floor.
        _ = time.perf_counter_ns()


def needs_rehash(encoded_hash: str) -> bool:
    try:
        return bool(_PH.check_needs_rehash(encoded_hash))
    except InvalidHash:
        return True


__all__ = [
    "PasswordVerificationResult",
    "dummy_verify_password",
    "hash_password",
    "needs_rehash",
    "verify_password",
]
