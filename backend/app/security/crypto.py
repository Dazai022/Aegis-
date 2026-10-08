from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core import logging as aegis_logging

log = aegis_logging.logger

NONCE_LENGTH = 12
TAG_LENGTH   = 16
VERSION_PREFIX = b"v1:"


class CryptoError(Exception):
    """Raised on irreversible cryptographic errors (tampering, bad keys, etc)."""


@dataclass(frozen=True)
class HmacHelper:
    """HMAC-SHA256 helpers for API-key storage using the server-side pepper."""

    DIGESTMOD: ClassVar[str] = "sha256"

    @classmethod
    def pepper_bytes(cls) -> bytes:
        from app.core.config import settings
        raw = settings.PEPPER.get_secret_value().encode("utf-8")
        if len(raw) < 16:
            if settings.is_production:
                raise CryptoError("PEPPER must be at least 16 bytes in production.")
            log.warning("PEPPER is shorter than 16 bytes; never do this in production.")
        return raw

    @classmethod
    def api_key_hash(cls, api_key_plain_text: str) -> str:
        if not api_key_plain_text:
            raise ValueError("api_key_plain_text cannot be empty")
        mac = hmac.new(
            cls.pepper_bytes(),
            msg=api_key_plain_text.encode("utf-8"),
            digestmod=hashlib.sha256,
        )
        return mac.hexdigest()

    @classmethod
    def constant_time_equals(cls, a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class AesGcm:
    """AES-256-GCM authenticated encryption for sensitive stored values.

    Aegis uses AES-256-GCM exclusively. A non-32-byte key is rejected.

    Ciphertext wire format (base64-encoded for storage):
        VERSION_PREFIX (3 bytes)  ||
        nonce          (12 bytes) ||
        GCM ciphertext+tag        (len(plaintext) + 16 bytes)
    """

    _REQUIRED_KEY_BYTES = 32

    def __init__(self, key_bytes: bytes) -> None:
        if len(key_bytes) != self._REQUIRED_KEY_BYTES:
            raise CryptoError(
                f"AES-256-GCM requires exactly 32-byte key (got {len(key_bytes)})."
            )
        self._aesgcm = AESGCM(key_bytes)

    def encrypt(self, plaintext: str | bytes, associated_data: bytes | None = None) -> str:
        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        nonce = os.urandom(NONCE_LENGTH)
        ct = self._aesgcm.encrypt(nonce, data, associated_data)
        combined = VERSION_PREFIX + nonce + ct
        return base64.b64encode(combined).decode("ascii")

    def decrypt(self, ciphertext_b64: str, associated_data: bytes | None = None) -> str:
        try:
            blob = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
        except Exception as exc:
            raise CryptoError("Ciphertext is not valid base64.") from exc
        if not blob.startswith(VERSION_PREFIX):
            raise CryptoError("Unsupported ciphertext version prefix.")
        body = blob[len(VERSION_PREFIX):]
        if len(body) < NONCE_LENGTH + TAG_LENGTH:
            raise CryptoError("Truncated ciphertext.")
        nonce = body[:NONCE_LENGTH]
        ct    = body[NONCE_LENGTH:]
        try:
            plain = self._aesgcm.decrypt(nonce, ct, associated_data)
        except InvalidTag as exc:
            raise CryptoError(
                "Ciphertext authentication failed - possible tampering or wrong key."
            ) from exc
        return plain.decode("utf-8")


class _LazyAesGcm:
    """Proxy that defers AesGcm construction until first use.

    Allows importing this module with a placeholder/dev AES key without crash.
    First actual encrypt/decrypt with invalid key raises CryptoError.
    Never silently generates a key. Never downgrades key size.
    """

    def __init__(self) -> None:
        self._instance: AesGcm | None = None

    def _get(self) -> AesGcm:
        if self._instance is None:
            from app.core.config import settings
            key = settings.aes_master_key_bytes
            self._instance = AesGcm(key)
        return self._instance

    def encrypt(self, plaintext: str | bytes, associated_data: bytes | None = None) -> str:
        return self._get().encrypt(plaintext, associated_data)

    def decrypt(self, ciphertext_b64: str, associated_data: bytes | None = None) -> str:
        return self._get().decrypt(ciphertext_b64, associated_data)


aes_gcm = _LazyAesGcm()


def sha256_hex(*parts: str | bytes) -> str:
    """Deterministic SHA-256 over concatenated parts."""
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, str):
            p = p.encode("utf-8")
        h.update(p)
    return h.hexdigest()


__all__ = [
    "AesGcm",
    "CryptoError",
    "HmacHelper",
    "aes_gcm",
    "sha256_hex",
    "NONCE_LENGTH",
    "TAG_LENGTH",
]
