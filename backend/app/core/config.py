from __future__ import annotations

import base64
import os
from typing import Any

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Risk level thresholds ───────────────────────────────────────────────────

class RiskLevels(BaseModel):
    LOW_MAX: int = 29
    MEDIUM_MAX: int = 59
    HIGH_MAX: int = 79
    CRITICAL_MIN: int = 80


# ── Main settings ───────────────────────────────────────────────────────────

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.environ.get("AEGIS_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Runtime environment
    ENV: str = "dev"
    APP_NAME: str = "aegis"
    APP_VERSION: str = "0.1.0"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://aegis:aegis@localhost:5432/aegis"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_CONNECT_TIMEOUT: int = 10

    # JWT — HS256 only, 15-minute access tokens
    JWT_SECRET: SecretStr = Field(default="__REPLACE_ME__")
    JWT_ALG: str = "HS256"
    JWT_EXPIRE_MIN: int = 15
    JWT_AUDIENCE: str = "aegis-admin"
    JWT_ISSUER: str = "aegis"

    # API key HMAC pepper
    PEPPER: SecretStr = Field(default="__REPLACE_ME__")

    # AES-256-GCM master key (base64-encoded 32-byte key)
    AES_MASTER_KEY_BASE64: SecretStr = Field(default="__REPLACE_ME__")

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000"
    CORS_ALLOW_CREDENTIALS: bool = True

    # Rate limits
    RATE_LIMIT_LOGIN_PER_MIN: int = 5
    RATE_LIMIT_PER_IP_PER_MIN: int = 120

    # Approval expiry
    APPROVAL_EXPIRE_SECONDS: int = 600

    # Risk thresholds
    RISK_LEVELS: RiskLevels = Field(default_factory=RiskLevels)

    # Request / output size limits
    MAX_REQUEST_BYTES: int = 1024 * 1024
    MAX_OUTPUT_BYTES: int = 64 * 1024

    # Terminal sandbox
    TERMINAL_TIMEOUT_SECONDS: int = 30
    TERMINAL_MEMORY_MB: int = 256
    TERMINAL_CPU_SHARES: float = 0.5
    TERMINAL_IMAGE: str = "aegis-terminal-sandbox:latest"

    # WebSocket
    WS_CATCHUP_RING_SIZE: int = 1024
    WS_MAX_CONNECTIONS_PER_ADMIN: int = 16
    WS_HEARTBEAT_SECONDS: int = 20

    # Admin bootstrap
    ADMIN_MIN_PASSWORD_LENGTH: int = 12

    # ── Field-level validators ────────────────────────────────────────────

    @field_validator("JWT_ALG")
    @classmethod
    def _enforce_hs256_only(cls, v: Any) -> str:
        if v != "HS256":
            raise ValueError(
                "JWT_ALG must be HS256. Aegis explicitly rejects any other JWT algorithm."
            )
        return "HS256"

    @field_validator("AES_MASTER_KEY_BASE64")
    @classmethod
    def _validate_aes_key_format(cls, v: SecretStr) -> SecretStr:
        """Validate the AES key is valid base64 and the correct byte length.

        Skips validation when the value is still the placeholder (dev startup
        without a configured key is allowed; the key is validated again at
        actual encryption time via aes_master_key_bytes).
        """
        plain = v.get_secret_value()
        if not plain or _is_placeholder(plain):
            return v
        try:
            raw = base64.b64decode(plain, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("AES_MASTER_KEY_BASE64 must be valid base64.") from exc
        # Aegis uses AES-256-GCM. Accept 32 bytes only; reject 16/24 silently.
        if len(raw) != 32:
            raise ValueError(
                f"AES_MASTER_KEY_BASE64 must decode to exactly 32 bytes for AES-256 "
                f"(got {len(raw)})."
            )
        return v

    # ── Cross-field production secret validation ──────────────────────────

    @model_validator(mode="after")
    def _enforce_production_secrets(self) -> "Settings":
        """Reject placeholder / short secrets when ENV is prod/production.

        This runs *after* all field validators, so self.ENV is already the
        resolved value from the .env file (not os.environ.get("ENV") which
        would miss values that come only from the .env file).
        """
        if not self.ENV.lower() in ("prod", "production"):
            return self

        errors: list[str] = []

        if _is_placeholder(self.JWT_SECRET.get_secret_value()):
            errors.append("JWT_SECRET is a placeholder; set a real secret in production.")
        elif len(self.JWT_SECRET.get_secret_value()) < 32:
            errors.append("JWT_SECRET must be at least 32 characters in production.")

        if _is_placeholder(self.PEPPER.get_secret_value()):
            errors.append("PEPPER is a placeholder; set a real secret in production.")
        elif len(self.PEPPER.get_secret_value()) < 16:
            errors.append("PEPPER must be at least 16 characters in production.")

        aes_plain = self.AES_MASTER_KEY_BASE64.get_secret_value()
        if _is_placeholder(aes_plain):
            errors.append(
                "AES_MASTER_KEY_BASE64 is a placeholder; set a real 32-byte AES-256 key "
                "in production."
            )
        else:
            try:
                raw = base64.b64decode(aes_plain, validate=True)
                if len(raw) != 32:
                    errors.append(
                        f"AES_MASTER_KEY_BASE64 must be exactly 32 bytes for AES-256 "
                        f"in production (got {len(raw)})."
                    )
            except Exception:  # noqa: BLE001
                errors.append("AES_MASTER_KEY_BASE64 is not valid base64 in production.")

        if errors:
            raise ValueError(
                "Production startup rejected due to insecure secret configuration:\n"
                + "\n".join(f"  - {e}" for e in errors)
            )
        return self

    # ── Derived properties ────────────────────────────────────────────────

    @property
    def cors_origins_list(self) -> list[str]:
        return [s.strip() for s in self.CORS_ORIGINS.split(",") if s.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENV.lower() in ("prod", "production")

    @property
    def aes_master_key_bytes(self) -> bytes:
        """Return the decoded AES master key bytes.

        Always enforces 32-byte key regardless of ENV, because the field
        validator already blocks non-32-byte keys at settings load time.
        This property is a runtime guard for defence-in-depth.
        """
        plain = self.AES_MASTER_KEY_BASE64.get_secret_value()
        if not plain or _is_placeholder(plain):
            raise RuntimeError(
                "AES_MASTER_KEY_BASE64 is not configured. "
                "Set a valid 32-byte base64-encoded key before performing encryption."
            )
        try:
            raw = base64.b64decode(plain, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("AES_MASTER_KEY_BASE64 is not valid base64.") from exc
        if len(raw) != 32:
            raise RuntimeError(
                f"AES_MASTER_KEY_BASE64 must be exactly 32 bytes for AES-256 "
                f"(got {len(raw)})."
            )
        return raw


def _is_placeholder(value: str) -> bool:
    """Return True if the value looks like an unset placeholder."""
    if not value:
        return True
    upper = value.upper()
    return (
        "REPLACE_ME" in upper
        or "REPLACE_WITH" in upper
        or "__REPLACE" in upper
    )


settings = Settings()
