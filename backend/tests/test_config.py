"""
Tests for app/core/config.py production secret validation.
"""
from __future__ import annotations
import base64
import os
import sys

import pytest


GOOD_JWT = "a" * 64
GOOD_PEPPER = "b" * 32
GOOD_AES_32 = base64.b64encode(b"\x00" * 32).decode()
BAD_AES_16  = base64.b64encode(b"\x00" * 16).decode()
BAD_AES_24  = base64.b64encode(b"\x00" * 24).decode()


def fresh_settings(**kwargs):
    for k in list(sys.modules):
        if k.startswith("app.core.config"):
            del sys.modules[k]
    os.environ["AEGIS_ENV_FILE"] = "/nonexistent_so_no_env_file_loaded"
    from app.core.config import Settings
    return Settings(DATABASE_URL="postgresql+asyncpg://x:x@localhost/x", **kwargs)


class TestProductionSecretValidation:
    def test_prod_placeholder_jwt_rejected(self):
        with pytest.raises(Exception, match=r"(?i)production|placeholder"):
            fresh_settings(ENV="prod", JWT_SECRET="__REPLACE_ME__",
                           PEPPER=GOOD_PEPPER, AES_MASTER_KEY_BASE64=GOOD_AES_32)

    def test_prod_placeholder_pepper_rejected(self):
        with pytest.raises(Exception, match=r"(?i)production|placeholder"):
            fresh_settings(ENV="prod", JWT_SECRET=GOOD_JWT,
                           PEPPER="__REPLACE_ME__", AES_MASTER_KEY_BASE64=GOOD_AES_32)

    def test_prod_placeholder_aes_rejected(self):
        with pytest.raises(Exception, match=r"(?i)production|placeholder"):
            fresh_settings(ENV="prod", JWT_SECRET=GOOD_JWT,
                           PEPPER=GOOD_PEPPER, AES_MASTER_KEY_BASE64="__REPLACE_ME__")

    def test_prod_all_valid_accepted(self):
        s = fresh_settings(ENV="prod", JWT_SECRET=GOOD_JWT,
                           PEPPER=GOOD_PEPPER, AES_MASTER_KEY_BASE64=GOOD_AES_32)
        assert s.is_production is True

    def test_prod_aes_16_bytes_rejected(self):
        with pytest.raises(Exception, match=r"32"):
            fresh_settings(ENV="prod", JWT_SECRET=GOOD_JWT,
                           PEPPER=GOOD_PEPPER, AES_MASTER_KEY_BASE64=BAD_AES_16)

    def test_prod_aes_24_bytes_rejected(self):
        with pytest.raises(Exception, match=r"32"):
            fresh_settings(ENV="prod", JWT_SECRET=GOOD_JWT,
                           PEPPER=GOOD_PEPPER, AES_MASTER_KEY_BASE64=BAD_AES_24)

    def test_dev_placeholders_accepted(self):
        s = fresh_settings(ENV="dev", JWT_SECRET="__REPLACE_ME__",
                           PEPPER="__REPLACE_ME__", AES_MASTER_KEY_BASE64="__REPLACE_ME__")
        assert s.is_production is False

    def test_invalid_base64_aes_rejected_always(self):
        with pytest.raises(Exception, match=r"(?i)base64|valid"):
            fresh_settings(ENV="dev", JWT_SECRET="dev", PEPPER="dev-pepper-1234567",
                           AES_MASTER_KEY_BASE64="not-valid-base64!!!")

    def test_jwt_alg_none_rejected(self):
        with pytest.raises(Exception, match=r"HS256"):
            fresh_settings(ENV="dev", JWT_ALG="none")

    def test_jwt_alg_rs256_rejected(self):
        with pytest.raises(Exception, match=r"HS256"):
            fresh_settings(ENV="dev", JWT_ALG="RS256")

    def test_prod_env_not_based_on_os_environ(self):
        os.environ["ENV"] = "dev"   # os.environ says dev
        try:
            with pytest.raises(Exception):
                # Settings.ENV="prod" from kwargs should still trigger validation
                fresh_settings(ENV="prod", JWT_SECRET="__REPLACE_ME__",
                               PEPPER=GOOD_PEPPER, AES_MASTER_KEY_BASE64=GOOD_AES_32)
        finally:
            os.environ.pop("ENV", None)


class TestAesMasterKeyProperty:
    def test_aes_key_bytes_32_for_good_key(self):
        s = fresh_settings(ENV="dev", JWT_SECRET="dev", PEPPER="dev-pepper-1234567",
                           AES_MASTER_KEY_BASE64=GOOD_AES_32)
        assert len(s.aes_master_key_bytes) == 32

    def test_aes_key_bytes_fails_on_placeholder(self):
        s = fresh_settings(ENV="dev", JWT_SECRET="dev", PEPPER="dev-pepper-1234567",
                           AES_MASTER_KEY_BASE64="__REPLACE_ME__")
        with pytest.raises(RuntimeError, match=r"(?i)not configured|placeholder|replace"):
            _ = s.aes_master_key_bytes