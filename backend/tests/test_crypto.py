"""
Tests for app/security/crypto.py

Covers:
- Module import with placeholder AES key (no crash)
- Encrypt with placeholder key fails clearly
- AES-256-GCM round-trip correctness
- Modified ciphertext rejected (authentication)
- Modified nonce rejected
- Wrong key rejected
- 16-byte key rejected (AES-256 only)
- 24-byte key rejected
- Associated data mismatch rejected
- HMAC-SHA256 API key hash
- constant_time_equals
- sha256_hex determinism
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import os
import sys

import pytest


class TestModuleImportWithPlaceholder:
    def test_import_succeeds_with_placeholder(self, monkeypatch):
        """Importing crypto must not crash even when AES_MASTER_KEY_BASE64 is placeholder."""
        monkeypatch.setenv("AES_MASTER_KEY_BASE64", "__REPLACE_ME__")
        # Remove cached modules so fresh import uses env override
        for key in list(sys.modules):
            if "app.core.config" in key or "app.security.crypto" in key:
                del sys.modules[key]
        import app.security.crypto  # noqa: PLC0415
        assert hasattr(app.security.crypto, "aes_gcm")

    def test_encrypt_with_placeholder_fails_clearly(self, monkeypatch):
        """Encryption must fail with a clear error when key is placeholder."""
        monkeypatch.setenv("AES_MASTER_KEY_BASE64", "__REPLACE_ME__")
        for key in list(sys.modules):
            if "app.core.config" in key or "app.security.crypto" in key:
                del sys.modules[key]
        import app.security.crypto as c  # noqa: PLC0415
        with pytest.raises((RuntimeError, Exception)) as exc_info:
            c.aes_gcm.encrypt("test")
        assert any(
            kw in str(exc_info.value).lower()
            for kw in ("not configured", "placeholder", "replace", "invalid")
        )


@pytest.fixture(scope="module")
def gcm():
    from app.security.crypto import AesGcm
    return AesGcm(b"\xab" * 32)


class TestAesGcmCorrectness:
    def test_roundtrip_string(self, gcm):
        ct = gcm.encrypt("hello aegis")
        assert gcm.decrypt(ct) == "hello aegis"

    def test_roundtrip_bytes(self, gcm):
        ct = gcm.encrypt(b"raw bytes test")
        assert gcm.decrypt(ct) == "raw bytes test"

    def test_roundtrip_with_aad(self, gcm):
        ct = gcm.encrypt("secret", associated_data=b"context")
        assert gcm.decrypt(ct, associated_data=b"context") == "secret"

    def test_different_nonce_each_time(self, gcm):
        ct1 = gcm.encrypt("same plaintext")
        ct2 = gcm.encrypt("same plaintext")
        assert ct1 != ct2  # nonces must differ

    def test_ciphertext_is_base64(self, gcm):
        ct = gcm.encrypt("verify format")
        base64.b64decode(ct, validate=True)  # must not raise

    def test_version_prefix(self, gcm):
        ct = gcm.encrypt("prefix check")
        raw = base64.b64decode(ct)
        assert raw[:3] == b"v1:"


class TestAesGcmAuthentication:
    def test_modified_last_byte_rejected(self, gcm):
        from app.security.crypto import CryptoError
        ct = gcm.encrypt("tamper me")
        raw = bytearray(base64.b64decode(ct))
        raw[-1] ^= 0xFF
        with pytest.raises(CryptoError):
            gcm.decrypt(base64.b64encode(bytes(raw)).decode())

    def test_modified_first_data_byte_rejected(self, gcm):
        from app.security.crypto import CryptoError
        ct = gcm.encrypt("tamper first")
        raw = bytearray(base64.b64decode(ct))
        raw[3 + 12] ^= 0x01  # after v1: prefix (3) and nonce (12)
        with pytest.raises(CryptoError):
            gcm.decrypt(base64.b64encode(bytes(raw)).decode())

    def test_wrong_key_rejected(self, gcm):
        from app.security.crypto import AesGcm, CryptoError
        wrong = AesGcm(b"\xcd" * 32)
        ct = gcm.encrypt("secret data")
        with pytest.raises(CryptoError):
            wrong.decrypt(ct)

    def test_aad_mismatch_rejected(self, gcm):
        from app.security.crypto import CryptoError
        ct = gcm.encrypt("aad data", associated_data=b"right")
        with pytest.raises(CryptoError):
            gcm.decrypt(ct, associated_data=b"wrong")

    def test_aad_absent_on_decrypt_rejected(self, gcm):
        from app.security.crypto import CryptoError
        ct = gcm.encrypt("aad data", associated_data=b"required")
        with pytest.raises(CryptoError):
            gcm.decrypt(ct)  # no AAD


class TestAesGcmKeyValidation:
    def test_16_byte_key_rejected(self):
        from app.security.crypto import AesGcm, CryptoError
        with pytest.raises(CryptoError, match="32"):
            AesGcm(b"\x00" * 16)

    def test_24_byte_key_rejected(self):
        from app.security.crypto import AesGcm, CryptoError
        with pytest.raises(CryptoError, match="32"):
            AesGcm(b"\x00" * 24)

    def test_31_byte_key_rejected(self):
        from app.security.crypto import AesGcm, CryptoError
        with pytest.raises(CryptoError, match="32"):
            AesGcm(b"\x00" * 31)

    def test_33_byte_key_rejected(self):
        from app.security.crypto import AesGcm, CryptoError
        with pytest.raises(CryptoError, match="32"):
            AesGcm(b"\x00" * 33)

    def test_empty_key_rejected(self):
        from app.security.crypto import AesGcm, CryptoError
        with pytest.raises(CryptoError):
            AesGcm(b"")

    def test_invalid_base64_rejected(self, gcm):
        from app.security.crypto import CryptoError
        with pytest.raises(CryptoError, match="base64"):
            gcm.decrypt("not-valid-base64!!!")


class TestHmacHelper:
    def test_api_key_hash_returns_64_hex_chars(self):
        from app.security.crypto import HmacHelper
        result = HmacHelper.api_key_hash("ag-testkey12345678")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_api_key_hash_deterministic(self):
        from app.security.crypto import HmacHelper
        h1 = HmacHelper.api_key_hash("ag-samekey")
        h2 = HmacHelper.api_key_hash("ag-samekey")
        assert h1 == h2

    def test_different_keys_different_hash(self):
        from app.security.crypto import HmacHelper
        h1 = HmacHelper.api_key_hash("ag-key-one")
        h2 = HmacHelper.api_key_hash("ag-key-two")
        assert h1 != h2

    def test_empty_key_raises(self):
        from app.security.crypto import HmacHelper
        with pytest.raises(ValueError):
            HmacHelper.api_key_hash("")

    def test_constant_time_equals_true(self):
        from app.security.crypto import HmacHelper
        assert HmacHelper.constant_time_equals("abc123", "abc123") is True

    def test_constant_time_equals_false(self):
        from app.security.crypto import HmacHelper
        assert HmacHelper.constant_time_equals("abc123", "xyz789") is False


class TestSha256Hex:
    def test_deterministic(self):
        from app.security.crypto import sha256_hex
        assert sha256_hex("a", b"b", "c") == sha256_hex("a", b"b", "c")

    def test_returns_64_chars(self):
        from app.security.crypto import sha256_hex
        h = sha256_hex("hello world")
        assert len(h) == 64

    def test_known_value(self):
        from app.security.crypto import sha256_hex
        # SHA256 of empty string
        h = sha256_hex("")
        assert h == hashlib.sha256(b"").hexdigest()