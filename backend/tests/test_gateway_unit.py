from __future__ import annotations
import pytest
from app.services.gateway import _input_digest, _sanitize_params


class TestInputDigest:
    def test_digest_is_deterministic(self):
        d1 = _input_digest('github', 'read_file', {'path': 'README.md'})
        d2 = _input_digest('github', 'read_file', {'path': 'README.md'})
        assert d1 == d2

    def test_digest_is_64_hex_chars(self):
        d = _input_digest('github', 'read_file', {})
        assert len(d) == 64
        assert all(c in '0123456789abcdef' for c in d)

    def test_different_tools_different_digest(self):
        d1 = _input_digest('github', 'read_file', {})
        d2 = _input_digest('terminal', 'read_file', {})
        assert d1 != d2

    def test_different_params_different_digest(self):
        d1 = _input_digest('github', 'read_file', {'path': 'a.txt'})
        d2 = _input_digest('github', 'read_file', {'path': 'b.txt'})
        assert d1 != d2


class TestSanitizeParams:
    def test_token_redacted(self):
        r = _sanitize_params({'token': 'ghp_secret', 'file': 'main.py'})
        assert r['token'] == '[REDACTED]'
        assert r['file'] == 'main.py'

    def test_password_redacted(self):
        r = _sanitize_params({'password': 'abc123', 'action': 'read'})
        assert r['password'] == '[REDACTED]'
        assert r['action'] == 'read'

    def test_empty_params_unchanged(self):
        assert _sanitize_params({}) == {}

    def test_safe_params_unchanged(self):
        params = {'path': '/readme.md', 'branch': 'main', 'limit': 100}
        assert _sanitize_params(params) == params
