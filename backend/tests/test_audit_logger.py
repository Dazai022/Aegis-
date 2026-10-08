from __future__ import annotations
import pytest
from app.audit.logger import _redact_params, _compute_hash, _canonical_json, _SECRET_KEYS


class TestRedaction:
    def test_password_redacted(self):
        r = _redact_params({'password': 'hunter2', 'file': 'ok.txt'})
        assert r['password'] == '[REDACTED]'
        assert r['file'] == 'ok.txt'

    def test_token_redacted(self):
        r = _redact_params({'token': 'ghp_abc123', 'path': '/readme'})
        assert r['token'] == '[REDACTED]'
        assert r['path'] == '/readme'

    def test_nested_secret_redacted(self):
        r = _redact_params({'config': {'secret': 'abc', 'name': 'test'}})
        assert r['config']['secret'] == '[REDACTED]'
        assert r['config']['name'] == 'test'

    def test_non_secret_preserved(self):
        r = _redact_params({'action': 'read', 'tool': 'github', 'score': 42})
        assert r == {'action': 'read', 'tool': 'github', 'score': 42}

    def test_all_known_secret_keys_redacted(self):
        for key in _SECRET_KEYS:
            result = _redact_params({key: 'supersecret'})
            assert result[key] == '[REDACTED]', f'key {key!r} not redacted'

    def test_depth_limit_prevents_deep_recursion(self):
        deep = {'a': {'b': {'c': {'d': {'e': {'password': 'secret'}}}}}}
        r = _redact_params(deep, depth=2)
        assert isinstance(r, dict)


class TestHashChain:
    def test_hash_is_deterministic(self):
        record = {'request_id': 'abc', 'decision': 'ALLOW', 'score': 10}
        h1 = _compute_hash(None, record)
        h2 = _compute_hash(None, record)
        assert h1 == h2

    def test_hash_is_64_hex_chars(self):
        h = _compute_hash(None, {'a': 1})
        assert len(h) == 64
        assert all(c in '0123456789abcdef' for c in h)

    def test_chained_hash_differs_from_previous(self):
        h1 = _compute_hash(None, {'a': 1})
        h2 = _compute_hash(h1, {'b': 2})
        assert h1 != h2

    def test_tampered_record_changes_hash(self):
        h_orig = _compute_hash(None, {'decision': 'ALLOW'})
        h_tamper = _compute_hash(None, {'decision': 'BLOCK'})
        assert h_orig != h_tamper

    def test_hash_chain_verifiable(self):
        records = [{'seq': i, 'data': f'record_{i}'} for i in range(5)]
        hashes = []
        prev = None
        for rec in records:
            h = _compute_hash(prev, rec)
            hashes.append(h)
            prev = h
        # Verify chain: each hash depends on prev
        assert len(set(hashes)) == 5, 'all hashes must be unique'
        # Re-compute from scratch - must match
        prev = None
        for i, rec in enumerate(records):
            h = _compute_hash(prev, rec)
            assert h == hashes[i], f'chain broken at record {i}'
            prev = h


class TestCanonicalJson:
    def test_key_order_independent(self):
        j1 = _canonical_json({'b': 2, 'a': 1})
        j2 = _canonical_json({'a': 1, 'b': 2})
        assert j1 == j2

    def test_no_whitespace(self):
        j = _canonical_json({'a': 1})
        assert ' ' not in j
