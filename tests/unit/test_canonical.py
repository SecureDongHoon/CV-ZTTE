"""Unit tests for strict parsing, JCS canonicalization, and domain hashing (spec §8)."""

import hashlib

import pytest

from cvztte.canonical import Domain, canonicalize, commit, domain_hash, strict_loads
from cvztte.canonical.strict_json import MAX_NESTING_DEPTH, MAX_PAYLOAD_BYTES
from cvztte.errors import ErrorCode, StrictParseError


# --- strict_loads rejections ---


def test_rejects_duplicate_keys():
    with pytest.raises(StrictParseError) as ei:
        strict_loads('{"a": 1, "a": 2}')
    assert ei.value.code is ErrorCode.DUPLICATE_JSON_KEY


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_rejects_non_finite_numbers(bad):
    with pytest.raises(StrictParseError) as ei:
        strict_loads(f'{{"x": {bad}}}')
    assert ei.value.code is ErrorCode.SCHEMA_INVALID


def test_rejects_invalid_utf8():
    with pytest.raises(StrictParseError) as ei:
        strict_loads(b'{"x": "\xff\xfe"}')
    assert ei.value.code is ErrorCode.SCHEMA_INVALID


def test_rejects_oversized_payload():
    big = b'{"x": "' + b"a" * (MAX_PAYLOAD_BYTES) + b'"}'
    with pytest.raises(StrictParseError) as ei:
        strict_loads(big)
    assert ei.value.code is ErrorCode.PAYLOAD_TOO_LARGE


def test_rejects_excessive_nesting():
    depth = MAX_NESTING_DEPTH + 5
    payload = "[" * depth + "]" * depth
    with pytest.raises(StrictParseError) as ei:
        strict_loads(payload)
    assert ei.value.code is ErrorCode.SCHEMA_INVALID


def test_rejects_malformed_json():
    with pytest.raises(StrictParseError):
        strict_loads('{"x": }')


def test_accepts_valid_object():
    assert strict_loads('{"b": 1, "a": [2, 3]}') == {"b": 1, "a": [2, 3]}


# --- JCS canonicalization determinism ---


def test_jcs_key_order_independent():
    a = canonicalize({"b": 1, "a": 2, "c": {"z": 1, "y": 2}})
    b = canonicalize({"a": 2, "c": {"y": 2, "z": 1}, "b": 1})
    assert a == b
    assert a == b'{"a":2,"b":1,"c":{"y":2,"z":1}}'


def test_jcs_rejects_non_finite():
    with pytest.raises(StrictParseError):
        canonicalize({"x": float("nan")})


# --- domain-separated hashing ---


def test_domain_hash_formula():
    payload = b"hello"
    expected = hashlib.sha256(
        Domain.ACTION.value.encode("utf-8") + b"\x00" + payload
    ).digest()
    assert domain_hash(Domain.ACTION, payload) == expected


def test_domain_separation_changes_hash():
    payload = b"same-bytes"
    assert domain_hash(Domain.ACTION, payload) != domain_hash(Domain.POLICY, payload)


def test_commit_stable_and_domain_scoped():
    value = {"action_type": "DB_OPERATION", "target": "prod-db"}
    c1 = commit(Domain.ACTION, value)
    c2 = commit(Domain.ACTION, dict(reversed(list(value.items()))))
    assert c1 == c2  # key order independent
    assert c1.startswith("sha256:")
    # Same value under a different domain must not collide.
    assert commit(Domain.ACTION, value) != commit(Domain.REQUEST, value)
