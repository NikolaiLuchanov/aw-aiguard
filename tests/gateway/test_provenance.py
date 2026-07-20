"""Tests for gateway/core/provenance.py — Provenance dataclass."""

import pytest
from datetime import datetime, timezone

from gateway.core.provenance import Provenance


class TestProvenanceDefault:
    """Test Provenance.default() factory."""

    def test_default_returns_unknown_source(self):
        p = Provenance.default()
        assert p.source_id == "unknown"

    def test_default_returns_unknown_type(self):
        p = Provenance.default()
        assert p.source_type == "unknown"

    def test_default_returns_zero_trust(self):
        p = Provenance.default()
        assert p.trust_level == 0.0

    def test_default_has_utc_timestamp(self):
        p = Provenance.default()
        assert p.ingested_at.tzinfo is not None


class TestProvenanceFromDict:
    """Test Provenance.from_dict() deserialization."""

    def test_from_dict_full(self):
        data = {
            "source_id": "git-repo-1",
            "source_type": "repository",
            "trust_level": 0.95,
            "ingested_at": "2026-07-20T12:00:00+00:00",
        }
        p = Provenance.from_dict(data)
        assert p.source_id == "git-repo-1"
        assert p.source_type == "repository"
        assert p.trust_level == 0.95
        assert isinstance(p.ingested_at, datetime)

    def test_from_dict_partial_missing_source_type(self):
        data = {"source_id": "chat-1", "trust_level": 0.8}
        p = Provenance.from_dict(data)
        assert p.source_id == "chat-1"
        assert p.source_type == "unknown"
        assert p.trust_level == 0.8

    def test_from_dict_partial_missing_trust_level(self):
        data = {"source_id": "web-1", "source_type": "external_api"}
        p = Provenance.from_dict(data)
        assert p.source_id == "web-1"
        assert p.source_type == "external_api"
        assert p.trust_level == 0.0

    def test_from_dict_empty_defaults(self):
        p = Provenance.from_dict({})
        assert p.source_id == "unknown"
        assert p.source_type == "unknown"
        assert p.trust_level == 0.0

    def test_from_dict_string_trust_converts(self):
        data = {"source_id": "x", "source_type": "y", "trust_level": "0.5"}
        p = Provenance.from_dict(data)
        assert p.trust_level == 0.5


class TestProvenanceFromHeaders:
    """Test Provenance.from_headers() extraction."""

    def test_from_headers_all_present(self):
        headers = {
            "x-provenance-source-id": "git-repo-1",
            "x-provenance-source-type": "repository",
            "x-provenance-trust-level": "0.95",
        }
        p = Provenance.from_headers(headers)
        assert p.source_id == "git-repo-1"
        assert p.source_type == "repository"
        assert p.trust_level == 0.95

    def test_from_headers_missing_all(self):
        headers = {}
        p = Provenance.from_headers(headers)
        assert p.source_id == "unknown"
        assert p.source_type == "unknown"
        assert p.trust_level == 0.0

    def test_from_headers_partial_only_source_id(self):
        headers = {"x-provenance-source-id": "chat-42"}
        p = Provenance.from_headers(headers)
        assert p.source_id == "chat-42"
        assert p.source_type == "unknown"
        assert p.trust_level == 0.0

    def test_from_headers_case_insensitive(self):
        headers = {
            "x-provenance-source-id": "test-src",
            "x-provenance-source-type": "chat",
            "x-provenance-trust-level": "0.75",
        }
        p = Provenance.from_headers(headers)
        assert p.source_id == "test-src"
        assert p.source_type == "chat"
        assert p.trust_level == 0.75

    def test_from_headers_trust_clamped_high(self):
        headers = {
            "x-provenance-source-id": "x",
            "x-provenance-source-type": "y",
            "x-provenance-trust-level": "1.5",
        }
        p = Provenance.from_headers(headers)
        assert p.trust_level == 1.0

    def test_from_headers_trust_clamped_low(self):
        headers = {
            "x-provenance-source-id": "x",
            "x-provenance-source-type": "y",
            "x-provenance-trust-level": "-0.5",
        }
        p = Provenance.from_headers(headers)
        assert p.trust_level == 0.0

    def test_from_headers_trust_invalid_string(self):
        headers = {
            "x-provenance-source-id": "x",
            "x-provenance-source-type": "y",
            "x-provenance-trust-level": "not-a-number",
        }
        p = Provenance.from_headers(headers)
        assert p.trust_level == 0.0

    def test_from_headers_empty_string_headers(self):
        headers = {
            "x-provenance-source-id": "",
            "x-provenance-source-type": "",
            "x-provenance-trust-level": "",
        }
        p = Provenance.from_headers(headers)
        assert p.source_id == "unknown"
        assert p.source_type == "unknown"
        assert p.trust_level == 0.0

    def test_from_headers_trust_boundary(self):
        headers = {
            "x-provenance-source-id": "x",
            "x-provenance-source-type": "y",
            "x-provenance-trust-level": "0.5",
        }
        p = Provenance.from_headers(headers)
        assert p.trust_level == 0.5
        assert not p.is_low_trust  # 0.5 is NOT low trust (< 0.5 threshold)


class TestProvenanceToDict:
    """Test Provenance.to_dict() serialization."""

    def test_to_dict_structure(self):
        p = Provenance(source_id="test", source_type="repository", trust_level=0.9)
        d = p.to_dict()
        assert d == {
            "source_id": "test",
            "source_type": "repository",
            "trust_level": 0.9,
            "ingested_at": p.ingested_at.isoformat(),
        }

    def test_to_dict_roundtrip(self):
        original = Provenance(source_id="r1", source_type="chat", trust_level=0.5)
        d = original.to_dict()
        restored = Provenance.from_dict(d)
        assert restored.source_id == original.source_id
        assert restored.source_type == original.source_type
        assert restored.trust_level == original.trust_level


class TestProvenanceProperties:
    """Test is_low_trust and is_known properties."""

    def test_is_low_trust_true(self):
        p = Provenance(source_id="x", source_type="y", trust_level=0.3)
        assert p.is_low_trust is True

    def test_is_low_trust_false(self):
        p = Provenance(source_id="x", source_type="y", trust_level=0.7)
        assert p.is_low_trust is False

    def test_is_low_trust_boundary(self):
        p = Provenance(source_id="x", source_type="y", trust_level=0.5)
        assert p.is_low_trust is False  # exactly 0.5 is NOT low trust

    def test_is_known_true(self):
        p = Provenance(source_id="x", source_type="repository", trust_level=0.5)
        assert p.is_known is True

    def test_is_known_false_unknown(self):
        p = Provenance.default()
        assert p.is_known is False

    def test_is_known_all_valid_types(self):
        for stype in ("repository", "chat", "external_api", "llm_output", "file_system"):
            p = Provenance(source_id="x", source_type=stype, trust_level=0.5)
            assert p.is_known is True, f"is_known should be True for {stype}"
