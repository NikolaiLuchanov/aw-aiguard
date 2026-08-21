"""
Regression test for the "implemented but never wired" bug.

gateway.main constructs the single LLMProxy used in production. This test
asserts that the four Phase-4 security components are actually injected,
so a future refactor that drops a kwarg fails loudly instead of silently
disabling a security layer.
"""

import main as gateway_main


def test_proxy_engine_has_function_call_detector():
    assert gateway_main.proxy_engine.detector is not None


def test_proxy_engine_has_sanitizer():
    assert gateway_main.proxy_engine.sanitizer is not None


def test_proxy_engine_has_output_controller():
    assert gateway_main.proxy_engine.output_controller is not None


def test_proxy_engine_has_schema_validator():
    assert gateway_main.proxy_engine.validator is not None


def test_proxy_engine_detector_shares_guardian():
    """The detector should reuse the shared guardian, not spawn its own."""
    assert gateway_main.proxy_engine.detector.guardian is gateway_main.guardian
