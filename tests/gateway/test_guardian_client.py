"""Unit tests for gateway/core/guardian_client.py — pure protocol layer, no I/O."""

import os
import pytest
from gateway.core.guardian_client import build_request, build_function_request, parse_score, load_prompts

PROMPTS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "guardrail-config", "guardian_prompts.yaml")


def _load_prompts():
    return load_prompts(PROMPTS_PATH)


# --- parse_score: tolerant, fail-closed ---


@pytest.mark.parametrize("content,expected", [
    ("<score>yes</score>", "yes"),
    ("<score>no</score>", "no"),
    ("<SCORE>YES</SCORE>", "yes"),
    ("<score> yes </score>", "yes"),
    ("<score>no</score>", "no"),
    ("yes", "yes"),
    ("YES", "yes"),
    ("no", "no"),
    ("no.", "no"),
    ("The answer is no", "no"),
    ("Reasoning... the final verdict: <score>no</score>", "no"),
    # tag beats a bare word earlier in the text (thinking-mode traces):
    ("reasoning says yes but <score>no</score>", "no"),
])
def test_parse_score_valid(content, expected):
    assert parse_score(content) == expected


# --- parse_score: fail-closed on anything ambiguous ---


@pytest.mark.parametrize("content", [
    "", "maybe", "I am not sure", "null", "404",
    "unsure", "perhaps", "I cannot determine.",
])
def test_parse_score_invalid_returns_none(content):
    assert parse_score(content) is None


# --- build_request: fast mode ---


def test_build_request_fast_mode():
    req = build_request(prompt="hello", model="granite", think=False,
                        prompts=_load_prompts(), api_key="")
    body = req["body"]
    assert body["model"] == "granite"
    # build_request strips YAML trailing newlines; compare against stripped values
    system_content = _load_prompts()["fast"]["system"].strip()
    user_content = _load_prompts()["fast"]["user"].strip().format(prompt="hello")
    assert body["messages"] == [
        {"role": "system", "content": system_content},
        {"role": "user", "content": user_content},
    ]
    assert body["max_tokens"] == 8
    assert "think" not in body            # old wire flag must be gone
    assert "temperature" in body
    assert body["temperature"] == 0
    assert "stream" in body
    assert body["stream"] is False
    assert req["headers"].get("Authorization") is None
    assert req["headers"]["Content-Type"] == "application/json"


# --- build_request: auth header when key set ---


def test_build_request_includes_auth_header():
    req = build_request(prompt="x", model="m", think=False,
                        prompts=_load_prompts(), api_key="sekrit")
    assert req["headers"]["Authorization"] == "Bearer sekrit"


# --- build_request: thinking mode bumps max_tokens ---


def test_build_request_thinking_mode_bumps_max_tokens():
    req = build_request(prompt="x", model="m", think=True,
                        prompts=_load_prompts(), api_key="")
    assert req["body"]["max_tokens"] == 256
    assert req["body"]["messages"][0]["role"] == "system"
    assert "step by step" in req["body"]["messages"][1]["content"]
    assert "think" not in req["body"]  # think flag is NOT sent on the wire


# --- build_function_request: function-hallucination ---


def test_build_function_request_valid():
    tool_calls_json = '[{"name": "shell_execute", "arguments": "{}"}]'
    req = build_function_request(tool_calls_json=tool_calls_json, model="granite",
                                 prompts=_load_prompts(), api_key="")
    body = req["body"]
    assert body["model"] == "granite"
    assert body["max_tokens"] == 256  # function-hallucination uses thinking mode
    assert req["body"]["messages"][0]["role"] == "system"
    assert "tool-call validator" in req["body"]["messages"][0]["content"].lower()
    assert "shell_execute" in req["body"]["messages"][1]["content"]
    assert req["headers"]["Content-Type"] == "application/json"


def test_build_function_request_includes_auth():
    tool_calls_json = '[]'
    req = build_function_request(tool_calls_json=tool_calls_json, model="m",
                                 prompts=_load_prompts(), api_key="key123")
    assert req["headers"]["Authorization"] == "Bearer key123"


# --- load_prompts: loads all sections ---


def test_load_prompts_all_sections():
    prompts = load_prompts(PROMPTS_PATH)
    assert "fast" in prompts
    assert "thinking" in prompts
    assert "function_hallucination" in prompts
    for section in ("fast", "thinking", "function_hallucination"):
        assert "system" in prompts[section]
        assert "user" in prompts[section]
