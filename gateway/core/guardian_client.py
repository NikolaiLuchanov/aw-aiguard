"""
Guardian wire protocol: llama.cpp OpenAI-compatible /v1/chat/completions.

Pure functions only (no I/O) so the protocol is unit-testable without a
server. GuardianGuard (guardrail.py) owns the HTTP + fail-strategy logic and
delegates request-building/parsing here.

Protocol:
  Request shape (OpenAI chat-completions):
    {
      "model": "<model>",
      "messages": [
        {"role": "system", "content": "<system prompt>"},
        {"role": "user", "content": "<user prompt with {prompt} or {tool_calls_json} interpolated>"}
      ],
      "max_tokens": 8,           # fast mode (or 256 for thinking)
      "temperature": 0,
      "stream": false
    }

  Response shape:
    {
      "choices": [{
        "message": {"role": "assistant", "content": "<score>yes</score>" | "no" | <thinking trace>}
      }]
    }

  Parser: extract yes/no from content with this precedence:
    1. <score>yes</score> / <score>no</score> tag (case-insensitive)
    2. First whole-word yes/no token in the content
    3. None (caller applies fail strategy)

  Auth: optional Bearer token via GUARDIAN_API_KEY (llama.cpp --api-key).
"""
import json
import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger("aw-aiguard.guardian")

FAST_MAX_TOKENS = 8
THINK_MAX_TOKENS = 256

_SCORE_TAG = re.compile(r"<score>\s*(yes|no)\s*</score>", re.IGNORECASE)
_WHOLE_WORD = re.compile(r"\b(yes|no)\b", re.IGNORECASE)


def load_prompts(path: str) -> Dict[str, Dict[str, str]]:
    """Load guardian_prompts.yaml. Raises on missing file (config is required)."""
    import yaml
    with open(path, "r") as f:
        return yaml.safe_load(f)


def build_request(
    prompt: str,
    model: str,
    think: bool,
    prompts: Dict[str, Dict[str, str]],
    api_key: str = "",
) -> Dict[str, Any]:
    """Build an OpenAI chat-completions request for the guardian.

    Args:
        prompt: The text to evaluate (for fast/thinking) or tool-calls JSON (for function_hallucination).
        model: The guardian model identifier.
        think: If True, use thinking mode (longer max_tokens, thinking template).
        prompts: Prompt templates loaded from guardian_prompts.yaml.
        api_key: Optional API key for llama.cpp auth.

    Returns:
        Dict with keys "body" (the JSON payload) and "headers" (HTTP headers).
    """
    tpl = prompts["thinking" if think else "fast"]
    body: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": tpl["system"].strip()},
            {"role": "user", "content": tpl["user"].strip().format(prompt=prompt)},
        ],
        "max_tokens": THINK_MAX_TOKENS if think else FAST_MAX_TOKENS,
        "temperature": 0,
        "stream": False,
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return {"body": body, "headers": headers}


def build_function_request(
    tool_calls_json: str,
    model: str,
    prompts: Dict[str, Dict[str, str]],
    api_key: str = "",
) -> Dict[str, Any]:
    """Build a function-hallucination request for the guardian.

    Args:
        tool_calls_json: JSON-serialized tool calls list.
        model: The guardian model identifier.
        prompts: Prompt templates loaded from guardian_prompts.yaml.
        api_key: Optional API key for llama.cpp auth.

    Returns:
        Dict with keys "body" (the JSON payload) and "headers" (HTTP headers).
    """
    tpl = prompts["function_hallucination"]
    body: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": tpl["system"].strip()},
            {"role": "user", "content": tpl["user"].strip().format(tool_calls_json=tool_calls_json)},
        ],
        "max_tokens": THINK_MAX_TOKENS,  # function-hallucination uses thinking mode for thorough analysis
        "temperature": 0,
        "stream": False,
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return {"body": body, "headers": headers}


def parse_score(content: str) -> Optional[str]:
    """Extract a yes/no score from the guardian's response text.

    Precedence:
      1. <score>yes</score> or <score>no</score> tag (case-insensitive).
      2. First whole-word yes/no token in the content.

    Returns 'yes'/'no', or None (caller applies the fail strategy).
    This is intentionally strict — no lenient substring matching.
    Granite's thinking-mode traces can contain 'yes'/'no' in prose,
    so the tag check comes first to avoid false ALLOWs.
    """
    if not content:
        return None
    m = _SCORE_TAG.search(content)
    if m:
        return m.group(1).lower()
    m = _WHOLE_WORD.search(content.strip())
    if m:
        return m.group(1).lower()
    return None
