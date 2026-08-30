from __future__ import annotations

import logging
import os
from enum import Enum
from typing import Any, Optional

import httpx

from gateway.core.guardian_client import parse_score

logger = logging.getLogger(__name__)

class SafetyDecision(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARNING = "warning"

class GuardianGuard:
    """
    Robust adapter for the Central Service Guardian Model.

    Wire protocol: llama.cpp OpenAI-compatible /v1/chat/completions.
    Builds requests via gateway.core.guardian_client.build_request() and
    parses responses via guardian_client.parse_score().

    Handles dialect translation, circuit breaking, and fail-safe strategies.
    """
    def __init__(
        self,
        url: str,
        model: str,
        fail_strategy: Optional[str],
        api_key: str = "",
        prompts_path: Optional[str] = None,
        guardian_threshold: Optional[float] = None,
        llm_safety_mode: Optional[str] = None,
        scanner: Optional[Any] = None,
    ):
        self.url = url
        self.model = model
        self.fail_strategy = fail_strategy.lower() if fail_strategy else ""
        self.api_key = api_key
        # Settings-driven configuration (wired from settings.yaml — Finding #7).
        # If not explicitly passed, falls back to env vars then to embedded defaults.
        self.guardian_threshold = guardian_threshold if guardian_threshold is not None else float(
            os.getenv("GUARDIAN_THRESHOLD", "0.85")
        )
        self.llm_safety_mode = (llm_safety_mode or
                                os.getenv("LLM_SAFETY_MODE", "hard_block")).lower()
        # Timeout defaults are env-tunable for remote EC2 deployment.
        # Raise GUARDIAN_TIMEOUT for cross-internet latency (default: 2.0s).
        # Raise GUARDIAN_THINKING_TIMEOUT for thinking mode (default: 30.0s).
        self.timeout = httpx.Timeout(
            float(os.getenv("GUARDIAN_TIMEOUT", "2.0"))
        )
        self.thinking_timeout = httpx.Timeout(
            float(os.getenv("GUARDIAN_THINKING_TIMEOUT", "30.0"))
        )
        self._prompts = self._load_prompts(prompts_path)
        self.scanner = scanner

    def _load_prompts(self, path: Optional[str]) -> dict:
        """Load guardian prompt templates from YAML, falling back to bundled defaults."""
        from gateway.core.guardian_client import load_prompts
        if path and os.path.isfile(path):
            try:
                return load_prompts(path)
            except Exception as e:
                logger.warning("Failed to load prompts from %s: %s; using bundled defaults", path, e)
        # Fallback: embedded defaults (same content as guardian_prompts.yaml)
        return {
            "fast": {
                "system": "You are a safety classifier. Answer with exactly one word: \"yes\" or \"no\".",
                "user": "Is the following prompt safe to process? Respond with only \"yes\" (safe) or\n\"no\" (unsafe).\nPrompt: {prompt}",
            },
            "thinking": {
                "system": "You are a safety classifier. Reason briefly, then answer with exactly one\nfinal word: \"yes\" or \"no\".",
                "user": "Reason step by step about whether the following prompt is safe to process,\nthen respond with only \"yes\" (safe) or \"no\" (unsafe).\nPrompt: {prompt}",
            },
            "function_hallucination": {
                "system": "You are a tool-call validator. Answer with exactly one word: \"yes\" or \"no\".",
                "user": "The AI assistant proposed the following tool calls. Are these tool calls\nlegitimate and consistent with the user's request, or are they fabricated\nor suspicious? Answer \"yes\" if legitimate, \"no\" if hallucinated or suspicious.\nTool calls:\n{tool_calls_json}",
            },
        }

    def _resolve_fail_strategy(self) -> str:
        """Resolve fail_strategy from llm_safety_mode if not explicitly set.

        Mapping (settings.yaml → fail_strategy):
          hard_block → block
          warn_only  → warn
          hybrid     → allow

        If fail_strategy was explicitly set in the constructor, it wins.
        When fail_strategy is a settings value (hard_block/warn_only/hybrid),
        map it directly to the corresponding fail_strategy.
        When fail_strategy is empty (None passed), fall back to llm_safety_mode.
        """
        if self.fail_strategy not in ("hard_block", "warn_only", "hybrid", ""):
            # Already a proper fail_strategy value
            return self.fail_strategy

        mode_map = {
            "hard_block": "block",
            "warn_only": "warn",
            "hybrid": "allow",
        }

        # If fail_strategy is a settings value, map it directly
        if self.fail_strategy in mode_map:
            resolved = mode_map[self.fail_strategy]
        # If fail_strategy is empty, try llm_safety_mode first
        elif self.llm_safety_mode in mode_map:
            resolved = mode_map[self.llm_safety_mode]
        else:
            resolved = "block"

        logger.info("Resolved fail_strategy=%s, llm_safety_mode=%s → %s",
                     self.fail_strategy, self.llm_safety_mode, resolved)
        return resolved

    async def check_safety(self, prompt: str, think: bool = False) -> SafetyDecision:
        """
        Performs a pre-flight safety check.

        Args:
            prompt: Text to evaluate.
            think: If True, runs Guardian in thinking mode (deeper reasoning, higher latency).

        Returns:
            SafetyDecision based on the model score or the fail-safe strategy.
        """
        try:
            timeout = self.thinking_timeout if think else self.timeout
            req = self._build_request(prompt, think)
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    self.url,
                    json=req["body"],
                    headers=req["headers"],
                )

                if response.status_code == 200:
                    data = response.json()
                    choices = data.get("choices") or []
                    content = ""
                    if choices:
                        content = (choices[0].get("message") or {}).get("content", "")
                    score = parse_score(content)
                    if score == "yes":
                        return SafetyDecision.ALLOW
                    if score == "no":
                        return SafetyDecision.BLOCK
                    logger.warning(
                        "Guardian returned unparseable score (content=%r) — applying fail strategy.",
                        content[:200],
                    )
                    return await self._handle_failure(prompt)

                logger.error("Guardian API returned unexpected status: %d", response.status_code)
                return await self._handle_failure(prompt)

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.warning("Guardian safety check failed: %s", str(e))
            return await self._handle_failure(prompt)
        except Exception:
            logger.exception("Unexpected error in GuardianGuard")
            return await self._handle_failure(prompt)

    def _build_request(self, prompt: str, think: bool) -> dict:
        """Build an OpenAI chat-completions request for the guardian."""
        from gateway.core.guardian_client import build_request
        return build_request(
            prompt=prompt,
            model=self.model,
            think=think,
            prompts=self._prompts,
            api_key=self.api_key,
        )

    async def _handle_failure(self, prompt: Optional[str] = None) -> SafetyDecision:
        """
        Implements the 4-way switch for GUARDIAN_FAIL_STRATEGY.

        Uses _resolve_fail_strategy() to apply settings.yaml-driven
        llm_safety_mode when fail_strategy was set from settings rather than env.
        """
        strategy = self._resolve_fail_strategy()

        if strategy == "block":
            logger.critical("Guardian FAIL-CLOSED: Blocking request due to system failure.")
            return SafetyDecision.BLOCK

        elif strategy == "allow":
            logger.warning("Guardian FAIL-OPEN: Allowing request despite system failure.")
            return SafetyDecision.ALLOW

        elif strategy == "warn":
            logger.warning("Guardian AUDIT-MODE: Allowing request and tagging as unverified.")
            return SafetyDecision.WARNING

        elif strategy == "fallback":
            return await self._emergency_filter(prompt)

        # Default to safest option
        return SafetyDecision.BLOCK

    async def _emergency_filter(self, prompt: Optional[str] = None) -> SafetyDecision:
        """
        Local emergency filter used when cloud Guardian is unreachable (Fallback strategy).

        Uses the PII scanner as a lightweight local safety net — blocks requests
        that contain detected PII/secrets (credit cards, keys, private keys, etc.),
        otherwise allows. Local dev can opt into blocking all via
        ``EMERGENCY_FILTER_BLOCK_ALL=true`` env var.
        """
        block_all = os.getenv("EMERGENCY_FILTER_BLOCK_ALL", "false").lower() == "true"

        if block_all:
            logger.warning(
                "Guardian unreachable — EMERGENCY_FILTER_BLOCK_ALL=true — blocking request."
            )
            return SafetyDecision.BLOCK

        if self.scanner and prompt:
            logger.info(
                "Guardian unreachable — running PII scanner as local emergency filter..."
            )
            _, decision = self.scanner.scan_text(prompt)
            if decision == SafetyDecision.BLOCK:
                return SafetyDecision.BLOCK

        logger.info(
            "Guardian unreachable — PII scanner as local emergency filter — ALLOW."
        )
        return SafetyDecision.ALLOW
