from enum import Enum
import logging
import httpx
import os
import asyncio
from typing import Dict, Optional

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
        fail_strategy: str,
        api_key: str = "",
        prompts_path: Optional[str] = None,
    ):
        self.url = url
        self.model = model
        self.fail_strategy = fail_strategy.lower()
        self.api_key = api_key
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

    def _load_prompts(self, path: Optional[str]) -> Dict:
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
                    return await self._handle_failure()

                logger.error("Guardian API returned unexpected status: %d", response.status_code)
                return await self._handle_failure()

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.warning("Guardian safety check failed: %s", str(e))
            return await self._handle_failure()
        except Exception as e:
            logger.exception("Unexpected error in GuardianGuard: %s", str(e))
            return await self._handle_failure()

    def _build_request(self, prompt: str, think: bool) -> Dict:
        """Build an OpenAI chat-completions request for the guardian."""
        from gateway.core.guardian_client import build_request
        return build_request(
            prompt=prompt,
            model=self.model,
            think=think,
            prompts=self._prompts,
            api_key=self.api_key,
        )

    async def _handle_failure(self) -> SafetyDecision:
        """
        Implements the 4-way switch for GUARDIAN_FAIL_STRATEGY.
        """
        if self.fail_strategy == "block":
            logger.critical("Guardian FAIL-CLOSED: Blocking request due to system failure.")
            return SafetyDecision.BLOCK
        
        elif self.fail_strategy == "allow":
            logger.warning("Guardian FAIL-OPEN: Allowing request despite system failure.")
            return SafetyDecision.ALLOW
        
        elif self.fail_strategy == "warn":
            logger.warning("Guardian AUDIT-MODE: Allowing request and tagging as unverified.")
            return SafetyDecision.WARNING
        
        elif self.fail_strategy == "fallback":
            return await self._emergency_filter()
        
        # Default to safest option
        return SafetyDecision.BLOCK

    async def _emergency_filter(self) -> SafetyDecision:
        """
        Local emergency filter used when cloud backend is unreachable (Fallback strategy).
        Placeholder implementation for Phase 1.3.
        """
        # FUTURE: Implement regex/keyword checks here.
        # For now, we return ALLOW to avoid blocking users in dev, 
        # but in a real prod scenario, this might be a strict BLOCK.
        logger.info("Executing local emergency filter (fallback)...")
        return SafetyDecision.ALLOW
