from enum import Enum
import logging
import httpx
import asyncio
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class SafetyDecision(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARNING = "warning"

class GuardianGuard:
    """
    Robust adapter for the Central Service Guardian Model.
    Handles dialect translation, circuit breaking, and fail-safe strategies.
    """
    def __init__(self, url: str, model: str, fail_strategy: str):
        self.url = url
        self.model = model
        self.fail_strategy = fail_strategy.lower()
        self.timeout = httpx.Timeout(2.0)        # fast mode
        self.thinking_timeout = httpx.Timeout(30.0)  # thinking mode (Phase 4.4)

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
            async with httpx.AsyncClient(timeout=timeout) as client:
                payload: Dict[str, object] = {
                    "prompt": prompt,
                    "model": self.model,
                }
                if think:
                    payload["think"] = True  # Phase 4.4: thinking mode flag
                response = await client.post(
                    self.url,
                    json=payload
                )
                
                if response.status_code == 200:
                    data = response.json()
                    score = data.get("score", "").lower()
                    
                    if score == "yes":
                        return SafetyDecision.ALLOW
                    elif score == "no":
                        return SafetyDecision.BLOCK
                    
                logger.error(f"Guardian API returned unexpected status: {response.status_code}")
                return await self._handle_failure()
                
        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.warning(f"Guardian safety check failed: {str(e)}")
            return await self._handle_failure()
        except Exception as e:
            logger.exception(f"Unexpected error in GuardianGuard: {str(e)}")
            return await self._handle_failure()

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
