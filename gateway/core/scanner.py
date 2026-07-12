import re
import yaml
import logging
from typing import Tuple, List, Dict
from gateway.core.guardrail import SafetyDecision

logger = logging.getLogger(__name__)

class PIIScanner:
    """
    High-performance PII and Secret scanning engine.
    Uses regex-based pattern matching with action-based rules.
    """
    def __init__(self, rules_path: str, redaction_mode: str = "token", block_mode: str = "block"):
        self.redaction_mode = redaction_mode
        self.block_mode = block_mode.lower()  # "block" = enforce block actions; "warn" = down-grade block to warn
        self.rules = self._load_rules(rules_path)
        logger.info(f"PIIScanner initialized with {len(self.rules)} rules in {redaction_mode} mode, action={block_mode}.")

    def _load_rules(self, path: str) -> List[Dict]:
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f)
                rules = config.get('rules', [])
                for rule in rules:
                    rule['compiled'] = re.compile(rule['pattern'])
                return rules
        except Exception as e:
            logger.error(f"Failed to load scan rules from {path}: {e}")
            return []

    def scan_text(self, text: str) -> Tuple[str, SafetyDecision]:
        if not text:
            return text, SafetyDecision.ALLOW

        current_text = text
        overall_decision = SafetyDecision.ALLOW
        redaction_count = 0

        for rule in self.rules:
            pattern = rule['compiled']
            action = rule.get('action', 'redact').lower()
            matches = list(pattern.finditer(current_text))
            if not matches:
                continue
            
            if action == 'block':
                if self.block_mode == 'block':
                    logger.warning(f"CRITICAL: {rule['name']} detected. Blocking request.")
                    return text, SafetyDecision.BLOCK
                else:
                    logger.warning(f"SECURITY WARN (block downgraded): {rule['name']} detected in prompt (SCAN_ACTION_MODE=warn).")
                    if overall_decision == SafetyDecision.ALLOW:
                        overall_decision = SafetyDecision.WARNING
            elif action == 'ignore':
                continue
            elif action == 'warn':
                logger.warning(f"SECURITY WARN: {rule['name']} detected in prompt.")
                if overall_decision == SafetyDecision.ALLOW:
                    overall_decision = SafetyDecision.WARNING
            elif action == 'redact':
                for match in reversed(matches):
                    val = match.group(0)
                    redacted_val = self._apply_redaction(val, rule['name'], redaction_count)
                    current_text = current_text[:match.start()] + redacted_val + current_text[match.end():]
                    redaction_count += 1
        
        if redaction_count > 0:
            logger.info(f"PII Scanner: Redacted {redaction_count} items.")
        return current_text, overall_decision

    def _apply_redaction(self, value: str, rule_name: str, index: int) -> str:
        if self.redaction_mode == "token":
            clean_name = rule_name.replace(" ", "_").upper()
            return f"[{clean_name}_{index + 1}]"
        if len(value) <= 8: return "*" * len(value)
        return f"{value[:4]}****{value[-4:]}"
