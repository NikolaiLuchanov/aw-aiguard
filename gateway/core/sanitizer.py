"""
Ingestion Sanitizer — Stored Injection Countermeasures (Phase 4.2)

Sanitizes ingested content (LLM responses, RAG docs, web pages, file reads)
before it enters the LLM context window or RAG store. Targets:

- <script> tags and their content
- Zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF, U+2060, U+00AD)
- HTML comments containing injection-related keywords
- CSS-hiding patterns (display:none, visibility:hidden, white-on-white)
- Base64-encoded payloads (log_only for analysis)
- Meta refresh / redirect tags
- Iframe embeds
- JavaScript event handler attributes

Patterns are configured in guardrail-config/ingestion_sanitize_rules.yaml.
Each pattern has an action (strip, redact, log_only) and severity level.

Low-trust provenance (trust_level < 0.5) triggers **aggressive mode**:
log_only rules are elevated to warn, triggering audit alerts for dangerous patterns.

Phase 4.2 deliverable — Layer 2+ of the safety pipeline.
"""

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from gateway.core.provenance import Provenance

logger = logging.getLogger(__name__)


@dataclass
class SanitizationResult:
    """Result of a sanitization pass."""
    cleaned_content: str          # Content after sanitization
    stripped_count: int           # Total patterns removed/redacted
    dangerous_patterns: list      # Names of dangerous patterns found
    action_taken: dict            # {pattern_name: action_applied}

    def __post_init__(self):
        if self.dangerous_patterns is None:
            object.__setattr__(self, "dangerous_patterns", [])
        if self.action_taken is None:
            object.__setattr__(self, "action_taken", {})


class IngestionSanitizer:
    """
    Regex-based ingestion sanitizer for stored injection countermeasures.

    Runs configurable regex patterns on input text, applying strip/redact/log_only actions.
    Supports Unicode NFC normalization and trust-level-aware aggressive mode.

    Pipeline position: Response path (LLM → client), catching injected content
    the LLM may have generated from poisoned context. Other ingestion points
    (web fetches, RAG, file reads) call the sanitizer directly.
    """

    # Compiled regex cache to avoid recompilation
    _compiled_cache: Dict[str, re.Pattern] = {}

    def __init__(self, rules_path: str, action_mode: Optional[str] = None):
        """
        Initialize the sanitizer.

        Args:
            rules_path: Path to ingestion_sanitize_rules.yaml.
            action_mode: Global action override — "strip", "redact", or "log_only".
                         When None (default), each rule's per-pattern action is used.
        """
        self.rules = self._load_rules(rules_path)
        self.action_mode = action_mode
        self._compile_patterns()

    def _load_rules(self, path: str) -> List[Dict[str, Any]]:
        """Load sanitization rules from YAML file."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
                patterns = data.get("patterns", [])
                if patterns is None:
                    return []
                return patterns
        except Exception as e:
            logger.error("Failed to load sanitize rules from %s: %s", path, e)
            return []

    def _compile_patterns(self):
        """Pre-compile all regex patterns for performance."""
        self._compiled_cache = {}
        for rule in self.rules:
            name = rule.get("name", "")
            pattern_str = rule.get("pattern", "").strip()  # Strip whitespace/newlines from | block scalars
            flags_str = rule.get("flags", "")

            # Parse flags from string like "re.IGNORECASE | re.DOTALL"
            flag_mask = 0
            if flags_str:
                flag_names = [f.strip() for f in flags_str.split("|")]
                for fn in flag_names:
                    if fn == "re.IGNORECASE":
                        flag_mask |= re.IGNORECASE
                    elif fn == "re.DOTALL":
                        flag_mask |= re.DOTALL
                    elif fn == "re.MULTILINE":
                        flag_mask |= re.MULTILINE

            try:
                compiled = re.compile(pattern_str, flag_mask)
                self._compiled_cache[name] = compiled
            except re.error as e:
                logger.error("Invalid regex pattern '%s': %s", name, e)

    def _resolve_action(self, rule: Dict[str, Any]) -> str:
        """Resolve the effective action for a rule."""
        if self.action_mode:
            return self.action_mode
        return rule.get("action", "log_only")

    def sanitize(self, content: str, provenance: Optional[Provenance] = None) -> SanitizationResult:
        """
        Sanitize ingested content.

        Args:
            content: The text to sanitize (LLM response, RAG doc, etc.).
            provenance: Optional provenance for trust-level-aware aggressive mode.

        Returns:
            SanitizationResult with cleaned content and metadata.
        """
        if not content:
            return SanitizationResult(
                cleaned_content=content or "",
                stripped_count=0,
                dangerous_patterns=[],
                action_taken={},
            )

        # Step 1: Unicode NFC normalization to prevent NFD-encoded bypasses
        text = unicodedata.normalize("NFC", content)

        # Determine if aggressive mode applies
        is_aggressive = provenance is not None and provenance.is_low_trust

        stripped_count = 0
        dangerous_patterns: List[str] = []
        action_taken: Dict[str, str] = {}

        # Step 2: Apply all patterns in order
        for rule in self.rules:
            name = rule.get("name", "")
            severity = rule.get("severity", "low")
            action = self._resolve_action(rule)
            compiled = self._compiled_cache.get(name)

            if compiled is None:
                continue

            # In aggressive mode, elevate log_only to warn behavior
            # (still strip/redact, but always flag as dangerous)
            effective_action = action
            if is_aggressive and action == "log_only":
                effective_action = "warn"
                # "warn" preserves content but always flags
                match = compiled.search(text)
                if match:
                    dangerous_patterns.append(name)
                    action_taken[name] = "warn (elevated from log_only)"
                    stripped_count += 1
                continue

            # Apply the pattern
            match = compiled.search(text)
            if not match:
                continue

            match_count = len(compiled.findall(text))
            text, count = self._apply_pattern(text, rule, effective_action)
            stripped_count += count

            dangerous_patterns.append(name)
            action_taken[name] = effective_action

            # Also track elevated actions for aggressive mode
            if is_aggressive and effective_action == "warn":
                action_taken[name] = "warn (elevated from log_only)"

        # Step 3: Record sanitization metadata in provenance if available
        if provenance and dangerous_patterns:
            provenance.record_sanitization(
                patterns=dangerous_patterns,
                applied=stripped_count > 0,
            )

        return SanitizationResult(
            cleaned_content=text,
            stripped_count=stripped_count,
            dangerous_patterns=dangerous_patterns,
            action_taken=action_taken,
        )

    def _apply_pattern(self, content: str, rule: Dict[str, Any], action: str) -> tuple:
        """
        Apply a single regex pattern to content.

        Args:
            content: Current text content.
            rule: Rule definition dict.
            action: "strip", "redact", or "log_only".

        Returns:
            (new_content, match_count) tuple.
        """
        name = rule.get("name", "unknown")
        compiled = self._compiled_cache.get(name)
        if compiled is None:
            return content, 0

        match_count = len(compiled.findall(content))

        if action == "strip":
            # Remove matched content entirely
            new_content = compiled.sub("", content)
            return new_content, match_count

        elif action == "redact":
            # Replace with [REDACTED: <name>] marker
            replacement = f"[REDACTED: {name}]"
            new_content = compiled.sub(replacement, content)
            return new_content, match_count

        elif action == "log_only":
            # Preserve content, no modification
            return content, match_count

        elif action == "warn":
            # Warn preserves content but always flags in dangerous_patterns
            return content, match_count

        # Unknown action — treat as log_only (safe default)
        return content, match_count

    def get_rules_summary(self) -> List[Dict[str, str]]:
        """Return a summary of loaded rules for debugging/inspection."""
        return [
            {
                "name": rule.get("name", ""),
                "action": rule.get("action", "log_only"),
                "severity": rule.get("severity", "low"),
                "description": rule.get("description", ""),
            }
            for rule in self.rules
        ]

    def reload_rules(self, rules_path: str) -> None:
        """Hot-reload rules from a new or updated file path."""
        old_rules = self.rules
        self.rules = self._load_rules(rules_path)
        self._compile_patterns()
        logger.info(
            "Sanitizer rules reloaded: %d rules (was %d)",
            len(self.rules),
            len(old_rules),
        )
