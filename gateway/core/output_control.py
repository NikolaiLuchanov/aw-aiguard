"""
Output Control — OWASP LLM05 Countermeasures (Phase 4.3)

Ensures LLM output is treated as untrusted data — never as executable code —
before it reaches the client, shell, browser, DB, or downstream consumers.

Three sub-layers:
1. Output Schema Validation — validate structured responses against JSON schemas
2. HTML/Text Escaping — escape HTML entities before rendering
3. Shell/DB Parameter Quoting — prevent interpolation attacks

Schemas loaded from guardrail-config/output_schemas.yaml.
BYOC rules loaded from guardrail-config/byoc_output_control.yaml.

Phase 4.3 deliverable — Layer 6 of the safety pipeline.
"""

import html
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Result dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class ValidationResult:
    """Result of a schema validation pass."""
    valid: bool = True
    errors: List[str] = field(default_factory=list)
    sanitized: str = ""

    def add_error(self, error: str):
        self.valid = False
        self.errors.append(error)


@dataclass
class OutputControlResult:
    """Result of a full output control pass."""
    content: str                           # Sanitized/escaped content
    schema_validated: bool                 # Whether schema validation passed
    html_escaped: bool                     # Whether HTML escaping was applied
    shell_quoted: bool                     # Whether shell quoting was applied
    schema_errors: List[str] = field(default_factory=list)
    byoc_violations: List[str] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""                 # Why it was blocked (BYOC hard_stop)


# --------------------------------------------------------------------------- #
# Output Controller
# --------------------------------------------------------------------------- #


class OutputController:
    """
    Post-response output control layer for OWASP LLM05.

    Runs after the LLM response is received and before it reaches the client.
    Validates schema, escapes HTML, quotes shell parameters.

    Pipeline position: Post-response (after LLM response, before delivery).
    """

    def __init__(
        self,
        schema_path: str,
        byoc_rules_path: str,
    ):
        """
        Initialize the output controller.

        Args:
            schema_path: Path to output_schemas.yaml.
            byoc_rules_path: Path to byoc_output_control.yaml.
        """
        self.schemas = self._load_schemas(schema_path)
        self.byoc_rules = self._load_byoc_rules(byoc_rules_path)

    # --- Loading ---

    def _load_schemas(self, path: str) -> Dict[str, Any]:
        """Load output schemas from YAML file."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
                return data.get("schemas", {}) or {}
        except Exception as e:
            logger.error("Failed to load output schemas from %s: %s", path, e)
            return {}

    def _load_byoc_rules(self, path: str) -> List[Dict[str, Any]]:
        """Load BYOC output control rules from YAML file."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
                rules = data.get("rules", [])
                if rules is None:
                    return []
                return rules
        except Exception as e:
            logger.error("Failed to load byoc output control rules from %s: %s", path, e)
            return []

    # --- Public API ---

    def validate_response(
        self,
        response_text: str,
        tool_name: Optional[str] = None,
    ) -> OutputControlResult:
        """
        Run all output control checks on LLM response text.

        Args:
            response_text: The raw LLM response.
            tool_name: Optional tool name for schema lookup.

        Returns:
            OutputControlResult with all validation/escaping results.
        """
        if not response_text:
            return OutputControlResult(
                content="",
                schema_validated=True,
                html_escaped=False,
                shell_quoted=False,
            )

        result = OutputControlResult(
            content=response_text,
            schema_validated=True,
            html_escaped=False,
            shell_quoted=False,
        )

        # Step 1: Schema validation (if tool-specific schema exists)
        if tool_name and tool_name in self.schemas:
            schema = self.schemas[tool_name]
            schema_result = self._validate_json_schema(response_text, schema)
            result.schema_validated = schema_result.valid
            result.schema_errors = schema_result.errors

            # Check BYOC rule: require_schema_validation
            for rule in self.byoc_rules:
                if rule.get("name") == "require_schema_validation" and not schema_result.valid:
                    if rule.get("enforcement") == "hard_stop":
                        result.blocked = True
                        result.block_reason = f"BYOC hard_stop: {rule.get('description', '')}"
                        result.byoc_violations.append(rule.get("name", "unknown"))
                    else:
                        # soft_block — warn but don't block
                        result.byoc_violations.append(rule.get("name", "unknown"))

        # Step 2: HTML escaping for all text outputs
        if self._contains_html_tags(response_text):
            result.content = self.escape_html(result.content)
            result.html_escaped = True

            # Check BYOC rule: never_shell_interpolate_llm_output
            # (check on original text, before escaping — after escaping tags are neutralized)
            for rule in self.byoc_rules:
                if rule.get("name") == "never_shell_interpolate_llm_output":
                    # Only block if original contained active script content
                    if rule.get("enforcement") == "hard_stop":
                        if self._contains_script_content(response_text):
                            result.blocked = True
                            result.block_reason = f"BYOC hard_stop: {rule.get('description', '')}"
                            result.byoc_violations.append(rule.get("name", "unknown"))

        # Step 3: Shell/DB parameter quoting check
        # Detect if the output looks like it might be used in shell/DB context
        if self._looks_like_shell_command(response_text) or self._looks_like_sql(response_text):
            result.content = self.quote_shell_param(result.content)
            result.shell_quoted = True

            # Check BYOC rule: never_sql_unquoted
            for rule in self.byoc_rules:
                if rule.get("name") == "never_sql_unquoted":
                    if rule.get("enforcement") == "hard_stop":
                        # Output has been quoted, so the violation is mitigated
                        # but we still log the detection
                        logger.warning("SQL-interpolation pattern detected in output, auto-quoted")

        return result

    # --- Schema validation (simplified JSON Schema validation) ---

    def _validate_json_schema(self, text: str, schema: Dict[str, Any]) -> ValidationResult:
        """
        Validate text against a JSON schema (simplified, no external deps).

        Supports: type, required, properties, items, maxLength, minimum, maximum, format (uri).
        """
        vr = ValidationResult()

        # Try to parse as JSON first
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            vr.add_error("Response is not valid JSON (schema requires structured data)")
            return vr

        # Type check
        expected_type = schema.get("type")
        if expected_type and not self._check_type(data, expected_type):
            vr.add_error(f"Expected type '{expected_type}', got '{type(data).__name__}'")
            return vr

        # Object-level checks
        if expected_type == "object" and isinstance(data, dict):
            # Required fields
            for field_name in schema.get("required", []):
                if field_name not in data:
                    vr.add_error(f"Missing required field: '{field_name}'")

            # Properties validation
            properties = schema.get("properties", {})
            for prop_name, prop_schema in properties.items():
                if prop_name not in data:
                    continue
                value = data[prop_name]

                # Type check for property
                if "type" in prop_schema and not self._check_type(value, prop_schema["type"]):
                    vr.add_error(f"Field '{prop_name}': expected type '{prop_schema['type']}', got '{type(value).__name__}'")
                    continue

                # String-specific constraints
                if prop_schema.get("type") == "string" and isinstance(value, str):
                    max_length = prop_schema.get("maxLength")
                    if max_length is not None and len(value) > max_length:
                        vr.add_error(f"Field '{prop_name}': exceeds maxLength {max_length} (got {len(value)})")

                    pattern = prop_schema.get("pattern")
                    if pattern and not re.match(pattern, value):
                        vr.add_error(f"Field '{prop_name}': does not match pattern '{pattern}'")

                    format_constraint = prop_schema.get("format")
                    if format_constraint == "uri" and not self._is_valid_uri(value):
                        vr.add_error(f"Field '{prop_name}': invalid URI format")

                # Number constraints (integer, number)
                if isinstance(value, (int, float)):
                    if "minimum" in prop_schema and value < prop_schema["minimum"]:
                        vr.add_error(f"Field '{prop_name}': below minimum {prop_schema['minimum']}")
                    if "maximum" in prop_schema and value > prop_schema["maximum"]:
                        vr.add_error(f"Field '{prop_name}': exceeds maximum {prop_schema['maximum']}")

                # Array items validation
                if prop_schema.get("type") == "array" and isinstance(value, list):
                    items_schema = prop_schema.get("items", {})
                    if items_schema:
                        for i, item in enumerate(value):
                            if "type" in items_schema and not self._check_type(item, items_schema["type"]):
                                vr.add_error(f"Field '{prop_name}': item {i} has wrong type (expected '{items_schema['type']}')")
                            # Recurse for nested objects
                            if items_schema.get("type") == "object" and isinstance(item, dict):
                                nested = self._validate_json_schema(json.dumps(item), items_schema)
                                for err in nested.errors:
                                    vr.add_error(f"Field '{prop_name}': item {i} — {err}")

        return vr

    def _check_type(self, value: Any, expected: str) -> bool:
        """Check if a Python value matches a JSON Schema type."""
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
            "null": type(None),
        }
        python_type = type_map.get(expected)
        if python_type is None:
            return True  # Unknown type, pass through
        # In JSON, booleans are not integers — be explicit
        if expected == "integer" and isinstance(value, bool):
            return False
        if expected == "number" and isinstance(value, bool):
            return False
        return isinstance(value, python_type)

    def _is_valid_uri(self, value: str) -> bool:
        """Basic URI validation (http/https/file schemes)."""
        return bool(re.match(r"^(https?|file)://", value))

    # --- HTML escaping ---

    def _contains_html_tags(self, text: str) -> bool:
        """Check if text contains HTML tags."""
        return bool(re.search(r"<[^>]+>", text))

    def _contains_script_content(self, text: str) -> bool:
        """Check if text contains active script-like content."""
        return bool(re.search(r"<\s*script[^>]*>", text, re.IGNORECASE))

    def escape_html(self, content: str) -> str:
        """
        Escape HTML entities in content.

        Converts < > & " ' to their HTML entity equivalents.
        """
        return html.escape(content, quote=True)

    # --- Shell/DB parameter quoting ---

    def _looks_like_shell_command(self, text: str) -> bool:
        """Detect if output looks like a shell command that might be interpolated."""
        # Detect command injection patterns that could result from interpolation
        patterns = [
            r";\s*(rm|cat|echo|curl|wget|chmod|chown)\s",  # chained commands
            r"\|\s*(rm|cat|echo|curl|wget)\s",               # pipe to dangerous command
            r"`[^`]+`",                                        # command substitution
            r"\$\([^)]+\)",                                    # $() command substitution
        ]
        return any(re.search(p, text) for p in patterns)

    def _looks_like_sql(self, text: str) -> bool:
        """Detect if output looks like SQL that might be interpolated."""
        patterns = [
            r";\s*(DROP|DELETE|ALTER|CREATE|INSERT|UPDATE)\b",
            r"--\s",                                          # SQL comment
            r"'\s*OR\s+'",                                    # SQL injection pattern
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)

    def quote_shell_param(self, content: str) -> str:
        """
        Quote content for safe shell/DB parameter usage.

        Replaces dangerous characters and wraps in single quotes.
        Single quotes inside are escaped by appending: ' -> '\''
        """
        # Escape single quotes: ' -> '\''
        escaped = content.replace("'", "'\\''")
        # Wrap in single quotes
        return f"'{escaped}'"

    # --- Configuration ---

    def get_schemas_summary(self) -> List[Dict[str, str]]:
        """Return a summary of loaded schemas for debugging/inspection."""
        return [
            {"name": name, "type": schema.get("type", "unknown")}
            for name, schema in self.schemas.items()
        ]

    def get_byoc_rules_summary(self) -> List[Dict[str, str]]:
        """Return a summary of loaded BYOC rules for debugging/inspection."""
        return [
            {
                "name": rule.get("name", ""),
                "enforcement": rule.get("enforcement", "hard_stop"),
                "severity": rule.get("severity", "critical"),
            }
            for rule in self.byoc_rules
        ]

    def reload_schemas(self, schema_path: str) -> None:
        """Hot-reload schemas from a new or updated file path."""
        old = self.schemas
        self.schemas = self._load_schemas(schema_path)
        logger.info(
            "Output controller schemas reloaded: %d schemas (was %d)",
            len(self.schemas),
            len(old),
        )

    def reload_byoc_rules(self, byoc_path: str) -> None:
        """Hot-reload BYOC output control rules from a new or updated file path."""
        old = self.byoc_rules
        self.byoc_rules = self._load_byoc_rules(byoc_path)
        logger.info(
            "Output controller BYOC rules reloaded: %d rules (was %d)",
            len(self.byoc_rules),
            len(old),
        )
