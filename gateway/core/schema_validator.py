from __future__ import annotations

"""
CaMeL Structural Enforcement — Schema Validator (Phase 4.5.1)

Validates tool-call parameters against predefined JSON schemas before
they reach the target API or system command. This implements the CaMeL
pattern: physical isolation of data flows from control flows.

Schemas loaded from guardrail-config/tool_schemas.yaml.
Rules loaded from guardrail-config/camel_rules.yaml.

Phase 4.5.1 deliverable — Layer L0/L4 of the safety pipeline.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

import jsonschema
import yaml

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of a JSON schema validation pass."""
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    tool_name: str = ""


class SchemaValidator:
    """
    Validates tool-call parameters against JSON Schema Draft 7.

    Pipeline position: Between Function-Call Detector (4.1) and BYOC (L3).

    Key design decisions:
    - Unknown tools pass through (not blocked) — logged as warning
    - Strict mode is opt-in via camel_rules.yaml enforcement level
    - Per-tool overrides supported via the YAML structure
    """

    def __init__(
        self,
        schema_path: str,
        rules_path: str,
    ):
        """
        Initialize the schema validator.

        Args:
            schema_path: Path to tool_schemas.yaml
            rules_path: Path to camel_rules.yaml
        """
        self.schemas = self._load_schemas(schema_path)
        self.rules = self._load_rules(rules_path)
        logger.info(
            "SchemaValidator initialized: %d schemas, %d rules",
            len(self.schemas),
            len(self.rules),
        )

    # --- Loading ---

    def _load_schemas(self, path: str) -> dict[str, Any]:
        """Load tool schemas from YAML file."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
                return data.get("schemas", {}) or {}
        except Exception as e:
            logger.error("Failed to load tool schemas from %s: %s", path, e)
            return {}

    def _load_rules(self, path: str) -> list[dict[str, Any]]:
        """Load CaMeL enforcement rules from YAML file."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
                rules = data.get("rules", [])
                if rules is None:
                    return []
                return rules
        except Exception as e:
            logger.error("Failed to load CaMeL rules from %s: %s", path, e)
            return []

    # --- Public API ---

    def validate(
        self,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ValidationResult:
        """
        Validate tool-call parameters against the registered JSON schema.

        Args:
            tool_name: Name of the tool being invoked.
            parameters: Dict of parameter name → value.

        Returns:
            ValidationResult with valid flag and error list.
        """
        result = ValidationResult(tool_name=tool_name)

        # Unknown tools pass through (not blocked) — log warning
        if tool_name not in self.schemas:
            logger.warning(
                "SchemaValidator: no schema registered for tool '%s' — passing through",
                tool_name,
            )
            return result  # valid=True, empty errors

        schema = self.schemas[tool_name]

        try:
            jsonschema.validate(instance=parameters, schema=schema)
            # Validation passed
            result.valid = True
        except jsonschema.ValidationError as e:
            result.valid = False
            result.errors.append(str(e.message))
            logger.warning(
                "Schema validation failed for tool '%s': %s",
                tool_name,
                e.message,
            )
        except jsonschema.SchemaError as e:
            result.valid = False
            result.errors.append(f"Schema error: {e.message}")
            logger.error(
                "Schema error for tool '%s': %s",
                tool_name,
                e.message,
            )

        return result

    def get_schema_names(self) -> list[str]:
        """Return list of registered schema names (for dashboard/status)."""
        return list(self.schemas.keys())

    def get_rule_names(self) -> list[str]:
        """Return list of loaded rule names (for dashboard/status)."""
        return [r.get("name", "") for r in self.rules]

    # --- Hot-reload ---

    def reload_schemas(self, schema_path: str) -> None:
        """Hot-reload schemas from a new or updated file path."""
        old = self.schemas
        self.schemas = self._load_schemas(schema_path)
        logger.info(
            "SchemaValidator schemas reloaded: %d schemas (was %d)",
            len(self.schemas),
            len(old),
        )

    def reload_rules(self, rules_path: str) -> None:
        """Hot-reload CaMeL rules from a new or updated file path."""
        old = self.rules
        self.rules = self._load_rules(rules_path)
        logger.info(
            "SchemaValidator rules reloaded: %d rules (was %d)",
            len(self.rules),
            len(old),
        )
