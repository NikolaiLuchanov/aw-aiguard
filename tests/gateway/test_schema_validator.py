"""Tests for gateway/core/schema_validator.py — SchemaValidator (Phase 4.5.1)."""

import json
import tempfile
import os
import pytest
import yaml

from gateway.core.schema_validator import SchemaValidator, ValidationResult


@pytest.fixture
def tool_schemas_path(tmp_path):
    """Write tool schemas YAML and return path."""
    schemas = {
        "schemas": {
            "terminal": {
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9/_\\.\\-\\+\\*\\?\\[\\] ]+$",
                        "maxLength": 1024,
                    },
                    "working_directory": {
                        "type": "string",
                        "pattern": "^/[a-zA-Z0-9/_\\.\\-\\[\\]]+$",
                    },
                    "timeout": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 3600,
                    },
                },
            },
            "browser_navigate": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "format": "uri",
                        "pattern": "^(https?|file)://.*$",
                    },
                },
            },
            "delegate_task": {
                "type": "object",
                "required": ["task"],
                "properties": {
                    "task": {"type": "string", "maxLength": 4096},
                    "max_depth": {"type": "integer", "minimum": 1, "maximum": 5},
                },
            },
            "web_search": {
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 512},
                },
            },
            "file_read": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9/_\\.\\-\\[\\]]+$",
                        "maxLength": 2048,
                    },
                },
            },
        },
    }
    path = tmp_path / "tool_schemas.yaml"
    with open(path, "w") as f:
        yaml.dump(schemas, f)
    return str(path)


@pytest.fixture
def camel_rules_path(tmp_path):
    """Write CaMeL rules YAML and return path."""
    rules = {
        "rules": [
            {
                "name": "validate_all_tool_schemas",
                "enforcement": "hard_stop",
                "severity": "critical",
                "description": "All tool parameters must match their JSON schema",
            },
            {
                "name": "no_string_concat_in_commands",
                "enforcement": "hard_stop",
                "severity": "critical",
                "description": "Untrusted data must never be concatenated into shell commands",
            },
        ],
    }
    path = tmp_path / "camel_rules.yaml"
    with open(path, "w") as f:
        yaml.dump(rules, f)
    return str(path)


@pytest.fixture
def validator(tool_schemas_path, camel_rules_path):
    return SchemaValidator(schema_path=tool_schemas_path, rules_path=camel_rules_path)


# --- Core validation tests ---


class TestSchemaValidatorValidation:
    """Test the validate() method."""

    def test_terminal_command_valid(self, validator):
        """Valid terminal command parameters → passes."""
        result = validator.validate("terminal", {"command": "ls -la /tmp"})
        assert result.valid is True
        assert result.errors == []
        assert result.tool_name == "terminal"

    def test_terminal_command_injection_blocked(self, validator):
        """Command with semicolons and pipes → schema pattern fail."""
        result = validator.validate("terminal", {"command": "ls; rm -rf /"})
        assert result.valid is False
        assert len(result.errors) > 0
        assert result.tool_name == "terminal"

    def test_browser_url_valid(self, validator):
        """Valid URL → passes."""
        result = validator.validate("browser_navigate", {"url": "https://example.com"})
        assert result.valid is True
        assert result.errors == []

    def test_browser_url_malformed_blocked(self, validator):
        """Invalid URL format → fails."""
        result = validator.validate("browser_navigate", {"url": "not-a-url"})
        assert result.valid is False
        assert len(result.errors) > 0

    def test_delegate_task_valid(self, validator):
        """Valid task string → passes."""
        result = validator.validate("delegate_task", {"task": "Review PR #42", "max_depth": 2})
        assert result.valid is True
        assert result.errors == []

    def test_delegate_task_too_long_blocked(self, validator):
        """Task > 4096 chars → maxLength fail."""
        result = validator.validate("delegate_task", {"task": "x" * 4097})
        assert result.valid is False
        assert len(result.errors) > 0

    def test_missing_required_field_blocked(self, validator):
        """Missing 'command' in terminal → required fail."""
        result = validator.validate("terminal", {"working_directory": "/tmp"})
        assert result.valid is False
        assert len(result.errors) > 0

    def test_wrong_type_blocked(self, validator):
        """'timeout' as string → type fail."""
        result = validator.validate("terminal", {
            "command": "ls",
            "timeout": "not_a_number",
        })
        assert result.valid is False
        assert len(result.errors) > 0

    def test_out_of_range_blocked(self, validator):
        """'timeout' > 3600 → maximum fail."""
        result = validator.validate("terminal", {
            "command": "ls",
            "timeout": 9999,
        })
        assert result.valid is False
        assert len(result.errors) > 0

    def test_unknown_tool_skips_validation(self, validator):
        """Unknown tool → pass-through (not blocked)."""
        result = validator.validate("unknown_tool", {"foo": "bar"})
        assert result.valid is True
        assert result.errors == []
        assert result.tool_name == "unknown_tool"

    def test_schema_validation_logged(self, validator, caplog):
        """Audit entry with component and validation result."""
        # A valid check doesn't produce warnings, but a failed one does
        validator.validate("terminal", {"command": "ls; rm -rf /"})
        assert any("Schema validation failed" in str(r) for r in caplog.messages)

    def test_byoc_hard_stop_on_validation(self, validator):
        """validate_all_tool_schemas rule exists with hard_stop enforcement."""
        rules = validator.get_rule_names()
        assert "validate_all_tool_schemas" in rules


# --- Configuration tests ---


class TestSchemaValidatorConfig:
    """Test schema and rule loading."""

    def test_custom_tool_schema(self, tmp_path):
        """User-defined schema for custom tool."""
        schemas = {
            "schemas": {
                "custom_tool": {
                    "type": "object",
                    "required": ["input"],
                    "properties": {"input": {"type": "string", "maxLength": 100}},
                }
            }
        }
        path = tmp_path / "tool_schemas.yaml"
        with open(path, "w") as f:
            yaml.dump(schemas, f)
        validator = SchemaValidator(
            schema_path=str(path),
            rules_path=str(tmp_path / "camel_rules.yaml"),
        )
        # Write minimal rules
        with open(tmp_path / "camel_rules.yaml", "w") as f:
            yaml.dump({"rules": [{"name": "test", "enforcement": "soft_block", "severity": "high"}]}, f)
        result = validator.validate("custom_tool", {"input": "test"})
        assert result.valid is True

    def test_nested_properties_validated(self, tmp_path):
        """Nested object properties validated."""
        schemas = {
            "schemas": {
                "nested_tool": {
                    "type": "object",
                    "required": ["config"],
                    "properties": {
                        "config": {
                            "type": "object",
                            "required": ["value"],
                            "properties": {
                                "value": {"type": "integer", "minimum": 0}
                            },
                        }
                    },
                }
            }
        }
        path = tmp_path / "tool_schemas.yaml"
        with open(path, "w") as f:
            yaml.dump(schemas, f)
        with open(tmp_path / "camel_rules.yaml", "w") as f:
            yaml.dump({"rules": [{"name": "test", "enforcement": "soft_block", "severity": "high"}]}, f)
        validator = SchemaValidator(schema_path=str(path), rules_path=str(tmp_path / "camel_rules.yaml"))
        result = validator.validate("nested_tool", {"config": {"value": -1}})
        assert result.valid is False

    def test_format_uri_validation(self, validator):
        """URI format constraint enforced."""
        result = validator.validate("browser_navigate", {"url": "mailto:user@example.com"})
        assert result.valid is False

    def test_pattern_constraint_enforced(self, validator):
        """Regex pattern constraint enforced."""
        result = validator.validate("file_read", {"path": "/tmp/file name with spaces"})
        assert result.valid is False  # spaces not in pattern

    def test_empty_parameters_passes(self, validator):
        """Empty params → schema allows (no required fields matched)."""
        result = validator.validate("terminal", {})
        # 'command' is required, so this should fail
        assert result.valid is False

    def test_extra_properties_allowed(self, validator):
        """Additional properties not in schema → pass (draft7 default)."""
        result = validator.validate("terminal", {
            "command": "ls",
            "extra_field": "should be allowed",
        })
        assert result.valid is True

    def test_schema_load_from_yaml(self, validator):
        """YAML schemas loaded correctly at startup."""
        names = validator.get_schema_names()
        assert "terminal" in names
        assert "browser_navigate" in names
        assert "delegate_task" in names
        assert len(names) >= 3


# --- ValidationResult dataclass tests ---


class TestValidationResult:
    """Test ValidationResult defaults and methods."""

    def test_validation_error_details(self, validator):
        """403 response includes field-level error messages."""
        result = validator.validate("terminal", {"command": "ls; rm -rf /"})
        assert not result.valid
        assert len(result.errors) > 0
        # Error message should be a string
        assert isinstance(result.errors[0], str)
        assert len(result.errors[0]) > 0


# --- Hot-reload tests ---


class TestSchemaValidatorHotReload:
    """Test hot-reload functionality."""

    def test_reload_schemas(self, validator, tmp_path):
        """Reload schemas from a new file."""
        # Old schemas have 'terminal'
        assert "terminal" in validator.get_schema_names()

        # Create new file without terminal
        new_schemas = {"schemas": {"web_search": {
            "type": "object",
            "required": ["query"],
            "properties": {"query": {"type": "string"}},
        }}}
        new_path = tmp_path / "new_schemas.yaml"
        with open(new_path, "w") as f:
            yaml.dump(new_schemas, f)

        validator.reload_schemas(str(new_path))
        assert "terminal" not in validator.get_schema_names()
        assert "web_search" in validator.get_schema_names()

    def test_reload_rules(self, validator, tmp_path):
        """Reload rules from a new file."""
        old_rules = validator.get_rule_names()
        assert "validate_all_tool_schemas" in old_rules

        new_rules = [{"name": "new_rule", "enforcement": "soft_block", "severity": "high"}]
        new_path = tmp_path / "new_rules.yaml"
        with open(new_path, "w") as f:
            yaml.dump({"rules": new_rules}, f)

        validator.reload_rules(str(new_path))
        assert "validate_all_tool_schemas" not in validator.get_rule_names()
        assert "new_rule" in validator.get_rule_names()
