"""Tests for gateway/core/output_control.py — OutputController (Phase 4.3)."""

import json
import pytest
import tempfile

from gateway.core.output_control import (
    OutputController,
    OutputControlResult,
    ValidationResult,
)


@pytest.mark.unit
class TestOutputController:

    @pytest.fixture
    def output_controller(self):
        """Create a minimal OutputController with inline schemas/rules."""
        schema_content = json.dumps({
            "schemas": {
                "generate_test_plan": {
                    "type": "object",
                    "required": ["test_cases"],
                    "properties": {
                        "test_cases": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["name", "steps"],
                                "properties": {
                                    "name": {"type": "string", "maxLength": 200},
                                    "steps": {"type": "array", "items": {"type": "string", "maxLength": 1024}},
                                },
                            },
                        },
                    },
                },
                "summarize_code": {
                    "type": "object",
                    "required": ["summary", "file_list"],
                    "properties": {
                        "summary": {"type": "string", "maxLength": 2000},
                        "file_list": {"type": "array", "items": {"type": "string", "maxLength": 512}},
                    },
                },
            },
        })
        byoc_content = json.dumps({
            "rules": [
                {
                    "name": "never_shell_interpolate_llm_output",
                    "enforcement": "hard_stop",
                    "severity": "critical",
                    "description": "Never interpolate LLM output directly into shell commands",
                },
                {
                    "name": "never_sql_unquoted",
                    "enforcement": "hard_stop",
                    "severity": "critical",
                    "description": "Never use LLM output in unparameterized SQL",
                },
                {
                    "name": "require_schema_validation",
                    "enforcement": "soft_block",
                    "severity": "high",
                    "description": "All structured outputs must pass schema validation",
                },
            ],
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as sf:
            sf.write(schema_content)
            schema_path = sf.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as bf:
            bf.write(byoc_content)
            byoc_path = bf.name
        return OutputController(schema_path=schema_path, byoc_rules_path=byoc_path)

    # --- Schema validation: valid outputs ---

    def test_valid_schema_passes(self, output_controller):
        """Response matching schema → passes."""
        response = json.dumps({
            "test_cases": [
                {"name": "test login", "steps": ["enter username", "enter password"]},
            ],
        })
        result = output_controller.validate_response(response, tool_name="generate_test_plan")
        assert result.schema_validated is True
        assert result.schema_errors == []
        assert result.blocked is False

    def test_missing_required_field_blocks(self, output_controller):
        """Missing 'test_cases' → block with schema_violation."""
        response = json.dumps({"other_field": "value"})
        result = output_controller.validate_response(response, tool_name="generate_test_plan")
        assert result.schema_validated is False
        assert any("test_cases" in err for err in result.schema_errors)
        assert result.blocked is False  # soft_block for require_schema_validation

    def test_wrong_type_blocks(self, output_controller):
        """test_cases as string instead of array → block."""
        response = json.dumps({"test_cases": "not an array"})
        result = output_controller.validate_response(response, tool_name="generate_test_plan")
        assert result.schema_validated is False
        assert any("array" in err.lower() for err in result.schema_errors)

    # --- Schema: nested objects ---

    def test_nested_object_validation(self, output_controller):
        """Nested schema structures validated recursively."""
        response = json.dumps({
            "test_cases": [
                {"name": "test 1", "steps": ["step 1"]},
                {"steps": ["step 2"]},  # missing name
            ],
        })
        result = output_controller.validate_response(response, tool_name="generate_test_plan")
        assert result.schema_validated is False
        assert any("name" in err for err in result.schema_errors)

    def test_maxLength_violation_detected(self, output_controller):
        """Output exceeding maxLength → error."""
        long_summary = "x" * 2001
        response = json.dumps({"summary": long_summary, "file_list": []})
        result = output_controller.validate_response(response, tool_name="summarize_code")
        assert result.schema_validated is False
        assert any("maxLength" in err for err in result.schema_errors)

    # --- HTML escaping ---

    def test_html_in_output_escaped(self, output_controller):
        """<script> in LLM output → &lt;script&gt;."""
        response = "Here is some text <script>alert('xss')</script> end."
        result = output_controller.validate_response(response)
        assert result.html_escaped is True
        assert "&lt;script&gt;" in result.content
        assert "<script>" not in result.content

    def test_css_in_output_escaped(self, output_controller):
        """CSS styles in output → HTML-escaped."""
        response = '<div style="color: red">Hello</div>'
        result = output_controller.validate_response(response)
        assert result.html_escaped is True
        assert "&lt;div" in result.content
        assert "<div" not in result.content

    def test_plain_text_unchanged_by_escape(self, output_controller):
        """Normal text passes HTML escaping intact."""
        response = "Hello world, this is a normal sentence."
        result = output_controller.validate_response(response)
        assert result.html_escaped is False
        assert result.content == response

    # --- Shell/DB parameter quoting ---

    def test_shell_param_quoted(self, output_controller):
        """LLM output with dangerous patterns → quoted."""
        response = "echo hello; rm -rf /tmp/test"
        result = output_controller.validate_response(response)
        assert result.shell_quoted is True
        assert result.content.startswith("'")
        assert result.content.endswith("'")

    def test_sql_param_quoted(self, output_controller):
        """LLM output with SQL injection pattern → quoted."""
        response = "SELECT * FROM users; DROP TABLE users"
        result = output_controller.validate_response(response)
        assert result.shell_quoted is True
        assert result.content.startswith("'")
        assert result.content.endswith("'")

    # --- BYOC rules ---

    def test_byoc_hard_stop_blocks(self, output_controller):
        """'never_shell_interpolate' violation with <script> → 403."""
        response = "<script>steal_data()</script>"
        result = output_controller.validate_response(response)
        assert result.blocked is True
        assert "hard_stop" in result.block_reason
        assert "never_shell_interpolate_llm_output" in result.byoc_violations

    def test_byoc_soft_block_warns(self, output_controller):
        """'require_schema_validation' → warning, not block."""
        response = json.dumps({"test_cases": "wrong type"})
        result = output_controller.validate_response(response, tool_name="generate_test_plan")
        assert result.blocked is False  # soft_block, not hard
        assert "require_schema_validation" in result.byoc_violations
        assert result.schema_validated is False

    # --- Configuration and edge cases ---

    def test_custom_schema_addition(self, output_controller):
        """User-defined schema from YAML applied correctly."""
        # Reload schemas with a custom schema
        schema_content = json.dumps({
            "schemas": {
                "custom_tool": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string", "maxLength": 100},
                    },
                },
            },
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as sf:
            sf.write(schema_content)
            custom_path = sf.name
        output_controller.reload_schemas(custom_path)
        # Valid query
        response = json.dumps({"query": "search for bugs"})
        result = output_controller.validate_response(response, tool_name="custom_tool")
        assert result.schema_validated is True
        # Missing required field
        response_missing = json.dumps({"other": "field"})
        result2 = output_controller.validate_response(response_missing, tool_name="custom_tool")
        assert result2.schema_validated is False

    def test_no_schema_for_untyped_output(self, output_controller):
        """Plain text outputs bypass schema validation."""
        response = "Just plain text output from the LLM."
        result = output_controller.validate_response(response, tool_name="unknown_tool")
        assert result.schema_validated is True  # no schema to validate against
        assert result.content == response

    def test_output_control_empty_response(self, output_controller):
        """Empty/None response handled gracefully."""
        result = output_controller.validate_response("")
        assert result.content == ""
        assert result.schema_validated is True
        assert result.html_escaped is False
        assert result.shell_quoted is False

    # --- Summary methods ---

    def test_schemas_summary(self, output_controller):
        """get_schemas_summary returns loaded schema names."""
        summary = output_controller.get_schemas_summary()
        names = [s["name"] for s in summary]
        assert "generate_test_plan" in names
        assert "summarize_code" in names

    def test_byoc_rules_summary(self, output_controller):
        """get_byoc_rules_summary returns loaded BYOC rules."""
        summary = output_controller.get_byoc_rules_summary()
        names = [r["name"] for r in summary]
        assert "never_shell_interpolate_llm_output" in names
        assert "require_schema_validation" in names

    # --- Edge cases ---

    def test_uri_format_validation(self, output_controller):
        """URI format constraint enforced."""
        schema_content = json.dumps({
            "schemas": {
                "file_analysis": {
                    "type": "object",
                    "required": ["file_path"],
                    "properties": {
                        "file_path": {"type": "string", "format": "uri"},
                    },
                },
            },
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as sf:
            sf.write(schema_content)
            path = sf.name
        output_controller.reload_schemas(path)
        response = json.dumps({"file_path": "not_a_valid_uri"})
        result = output_controller.validate_response(response, tool_name="file_analysis")
        assert result.schema_validated is False
        assert any("URI" in err.upper() for err in result.schema_errors)

    def test_integer_type_rejects_boolean(self, output_controller):
        """Boolean values are not accepted as integers."""
        schema_content = json.dumps({
            "schemas": {
                "count_check": {
                    "type": "object",
                    "properties": {
                        "count": {"type": "integer"},
                    },
                },
            },
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as sf:
            sf.write(schema_content)
            path = sf.name
        output_controller.reload_schemas(path)
        response = json.dumps({"count": True})
        result = output_controller.validate_response(response, tool_name="count_check")
        assert result.schema_validated is False

    def test_integer_range_validation(self, output_controller):
        """Out of range integer blocked."""
        schema_content = json.dumps({
            "schemas": {
                "range_check": {
                    "type": "object",
                    "properties": {
                        "timeout": {"type": "integer", "minimum": 1, "maximum": 3600},
                    },
                },
            },
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as sf:
            sf.write(schema_content)
            path = sf.name
        output_controller.reload_schemas(path)
        response = json.dumps({"timeout": 5000})
        result = output_controller.validate_response(response, tool_name="range_check")
        assert result.schema_validated is False
        assert any("maximum" in err.lower() for err in result.schema_errors)

    def test_array_items_type_validation(self, output_controller):
        """Array items type validated."""
        schema_content = json.dumps({
            "schemas": {
                "string_array": {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
            },
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as sf:
            sf.write(schema_content)
            path = sf.name
        output_controller.reload_schemas(path)
        response = json.dumps({"items": [1, 2, 3]})  # integers instead of strings
        result = output_controller.validate_response(response, tool_name="string_array")
        assert result.schema_validated is False

    def test_non_json_response_fails_schema(self, output_controller):
        """Non-JSON response fails schema validation for object schemas."""
        response = "This is not JSON at all!"
        result = output_controller.validate_response(response, tool_name="generate_test_plan")
        assert result.schema_validated is False
        assert any("not valid json" in err.lower() for err in result.schema_errors)

    def test_validation_result_defaults(self):
        """ValidationResult defaults work correctly."""
        vr = ValidationResult()
        assert vr.valid is True
        assert vr.errors == []

    def test_validation_result_add_error(self):
        """Adding an error sets valid=False."""
        vr = ValidationResult()
        vr.add_error("test error")
        assert vr.valid is False
        assert "test error" in vr.errors
        assert len(vr.errors) == 1

    def test_output_control_result_defaults(self):
        """OutputControlResult defaults work correctly."""
        result = OutputControlResult(
            content="test",
            schema_validated=True,
            html_escaped=False,
            shell_quoted=False,
        )
        assert result.blocked is False
        assert result.block_reason == ""
        assert result.schema_errors == []
        assert result.byoc_violations == []
