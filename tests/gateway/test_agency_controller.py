"""Tests for gateway/core/agency_controller.py — AgencyController (Phase 4.5.2)."""

import pytest
import yaml
from pathlib import Path

from gateway.core.agency_controller import AgencyController, AgencyCheckResult
from gateway.core.provenance import Provenance


@pytest.fixture
def agency_rules_path(tmp_path):
    """Write agency rules YAML and return path."""
    rules = {
        "rules": {
            "max_delegation_depth": 3,
            "allowlist": ["terminal", "file_read", "web_search"],
            "require_approval_for": ["file_write", "shell_execute", "email_send", "commit", "deploy"],
            "mcp_server_vetting": {
                "mode": "allowlist",
                "allowlist": [],
                "blocklist": [],
            },
        },
    }
    path = tmp_path / "agency_rules.yaml"
    with open(path, "w") as f:
        yaml.dump(rules, f)
    return str(path)


@pytest.fixture
def controller(agency_rules_path):
    return AgencyController(rules_path=agency_rules_path)


# --- Depth limit tests ---


class TestAgencyControllerDepth:
    """Test delegation depth enforcement."""

    def test_delegation_within_depth_allowed(self, controller):
        """hop_depth < max → passes."""
        prov = Provenance(source_id="agent-1", source_type="llm_output", trust_level=0.9)
        result = controller.check_delegation(prov, "web_search")
        assert result.allowed is True

    def test_delegation_at_depth_limit_blocked(self, controller):
        """hop_depth == max → blocked."""
        prov = Provenance(
            source_id="agent-1", source_type="llm_output", trust_level=0.9,
            hop_depth=3, max_hop_depth=3,
        )
        result = controller.check_delegation(prov, "web_search")
        assert result.allowed is False
        assert "depth" in result.reason.lower()

    def test_delegation_exceeding_depth_blocked(self, controller):
        """hop_depth > max → blocked."""
        prov = Provenance(
            source_id="agent-1", source_type="llm_output", trust_level=0.9,
            hop_depth=5, max_hop_depth=3,
        )
        result = controller.check_delegation(prov, "web_search")
        assert result.allowed is False
        assert "depth" in result.reason.lower()

    def test_increment_depth(self, controller):
        """hop_depth increments correctly."""
        prov = Provenance(source_id="agent-1", source_type="llm_output", trust_level=0.9)
        assert prov.hop_depth == 0
        controller.increment_chain(prov)
        assert prov.hop_depth == 1
        controller.increment_chain(prov)
        assert prov.hop_depth == 2

    def test_source_chain_carry_through(self, controller):
        """Provenance chain carried forward."""
        prov = Provenance(source_id="agent-1", source_type="llm_output", trust_level=0.9)
        controller.increment_chain(prov)
        assert len(prov.source_chain) == 1
        assert prov.source_chain[0]["source_id"] == "agent-1"
        assert prov.source_chain[0]["hop_index"] == 0


# --- Chain integrity tests ---


class TestChainIntegrity:
    """Test chain broken detection."""

    def test_chain_broken_detected(self, controller):
        """Missing hop in source_chain → flagged."""
        prov = Provenance(
            source_id="agent-1", source_type="llm_output", trust_level=0.9,
            source_chain=[
                {"source_id": "agent-1", "hop_index": 0},
                {"source_id": "agent-3", "hop_index": 2},  # hop 1 is missing
            ],
        )
        result = controller.check_delegation(prov, "web_search")
        assert result.allowed is False
        assert "chain" in result.reason.lower()

    def test_valid_chain_not_broken(self, controller):
        """Sequential hops → not broken."""
        prov = Provenance(
            source_id="agent-1", source_type="llm_output", trust_level=0.9,
            source_chain=[
                {"source_id": "agent-1", "hop_index": 0},
                {"source_id": "agent-2", "hop_index": 1},
                {"source_id": "agent-3", "hop_index": 2},
            ],
        )
        result = controller.check_delegation(prov, "web_search")
        assert result.allowed is True

    def test_single_hop_not_broken(self, controller):
        """Single hop in chain → not broken."""
        prov = Provenance(
            source_id="agent-1", source_type="llm_output", trust_level=0.9,
            source_chain=[{"source_id": "agent-1", "hop_index": 0}],
        )
        result = controller.check_delegation(prov, "web_search")
        assert result.allowed is True


# --- Tool approval tests ---


class TestToolApproval:
    """Test approval-required tools."""

    def test_approval_required_action(self, controller):
        """Write/execute/deploy without HITL → blocked."""
        prov = Provenance(source_id="agent-1", source_type="llm_output", trust_level=0.9)
        result = controller.check_delegation(prov, "email_send")
        assert result.allowed is False
        assert "approval" in result.reason.lower()

    def test_non_approval_tool_passed(self, controller):
        """Non-approval tool → passes."""
        prov = Provenance(source_id="agent-1", source_type="llm_output", trust_level=0.9)
        result = controller.check_delegation(prov, "terminal")
        assert result.allowed is True


# --- MCP server vetting tests ---


class TestMCPVetting:
    """Test MCP server allowlist/blocklist."""

    def test_mcp_server_vetting_allowlist(self, controller):
        """Empty allowlist → all servers allowed (permissive default)."""
        result = controller.check_delegation(
            Provenance(source_id="a", source_type="x", trust_level=0.9),
            "terminal",
            mcp_server="https://mcp.example.com",
        )
        assert result.allowed is True

    def test_mcp_server_vetting_blocklist(self, controller):
        """MCP in blocklist → blocked."""
        controller.mcp_config = {"mode": "blocklist", "blocklist": ["https://evil.com"], "allowlist": []}
        result = controller.check_delegation(
            Provenance(source_id="a", source_type="x", trust_level=0.9),
            "terminal",
            mcp_server="https://evil.com",
        )
        assert result.allowed is False


# --- Configuration tests ---


class TestAgencyControllerConfig:
    """Test configuration loading."""

    def test_custom_max_depth_from_yaml(self, tmp_path):
        """Configurable max_delegation_depth from YAML."""
        rules = {
            "rules": {
                "max_delegation_depth": 5,
                "allowlist": ["terminal"],
                "require_approval_for": ["commit"],
                "mcp_server_vetting": {"mode": "allowlist", "allowlist": [], "blocklist": []},
            },
        }
        path = tmp_path / "agency_rules.yaml"
        with open(path, "w") as f:
            yaml.dump(rules, f)
        controller = AgencyController(rules_path=str(path))
        assert controller.max_depth == 5

    def test_default_max_depth(self, tmp_path):
        """Default max depth is 3."""
        rules = {"rules": {"max_delegation_depth": 3}}
        path = tmp_path / "agency_rules.yaml"
        with open(path, "w") as f:
            yaml.dump(rules, f)
        controller = AgencyController(rules_path=str(path))
        assert controller.max_depth == 3

    def test_audit_entry_on_violation(self, tmp_path):
        """Audit log with component and violation reason."""
        rules = {
            "rules": {
                "max_delegation_depth": 1,
                "allowlist": [],
                "require_approval_for": [],
                "mcp_server_vetting": {"mode": "allowlist", "allowlist": [], "blocklist": []},
            },
        }
        path = tmp_path / "agency_rules.yaml"
        with open(path, "w") as f:
            yaml.dump(rules, f)
        controller = AgencyController(rules_path=str(path))
        prov = Provenance(
            source_id="a", source_type="x", trust_level=0.9,
            hop_depth=1, max_hop_depth=1,
        )
        result = controller.check_delegation(prov, "terminal")
        assert result.allowed is False
        assert "depth" in result.reason.lower()

    def test_config_summary(self, controller):
        """Get config summary returns expected keys."""
        summary = controller.get_config_summary()
        assert "max_delegation_depth" in summary
        assert summary["max_delegation_depth"] == 3
        assert "allowlist" in summary
        assert "mcp_vetting_mode" in summary

    def test_reload_rules(self, controller, tmp_path):
        """Reload rules from a new file."""
        new_rules = {
            "rules": {
                "max_delegation_depth": 5,
                "allowlist": ["custom_tool"],
                "require_approval_for": ["deploy"],
                "mcp_server_vetting": {"mode": "blocklist", "blocklist": ["https://evil.com"], "allowlist": []},
            },
        }
        path = tmp_path / "new_rules.yaml"
        with open(path, "w") as f:
            yaml.dump(new_rules, f)
        controller.reload_rules(str(path))
        assert controller.max_depth == 5
        assert "custom_tool" in controller.allowlist
        assert "deploy" in controller.require_approval_for
