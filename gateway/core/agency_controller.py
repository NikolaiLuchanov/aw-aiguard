"""
Agency Constraints — Delegation Depth Limits & Chain Integrity (Phase 4.5.2)

Controls sub-agent delegation depth, chain continuity, and tool-level approval
requirements to prevent recursive injection attacks across agent chains.

Rules loaded from guardrail-config/agency_rules.yaml.

Phase 4.5.2 deliverable — Layer L7 of the safety pipeline.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class AgencyCheckResult:
    """Result of an agency delegation check."""
    allowed: bool
    reason: str
    rule_name: Optional[str] = None


class AgencyController:
    """
    Enforces delegation depth limits and chain integrity for sub-agent chains.

    Pipeline position: Between BYOC (L3) and HITL (L4).

    Checks performed:
    1. Depth limit: hop_depth < max_delegation_depth
    2. Chain continuity: no gaps in source_chain hop_index values
    3. Tool-level approval: certain tools require explicit HITL approval
    4. MCP server vetting: allowlist/blocklist enforcement
    """

    def __init__(self, rules_path: str):
        """
        Initialize the agency controller.

        Args:
            rules_path: Path to agency_rules.yaml
        """
        self.config = self._load_rules(rules_path)
        self.max_depth = self.config.get("max_delegation_depth", 3)
        self.allowlist = self.config.get("allowlist", [])
        self.require_approval_for = self.config.get("require_approval_for", [])
        self.mcp_config = self.config.get("mcp_server_vetting", {})
        logger.info(
            "AgencyController initialized: max_depth=%d, allowlist=%d tools, require_approval=%d tools",
            self.max_depth,
            len(self.allowlist),
            len(self.require_approval_for),
        )

    # --- Loading ---

    def _load_rules(self, path: str) -> Dict[str, Any]:
        """Load agency rules from YAML file."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
                rules = data.get("rules", {})
                if rules is None:
                    return {}
                return rules
        except Exception as e:
            logger.error("Failed to load agency rules from %s: %s", path, e)
            return {}

    # --- Public API ---

    def check_delegation(
        self,
        provenance,
        target_tool: str,
        mcp_server: Optional[str] = None,
    ) -> AgencyCheckResult:
        """
        Check whether a delegation is allowed under agency constraints.

        Args:
            provenance: Provenance dataclass with source_chain, hop_depth, max_hop_depth.
            target_tool: Name of the target tool.
            mcp_server: Optional MCP server URL for vetting.

        Returns:
            AgencyCheckResult with allowed flag and reason.
        """
        # Check 1: Depth limit
        max_hops = self.max_depth
        if hasattr(provenance, "max_hop_depth") and provenance.max_hop_depth > 0:
            max_hops = provenance.max_hop_depth

        if not provenance.is_within_depth_limit():
            return AgencyCheckResult(
                allowed=False,
                reason=f"Delegation depth exceeded: hop={provenance.hop_depth} >= max={max_hops}",
                rule_name="max_delegation_depth",
            )

        # Check 2: Chain continuity
        if hasattr(provenance, "is_chain_broken") and provenance.is_chain_broken():
            return AgencyCheckResult(
                allowed=False,
                reason="Provenance chain has gaps — missing hops detected",
                rule_name="chain_continuity",
            )

        # Check 3: Tool-level approval requirement
        if target_tool in self.require_approval_for:
            return AgencyCheckResult(
                allowed=False,
                reason=f"Tool '{target_tool}' requires explicit approval",
                rule_name="approval_required",
            )

        # Check 4: MCP server vetting
        if mcp_server:
            if not self.validate_mcp_server(mcp_server):
                return AgencyCheckResult(
                    allowed=False,
                    reason=f"MCP server '{mcp_server}' not vetted",
                    rule_name="mcp_vetting",
                )

        return AgencyCheckResult(
            allowed=True,
            reason="Agency checks passed",
        )

    def increment_chain(self, provenance) -> Any:
        """Increment the provenance hop depth via provenance.increment_depth()."""
        if hasattr(provenance, "increment_depth"):
            return provenance.increment_depth()
        # Fallback: manual increment
        provenance.hop_depth += 1
        return provenance

    def validate_mcp_server(self, server_url: str) -> bool:
        """
        Check an MCP server URL against the allowlist/blocklist.

        In allowlist mode: URL must be in the allowlist.
        In blocklist mode: URL must NOT be in the blocklist.
        """
        mode = self.mcp_config.get("mode", "allowlist")
        if mode == "blocklist":
            blocklist = self.mcp_config.get("blocklist", [])
            return server_url not in blocklist
        else:  # default to allowlist
            allowlist = self.mcp_config.get("allowlist", [])
            # Empty allowlist means all MCP servers are allowed (permissive default)
            if not allowlist:
                logger.warning(
                    "MCP server vetting in allowlist mode but allowlist is empty — all servers allowed"
                )
                return True
            return server_url in allowlist

    def get_config_summary(self) -> Dict[str, Any]:
        """Return a summary of agency controller configuration."""
        return {
            "max_delegation_depth": self.max_depth,
            "allowlist": self.allowlist,
            "require_approval_for": self.require_approval_for,
            "mcp_vetting_mode": self.mcp_config.get("mode", "allowlist"),
        }

    # --- Hot-reload ---

    def reload_rules(self, rules_path: str) -> None:
        """Hot-reload agency rules from a new or updated file path."""
        old = self.config
        self.config = self._load_rules(rules_path)
        self.max_depth = self.config.get("max_delegation_depth", 3)
        self.allowlist = self.config.get("allowlist", [])
        self.require_approval_for = self.config.get("require_approval_for", [])
        self.mcp_config = self.config.get("mcp_server_vetting", {})
        logger.info(
            "AgencyController rules reloaded: max_depth=%d, allowlist=%d (was %d)",
            self.max_depth,
            len(self.allowlist),
            len(old.get("allowlist", [])),
        )
