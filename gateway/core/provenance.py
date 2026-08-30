"""
aw-aiguard: Provenance tagging for data lineage tracking.

Every request is tagged with provenance metadata at ingestion time:
source_id, source_type, trust_level, ingested_at.

Phase 2.5 deliverable — Layer 0 of the safety pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

SUPPORTED_SOURCE_TYPES = frozenset({
    "repository",
    "chat",
    "external_api",
    "llm_output",
    "file_system",
    "unknown",
})


@dataclass
class Provenance:
    """Provenance record for a single request (mutable to support sanitization tracking)."""

    source_id: str
    source_type: str
    trust_level: float
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sanitization_applied: bool = False
    dangerous_patterns_detected: list = field(default_factory=list)
    # Phase 4.5: Agency constraints — sub-agent chain tracking
    source_chain: list = field(default_factory=list)
    hop_depth: int = 0
    max_hop_depth: int = 3

    def to_dict(self) -> Dict:
        """Serialize to dict for JSON/audit/log storage."""
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "trust_level": self.trust_level,
            "ingested_at": self.ingested_at.isoformat(),
            "source_chain": self.source_chain,
            "hop_depth": self.hop_depth,
            "max_hop_depth": self.max_hop_depth,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Provenance":
        """Deserialize from a dict (e.g. from JSON body or header parsing)."""
        return cls(
            source_id=str(data.get("source_id", "unknown")),
            source_type=str(data.get("source_type", "unknown")),
            trust_level=float(data.get("trust_level", 0.0)),
            ingested_at=datetime.fromisoformat(data["ingested_at"])
                if "ingested_at" in data and data["ingested_at"]
                else datetime.now(timezone.utc),
            source_chain=data.get("source_chain", []),
            hop_depth=int(data.get("hop_depth", 0)),
            max_hop_depth=int(data.get("max_hop_depth", 3)),
        )

    @classmethod
    def default(cls) -> "Provenance":
        """Maximum suspicion: unknown source, zero trust."""
        return cls(
            source_id="unknown",
            source_type="unknown",
            trust_level=0.0,
        )

    @classmethod
    def from_headers(cls, headers: Dict) -> "Provenance":
        """
        Extract provenance from HTTP request headers.

        Expected headers:
            X-Provenance-Source-ID: git-repo-1
            X-Provenance-Source-Type: repository
            X-Provenance-Trust-Level: 0.95

        If any header is missing, falls back to Provenance.default()
        for the missing fields.
        """
        source_id = headers.get("x-provenance-source-id", "").strip()
        source_type = headers.get("x-provenance-source-type", "").strip()
        trust_level_str = headers.get("x-provenance-trust-level", "").strip()

        # If ALL headers are missing, return default
        if not source_id and not source_type and not trust_level_str:
            return cls.default()

        # Clamp trust_level to [0.0, 1.0]
        try:
            trust_level = float(trust_level_str) if trust_level_str else 0.0
            trust_level = max(0.0, min(1.0, trust_level))
        except (ValueError, TypeError):
            trust_level = 0.0

        return cls(
            source_id=source_id or "unknown",
            source_type=source_type or "unknown",
            trust_level=trust_level,
        )

    @property
    def is_low_trust(self) -> bool:
        """Return True if trust_level is below the low-trust threshold (< 0.5)."""
        return self.trust_level < 0.5

    @property
    def is_known(self) -> bool:
        """Return True if source_type is a recognized type (not 'unknown')."""
        return self.source_type in SUPPORTED_SOURCE_TYPES and self.source_type != "unknown"

    def record_sanitization(self, patterns: list[str], applied: bool) -> None:
        """Record sanitization results in provenance metadata."""
        self.sanitization_applied = applied
        self.dangerous_patterns_detected = list(patterns)

    @property
    def has_dangerous_patterns(self) -> bool:
        """Return True if dangerous patterns were detected during sanitization."""
        return len(self.dangerous_patterns_detected) > 0

    # --- Phase 4.5: Agency constraints ---

    def increment_depth(self) -> "Provenance":
        """Increment hop_depth and add current provenance to source_chain. Returns self for chaining."""
        self.hop_depth += 1
        self.source_chain.append({
            "source_id": self.source_id,
            "source_type": self.source_type,
            "trust_level": self.trust_level,
            "hop_index": self.hop_depth - 1,
        })
        return self

    def is_within_depth_limit(self) -> bool:
        """Return True if hop_depth is below max_hop_depth."""
        return self.hop_depth < self.max_hop_depth

    def is_chain_broken(self) -> bool:
        """Detect if provenance chain has gaps — e.g., missing hops or trust_level resets."""
        if len(self.source_chain) < 2:
            return False
        # Check for continuity: hop_index should be sequential
        indices = [hop["hop_index"] for hop in self.source_chain]
        return indices != list(range(len(indices)))
