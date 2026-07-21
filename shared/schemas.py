"""
Shared Pydantic schemas for aw-aiguard.

These models are used by both the gateway and central-service.
Keeping them in one place prevents silent field divergence.
"""

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """An audit event pushed to the backend (matches central-service/audit_db.py)."""
    api_key: str
    event_type: Literal["allow", "block", "warn", "pause"]
    component: str  # 'guardian', 'pii_scanner', 'hitl_gate', 'byoc_engine', 'proxy'
    reason: Optional[str] = None
    prompt_hash: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None
    blocked_by: Optional[str] = None
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ProvenanceEvent(BaseModel):
    """Provenance record for data lineage tracking."""
    source_id: str
    source_type: str
    trust_level: float
    ingested_at: Optional[datetime] = None  # Defaults to NOW() in DB


class SettingsChange(BaseModel):
    """Record of a settings change."""
    developer_id: str
    setting_key: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    sync_source: str = "local"  # 'local', 'backend', 'auto'


# =================================================================== #
# Phase 3.1 — Dashboard schemas
# =================================================================== #


class HitlDecisionRequest(BaseModel):
    """Request body for HITL approve/deny from the dashboard."""
    approver_id: str = "system"


class BYOCRuleCreate(BaseModel):
    """Request body for creating/updating a BYOC rule."""
    name: str = Field(..., min_length=1, max_length=128, description="Unique rule name")
    description: str = ""
    pattern: str = Field(..., min_length=0, max_length=1024, description="Regex pattern (empty for rate-limit-only rules)")
    enforcement: Literal["hard_stop", "soft_block"] = "hard_stop"
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    rate_limit: Optional[int] = Field(None, ge=1, description="Max calls in window (soft_block only)")
    window_seconds: Optional[int] = Field(None, ge=1, description="Rate limit window in seconds (soft_block only)")


class BYOCRuleResponse(BaseModel):
    """Response model for a BYOC rule."""
    id: int
    name: str
    description: str
    pattern: str
    enforcement: str
    severity: str
    rate_limit: Optional[int] = None
    window_seconds: Optional[int] = None
    is_active: bool
    version: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class SettingsOverrideChange(BaseModel):
    """Request body for applying a settings override."""
    developer_id: str
    setting_key: str
    setting_value: str


class GatewayHeartbeat(BaseModel):
    """Request body for gateway heartbeat."""
    gateway_id: str
    api_key_hash: str
    version: Optional[str] = None
    settings_hash: Optional[str] = None
    ip_address: Optional[str] = None


class AuditLogQuery(BaseModel):
    """Query parameters for the audit log browser."""
    limit: int = 50
    offset: int = 0
    event_type: Optional[str] = None
    component: Optional[str] = None
    api_key: Optional[str] = None
