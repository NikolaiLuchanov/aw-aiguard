"""
Shared Pydantic schemas for aw-aiguard.

These models are used by both the gateway and central-service.
Keeping them in one place prevents silent field divergence.
"""

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel


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
