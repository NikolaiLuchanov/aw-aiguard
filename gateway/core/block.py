

"""
Block Response Generator

Centralized utility for generating standardized JSON responses
when the proxy intercepts and blocks a request.
"""
from __future__ import annotations

import json
from typing import Optional

from fastapi import Response


# Predefined block reason codes
class BlockReason:
    POTENTIAL_SAFETY_VIOLATION = "POTENTIAL_SAFETY_VIOLATION"
    CRITICAL_SECRET_DETECTED = "CRITICAL_SECRET_DETECTED"
    HITL_DENIED = "HITL_DENIED"
    HITL_EXPIRED = "HITL_EXPIRED"
    FUNCTION_CALL_HALLUCINATION = "FUNCTION_CALL_HALLUCINATION"
    STORED_INJECTION_DETECTED = "STORED_INJECTION_DETECTED"
    OUTPUT_SCHEMA_VIOLATION = "OUTPUT_SCHEMA_VIOLATION"
    OUTPUT_HTML_ESCAPING_REQUIRED = "OUTPUT_HTML_ESCAPING_REQUIRED"
    THINKING_MODE_WARNING = "THINKING_MODE_WARNING"  # Phase 4.4 — advisory only, used for audit logging
    # Phase 4.5: CaMeL + Agency Constraints
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    AGENCY_DEPTH_EXCEEDED = "AGENCY_DEPTH_EXCEEDED"
    AGENCY_CHAIN_BROKEN = "AGENCY_CHAIN_BROKEN"
    AGENCY_APPROVAL_REQUIRED = "AGENCY_APPROVAL_REQUIRED"


def generate_block_response(
    reason: str,
    message: str,
    blocked_by: str,
    request_id: Optional[str] = None,
) -> Response:
    """
    Generate a standardized 403 block response.

    Args:
        reason: One of the BlockReason codes.
        message: Human-readable explanation of the block.
        blocked_by: Component that triggered the block (e.g. 'guardian').
        request_id: Optional identifier for audit / HITL tracking.

    Returns:
        FastAPI Response with status_code=403 and standardized JSON body.
    """
    body = {
        "error": {
            "code": "BLOCKED",
            "message": message,
            "reason": reason,
            "blocked_by": blocked_by,
        }
    }
    if request_id is not None:
        body["error"]["request_id"] = request_id

    return Response(
        content=json.dumps(body),
        status_code=403,
        media_type="application/json",
    )
