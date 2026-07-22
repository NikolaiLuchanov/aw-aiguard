"""
Block Response Generator

Centralized utility for generating standardized JSON responses
when the proxy intercepts and blocks a request.
"""

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
