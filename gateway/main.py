import os
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from gateway.core.proxy import LLMProxy
from gateway.core.guardrail import GuardianGuard
from gateway.core.scanner import PIIScanner
from gateway.core.hitl import HITLGate
from gateway.core.byoc import BYOCEngine
from gateway.core.audit import AuditLogger

logger = logging.getLogger(__name__)

# Load environment variables from the gateway folder
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Configuration from .env
TARGET_URL = os.getenv("TARGET_API_BASE_URL")
API_KEY = os.getenv("TARGET_API_KEY")
PROXY_PORT = int(os.getenv("PROXY_PORT", 9020))

# Guardian Configuration
GUARDIAN_URL = os.getenv("GUARDIAN_URL", "http://localhost:8000/guardian")
GUARDIAN_MODEL = os.getenv("GUARDIAN_MODEL", "granite4.1-guardian")
GUARDIAN_FAIL_STRATEGY = os.getenv("GUARDIAN_FAIL_STRATEGY", "block")

# PII Scanner Configuration
SCAN_SEQUENCE = os.getenv("SCAN_SEQUENCE", "B")
SCAN_REDACTION_MODE = os.getenv("SCAN_REDACTION_MODE", "token")
SCAN_ACTION_MODE = os.getenv("SCAN_ACTION_MODE", "block")  # "block" or "warn"
SCAN_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "guardrail-config", "scan_rules.yaml")

# HITL Configuration
HITL_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "guardrail-config", "hitl_rules.yaml")
HITL_DEFAULT_TIMEOUT = int(os.getenv("HITL_DEFAULT_TIMEOUT", "300"))
HITL_NOTIFICATION_MODE = os.getenv("HITL_NOTIFICATION_MODE", "silent")

# BYOC Configuration
BYOC_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "guardrail-config", "byoc_rules.yaml")

# BYOC Cloud Sync (Phase 3.2)
BYOC_CLOUD_URL = os.getenv("BYOC_CLOUD_URL", "")  # e.g. "http://localhost:8000"
BYOC_SYNC_INTERVAL = int(os.getenv("BYOC_SYNC_INTERVAL", "120"))  # seconds

# Audit Logger Configuration — same Central Service as Guardian
AUDIT_BUFFER_PATH = os.getenv("AUDIT_BUFFER_PATH", "~/.config/aw-aiguard/audit_buffer.jsonl")

if not TARGET_URL or not API_KEY:
    print("Error: TARGET_API_BASE_URL and TARGET_API_KEY must be set in gateway/.env")
    exit(1)

# Initialize the Guardian Guard
guardian = GuardianGuard(
    url=GUARDIAN_URL,
    model=GUARDIAN_MODEL,
    fail_strategy=GUARDIAN_FAIL_STRATEGY
)

# Initialize the PII Scanner
scanner = PIIScanner(
    rules_path=SCAN_RULES_PATH,
    redaction_mode=SCAN_REDACTION_MODE,
    block_mode=SCAN_ACTION_MODE  # "block" = 403 on block rules; "warn" = log only
)

# Initialize the HITL Gate
hitl = HITLGate(
    rules_path=HITL_RULES_PATH,
    default_timeout=HITL_DEFAULT_TIMEOUT,
    notification_mode=HITL_NOTIFICATION_MODE
)

# Initialize the BYOC Engine
byoc = BYOCEngine(
    rules_path=BYOC_RULES_PATH,
    cloud_url=BYOC_CLOUD_URL or None,
    api_key=API_KEY or "default",
)

# Initialize the Audit Logger
audit_logger = AuditLogger(
    base_url=GUARDIAN_URL,
    buffer_path=AUDIT_BUFFER_PATH,
)

# Initialize the Proxy Engine with all security components
proxy_engine = LLMProxy(
    target_url=TARGET_URL, 
    api_key=API_KEY, 
    guardian=guardian,
    scanner=scanner,
    hitl=hitl,
    byoc=byoc,
    audit_logger=audit_logger,
    scan_sequence=SCAN_SEQUENCE
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await proxy_engine.start()
    await hitl.start_cleanup()
    await audit_logger.start()

    # Phase 3.2: Initial cloud BYOC rule sync
    if byoc.cloud_url:
        try:
            summary = await byoc.sync_all_cloud_state()
            logger.info(f"BYOC cloud sync complete: {summary}")
        except Exception:
            logger.warning("BYOC initial cloud sync failed — running with local rules only.")

    # Phase 3.2: Periodic cloud BYOC rule sync
    byoc_sync_task = None
    if byoc.cloud_url and BYOC_SYNC_INTERVAL > 0:
        byoc_sync_task = asyncio.create_task(_byoc_sync_loop())
        logger.info(f"BYOC sync loop started (interval={BYOC_SYNC_INTERVAL}s).")

    yield

    # Shutdown
    if byoc_sync_task:
        byoc_sync_task.cancel()
        try:
            await byoc_sync_task
        except asyncio.CancelledError:
            pass
    await audit_logger.stop()
    await hitl.stop_cleanup()
    await proxy_engine.stop()


async def _byoc_sync_loop():
    """Periodically re-sync BYOC rules from cloud. Runs every BYOC_SYNC_INTERVAL seconds."""
    while True:
        try:
            await asyncio.sleep(BYOC_SYNC_INTERVAL)
            summary = await byoc.sync_all_cloud_state()
            logger.info(f"BYOC periodic sync complete: {summary}")
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("BYOC periodic sync failed — will retry next cycle.")
            await asyncio.sleep(30)  # Shorter retry on failure

app = FastAPI(
    title="aw-aiguard Local Gateway Proxy",
    description="A transparent security proxy for LLM traffic interception.",
    lifespan=lifespan
)

# HITL Endpoints (Must be defined before catch-all to avoid interception)
@app.post("/hitl/approve")
async def approve_hitl(request: Request):
    body = await request.json()
    request_id = body.get("request_id")
    if hitl.approve(request_id):
        return JSONResponse(content={"status": "approved", "request_id": request_id})
    return JSONResponse(content={"error": "Request not found"}, status_code=404)

@app.post("/hitl/deny")
async def deny_hitl(request: Request):
    body = await request.json()
    request_id = body.get("request_id")
    if hitl.deny(request_id):
        return JSONResponse(content={"status": "denied", "request_id": request_id})
    return JSONResponse(content={"error": "Request not found"}, status_code=404)

@app.get("/hitl/status/{request_id}")
async def hitl_status(request_id: str):
    return JSONResponse(content=hitl.get_status(request_id))

@app.get("/hitl/pending")
async def hitl_pending():
    return JSONResponse(content=hitl.get_pending())

@app.post("/hitl/resume/{request_id}")
async def hitl_resume(request_id: str):
    """
    Called by the client after HITL approval to retrieve the LLM response.
    The proxy re-sends the stored request context to the cloud API and returns the result.
    """
    request_context, error = hitl.get_request_context(request_id)
    if error:
        return JSONResponse(content=error, status_code=403)

    try:
        response = await proxy_engine.forward_stored_request(request_context)
        return response
    except Exception as exc:
        logger.error(f"HITL resume error for {request_id}: {exc}")
        return JSONResponse(content={"error": "Failed to forward request after HITL approval"}, status_code=502)

@app.get("/byoc/rules")
async def byoc_rules():
    """List all active BYOC stop-limit rules."""
    return JSONResponse(content=byoc.get_rules_summary())

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all(request: Request):
    return await proxy_engine.forward_request(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PROXY_PORT)
