import os
import asyncio
import hashlib
import logging
import yaml
from typing import Any, Dict
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
from gateway.core.thinking_mode import ThinkingModeVerifier, ThinkingModeConfig
from gateway.core.schema_validator import SchemaValidator
from gateway.core.agency_controller import AgencyController
from gateway.core.function_call_detector import FunctionCallDetector   # Phase 4.1
from gateway.core.sanitizer import IngestionSanitizer                  # Phase 4.2
from gateway.core.output_control import OutputController               # Phase 4.3

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

# HITL Cloud Sync (Phase 3.3)
# Defaults to same parent as GUARDIAN_URL
if GUARDIAN_URL:
    HITL_CLOUD_URL = GUARDIAN_URL.rsplit("/", 1)[0] if "/" in GUARDIAN_URL else GUARDIAN_URL
else:
    HITL_CLOUD_URL = os.getenv("HITL_CLOUD_URL", "")

# Audit Logger Configuration — same Central Service as Guardian
AUDIT_BUFFER_PATH = os.getenv("AUDIT_BUFFER_PATH", "~/.config/aw-aiguard/audit_buffer.jsonl")

# Phase 3.4: Gateway Heartbeat Configuration
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))  # seconds

# Phase 3.4: Settings Poll Configuration
SETTINGS_POLL_INTERVAL = int(os.getenv("SETTINGS_POLL_INTERVAL", "60"))  # seconds

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
    notification_mode=HITL_NOTIFICATION_MODE,
    cloud_url=HITL_CLOUD_URL or None,  # Phase 3.3
    api_key=API_KEY or "default",      # Phase 3.3
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

# Phase 4.4: Initialize the Thinking-Mode Verifier
THINKING_MODE_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "thinking_mode_rules.yaml"
)
thinking_config = ThinkingModeConfig.from_yaml(THINKING_MODE_RULES_PATH)
thinking_verifier = ThinkingModeVerifier(guardian=guardian, config=thinking_config)

# Phase 4.5: Initialize SchemaValidator and AgencyController
TOOL_SCHEMAS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "tool_schemas.yaml"
)
CAMEL_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "camel_rules.yaml"
)
AGENCY_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "agency_rules.yaml"
)

# Phase 4.1: Function-Call Hallucination Detection
FUNCTION_CALL_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "function_call_rules.yaml"
)

# Phase 4.2: Ingestion Sanitizer
SANITIZE_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "ingestion_sanitize_rules.yaml"
)

# Phase 4.3: LLM05 Output Control
OUTPUT_SCHEMAS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "output_schemas.yaml"
)
OUTPUT_CONTROL_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "byoc_output_control.yaml"
)
schema_validator = SchemaValidator(schema_path=TOOL_SCHEMAS_PATH, rules_path=CAMEL_RULES_PATH)
agency_controller = AgencyController(rules_path=AGENCY_RULES_PATH)

# Initialize the Proxy Engine with all security components
proxy_engine = LLMProxy(
    target_url=TARGET_URL, 
    api_key=API_KEY, 
    guardian=guardian,
    scanner=scanner,
    hitl=hitl,
    byoc=byoc,
    thinking_verifier=thinking_verifier,  # Phase 4.4
    agency_controller=agency_controller,   # Phase 4.5.2
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

    # Phase 3.3: Recover pending HITL requests from cloud on startup
    if hitl.cloud_url:
        try:
            await hitl._recover_pending_from_cloud()
        except Exception:
            logger.warning("HITL cloud recovery failed — starting with local state only")

    # Phase 3.4: Gateway heartbeat loop
    heartbeat_task = None
    if HITL_CLOUD_URL:
        heartbeat_task = asyncio.create_task(_heartbeat_loop(HITL_CLOUD_URL))
        logger.info("Heartbeat loop started (interval=%ds).", HEARTBEAT_INTERVAL)

    # Phase 3.4: Settings poll loop
    settings_poll_task = None
    if HITL_CLOUD_URL and SETTINGS_POLL_INTERVAL > 0:
        settings_poll_task = asyncio.create_task(_settings_poll_loop(HITL_CLOUD_URL))
        logger.info("Settings poll loop started (interval=%ds).", SETTINGS_POLL_INTERVAL)

    yield

    # Shutdown
    if byoc_sync_task:
        byoc_sync_task.cancel()
        try:
            await byoc_sync_task
        except asyncio.CancelledError:
            pass
    if heartbeat_task:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
    if settings_poll_task:
        settings_poll_task.cancel()
        try:
            await settings_poll_task
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


# =================================================================== #
# Phase 3.4 — Heartbeat & Settings Sync
# =================================================================== #


def _compute_settings_hash() -> str:
    """Compute a SHA-256 hash of the current local settings state.
    Used to detect when remote settings differ from local."""
    state: Dict[str, Any] = {
        "scan_sequence": SCAN_SEQUENCE,
        "scan_redaction_mode": SCAN_REDACTION_MODE,
        "scan_action_mode": SCAN_ACTION_MODE,
        "hitl_timeout": HITL_DEFAULT_TIMEOUT,
        "hitl_notification_mode": HITL_NOTIFICATION_MODE,
        "guardian_fail_strategy": GUARDIAN_FAIL_STRATEGY,
    }
    return hashlib.sha256(yaml.dump(state, sort_keys=True).encode()).hexdigest()[:16]


def _compute_settings_hash_from_dict(settings: Dict) -> str:
    """Hash a settings dict for diff comparison with local state."""
    state: Dict[str, Any] = {
        "scan_sequence": settings.get("scan_sequence", SCAN_SEQUENCE),
        "scan_redaction_mode": settings.get("scan_redaction_mode", SCAN_REDACTION_MODE),
        "scan_action_mode": settings.get("scan_action_mode", SCAN_ACTION_MODE),
        "hitl_timeout": settings.get("hitl_timeout", HITL_DEFAULT_TIMEOUT),
        "hitl_notification_mode": settings.get("hitl_notification_mode", HITL_NOTIFICATION_MODE),
        "guardian_fail_strategy": settings.get("guardian_fail_strategy", GUARDIAN_FAIL_STRATEGY),
    }
    return hashlib.sha256(yaml.dump(state, sort_keys=True).encode()).hexdigest()[:16]


def _apply_remote_settings(remote_settings: Dict) -> None:
    """
    Apply remote settings to local components.
    This updates scanner, hitl, and guardrail configurations in-place.
    """
    global SCAN_SEQUENCE, SCAN_REDACTION_MODE, SCAN_ACTION_MODE
    global HITL_DEFAULT_TIMEOUT, HITL_NOTIFICATION_MODE
    global GUARDIAN_FAIL_STRATEGY

    applied: Dict[str, tuple] = {}

    # Scanner settings
    if "scan_sequence" in remote_settings:
        new_seq = remote_settings["scan_sequence"]
        if new_seq in ("A", "B", "C"):
            old = SCAN_SEQUENCE
            SCAN_SEQUENCE = new_seq
            applied["scan_sequence"] = (old, new_seq)
            # Note: LLMProxy.scan_sequence is set at init time.
            # For hot-reload we update the proxy's attribute directly.
            if proxy_engine:
                proxy_engine.scan_sequence = new_seq

    if "scan_redaction_mode" in remote_settings:
        new_mode = remote_settings["scan_redaction_mode"]
        if new_mode in ("token", "mask"):
            old = SCAN_REDACTION_MODE
            SCAN_REDACTION_MODE = new_mode
            scanner.redaction_mode = new_mode
            applied["scan_redaction_mode"] = (old, new_mode)

    if "scan_action_mode" in remote_settings:
        new_mode = remote_settings["scan_action_mode"]
        if new_mode in ("block", "warn"):
            old = SCAN_ACTION_MODE
            SCAN_ACTION_MODE = new_mode
            scanner.block_mode = new_mode
            applied["scan_action_mode"] = (old, new_mode)

    # HITL settings
    if "hitl_timeout" in remote_settings:
        new_timeout = int(remote_settings["hitl_timeout"])
        old = HITL_DEFAULT_TIMEOUT
        HITL_DEFAULT_TIMEOUT = new_timeout
        hitl.default_timeout = new_timeout
        applied["hitl_timeout"] = (old, new_timeout)

    if "hitl_notification_mode" in remote_settings:
        new_mode = remote_settings["hitl_notification_mode"]
        old = HITL_NOTIFICATION_MODE
        HITL_NOTIFICATION_MODE = new_mode
        hitl.notification_mode = new_mode
        applied["hitl_notification_mode"] = (old, new_mode)

    # Guardian settings
    if "guardian_fail_strategy" in remote_settings:
        new_strategy = remote_settings["guardian_fail_strategy"]
        if new_strategy in ("block", "allow", "warn", "fallback"):
            old = GUARDIAN_FAIL_STRATEGY
            GUARDIAN_FAIL_STRATEGY = new_strategy
            guardian.fail_strategy = new_strategy
            applied["guardian_fail_strategy"] = (old, new_strategy)

    if applied:
        logger.info("Settings applied: %s", applied)


async def _heartbeat_loop(backend_url: str):
    """Send heartbeats to the central service every HEARTBEAT_INTERVAL seconds."""
    import httpx
    while True:
        try:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            settings_hash = _compute_settings_hash()
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    f"{backend_url}/dashboard/heartbeat",
                    json={
                        "gateway_id": API_KEY,
                        "api_key_hash": hashlib.sha256(API_KEY.encode()).hexdigest(),
                        "version": "0.3.0",
                        "settings_hash": settings_hash,
                    },
                )
        except asyncio.CancelledError:
            break
        except Exception:
            logger.debug("Heartbeat failed — will retry next cycle.")


async def _settings_poll_loop(backend_url: str):
    """
    Poll backend for settings changes every SETTINGS_POLL_INTERVAL seconds.
    On change: applies new settings and updates local state.
    """
    import httpx
    while True:
        try:
            await asyncio.sleep(SETTINGS_POLL_INTERVAL)
            if not backend_url:
                continue

            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{backend_url}/dashboard/settings",
                    params={"developer_id": API_KEY},
                )
                if resp.status_code != 200:
                    continue

                remote_settings = resp.json()
                local_settings_hash = _compute_settings_hash()
                remote_settings_hash = _compute_settings_hash_from_dict(remote_settings)

                if local_settings_hash != remote_settings_hash:
                    logger.info("Settings diff detected — applying update.")
                    _apply_remote_settings(remote_settings)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("Settings poll failed — will retry next cycle.")
            await asyncio.sleep(10)  # Shorter retry on failure

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
