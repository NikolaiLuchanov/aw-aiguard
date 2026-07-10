import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from gateway.core.proxy import LLMProxy
from gateway.core.guardrail import GuardianGuard
from gateway.core.scanner import PIIScanner
from gateway.core.hitl import HITLGate

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
SCAN_SEQUENCE = os.getenv("SCAN_SEQUENCE", "A")
SCAN_REDACTION_MODE = os.getenv("SCAN_REDACTION_MODE", "token")
SCAN_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "guardrail-config", "scan_rules.yaml")

# HITL Configuration
HITL_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "guardrail-config", "hitl_rules.yaml")
HITL_DEFAULT_TIMEOUT = int(os.getenv("HITL_DEFAULT_TIMEOUT", "300"))

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
    redaction_mode=SCAN_REDACTION_MODE
)

# Initialize the HITL Gate
hitl = HITLGate(
    rules_path=HITL_RULES_PATH,
    default_timeout=HITL_DEFAULT_TIMEOUT
)

# Initialize the Proxy Engine with all security components
proxy_engine = LLMProxy(
    target_url=TARGET_URL, 
    api_key=API_KEY, 
    guardian=guardian,
    scanner=scanner,
    hitl=hitl,
    scan_sequence=SCAN_SEQUENCE
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await proxy_engine.start()
    await hitl.start_cleanup()
    yield
    await hitl.stop_cleanup()
    await proxy_engine.stop()

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

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all(request: Request):
    return await proxy_engine.forward_request(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PROXY_PORT)
