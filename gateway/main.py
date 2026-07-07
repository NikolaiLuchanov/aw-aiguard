import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from dotenv import load_dotenv
from gateway.core.proxy import LLMProxy

# Load environment variables from the gateway folder
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Configuration from .env
TARGET_URL = os.getenv("TARGET_API_BASE_URL")
API_KEY = os.getenv("TARGET_API_KEY")
PROXY_PORT = int(os.getenv("PROXY_PORT", 9020))

if not TARGET_URL or not API_KEY:
    print("Error: TARGET_API_BASE_URL and TARGET_API_KEY must be set in gateway/.env")
    exit(1)

# Initialize the Proxy Engine
proxy_engine = LLMProxy(target_url=TARGET_URL, api_key=API_KEY)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles the startup and shutdown of the proxy client.
    Ensures connection pooling is initialized once.
    """
    await proxy_engine.start()
    yield
    await proxy_engine.stop()

app = FastAPI(
    title="aw-aiguard Local Gateway Proxy",
    description="A transparent security proxy for LLM traffic interception.",
    lifespan=lifespan
)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all(request: Request):
    """
    Wildcard route that forwards all incoming HTTP requests 
    to the target LLM provider.
    """
    return await proxy_engine.forward_request(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PROXY_PORT)
