import httpx
import logging
import json
from typing import AsyncGenerator, Optional
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

# Configure logging for the proxy
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aw-aiguard.proxy")

class LLMProxy:
    """
    A reliable, asynchronous proxy engine for forwarding LLM API requests.
    
    This class handles the low-level HTTP communication between the local 
    gateway and the cloud LLM provider, ensuring header integrity, 
    streaming support, and robust error handling.
    """

    def __init__(self, target_url: str, api_key: str):
        """
        Initialize the proxy with target configuration.

        Args:
            target_url (str): The base URL of the LLM provider (e.g., OpenAI/Anthropic).
            api_key (str): The secret API key used for authentication.
        """
        self.target_url = target_url.rstrip("/")
        self.api_key = api_key
        self.client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """
        Initialize the AsyncClient with production-grade settings.
        Using a single client instance enables TCP connection pooling (Keep-Alive).
        """
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(600.0, connect=10.0), # High timeout for slow LLM responses
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=True
        )
        logger.info(f"Proxy client initialized. Target: {self.target_url}")

    async def stop(self):
        """Close the underlying HTTP client to release resources."""
        if self.client:
            await self.client.aclose()
            logger.info("Proxy client closed.")

    def _prepare_headers(self, request_headers: httpx.Headers) -> httpx.Headers:
        """
        Transforms incoming headers for the outgoing request.
        
        1. Strips the original Authorization header to prevent key conflicts.
        2. Injects the proxy's configured API key.
        3. Preserves content-type and other metadata.
        """
        headers = dict(request_headers)
        # Remove any existing auth header to ensure our proxy key is used
        headers.pop("authorization", None)
        headers["authorization"] = f"Bearer {self.api_key}"
        return httpx.Headers(headers)

    async def forward_request(self, request: Request) -> Response:
        """
        The primary entry point for request forwarding.
        Determines whether to return a standard response or a streaming response.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            Response: The response from the target provider (standard or streaming).
        """
        if not self.client:
            raise RuntimeError("Proxy client not started. Call start() first.")

        path = request.url.path
        url = f"{self.target_url}{path}"
        
        # Prepare request data
        method = request.method
        content = await request.body()
        headers = self._prepare_headers(request.headers)

        # Check for streaming in the request body
        is_streaming = False
        if content:
            try:
                body = json.loads(content)
                if isinstance(body, dict):
                    is_streaming = body.get("stream", False)
            except json.JSONDecodeError:
                pass

        try:
            if is_streaming:
                return await self._handle_streaming(method, url, headers, content)
            else:
                return await self._handle_standard(method, url, headers, content)
        except httpx.RequestError as exc:
            logger.error(f"Network error forwarding {method} {path}: {exc}")
            return Response(content="Bad Gateway: Could not reach LLM provider", status_code=502)
        except Exception as exc:
            logger.exception(f"Unexpected error forwarding {method} {path}: {exc}")
            return Response(content="Internal Server Error", status_code=500)

    async def _handle_standard(self, method: str, url: str, headers: httpx.Headers, content: bytes) -> Response:
        """Forwards a standard non-streaming request and returns the full response."""
        response = await self.client.request(
            method, url, headers=headers, content=content
        )
        
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers)
        )

    async def _handle_streaming(self, method: str, url: str, headers: httpx.Headers, content: bytes) -> StreamingResponse:
        """
        Forwards a streaming request. 
        Returns a FastAPI StreamingResponse that yields chunks in real-time.
        """
        # Use a request context to get the initial response and its headers
        req = self.client.build_request(method, url, headers=headers, content=content)
        
        async def stream_generator() -> AsyncGenerator[bytes, None]:
            async with self.client.stream(req) as response:
                async for chunk in response.aiter_bytes():
                    yield chunk

        # Note: StreamingResponse in FastAPI starts sending the response before 
        # the generator runs. We'll initialize it here. 
        # To forward exact headers, we'd need to perform an initial request, 
        # but that breaks the stream. Most LLM providers use 200 OK for streams.
        return StreamingResponse(
            stream_generator(),
            media_type="text/event-stream"
        )
