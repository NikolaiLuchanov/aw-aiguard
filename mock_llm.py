from fastapi import FastAPI, Request
import uvicorn
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-llm")

app = FastAPI()

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    prompt = ""
    if "messages" in body:
        prompt = body["messages"][-1].get("content", "")
    
    logger.info(f"Cloud LLM received prompt: {prompt}")
    
    return {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 123456789,
        "model": "gpt-3.5-turbo",
        "choices": [{"message": {"role": "assistant", "content": "I received your prompt!"}, "finish_reason": "stop"}]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
