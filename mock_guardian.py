from fastapi import FastAPI, Request
import uvicorn

app = FastAPI()
current_score = "yes"

@app.post("/guardian")
async def guardian(request: Request):
    global current_score
    body = await request.json()
    prompt = body.get("prompt", "")
    if "leak" in prompt.lower() or "hack" in prompt.lower():
        return {"score": "no", "reason": "Malicious intent detected"}
    return {"score": current_score}

@app.post("/set_score")
async def set_score(score: str):
    global current_score
    current_score = score.lower()
    return {"status": "success", "current_score": current_score}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)