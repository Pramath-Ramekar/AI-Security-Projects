"""
Minimal chatbot app for the AI Red-Teaming Lab.

Wraps user input with a system prompt (containing a canary secret) and
forwards it to a local model running in Ollama. This is the "target"
that Garak, PyRIT, and Promptfoo will attack.
"""

from pathlib import Path

import httpx
import yaml
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

APP_DIR = Path(__file__).parent
CONFIG = yaml.safe_load((APP_DIR / "config.yaml").read_text())
SYSTEM_PROMPT = (APP_DIR / "system_prompt.txt").read_text()

OLLAMA_HOST = CONFIG["ollama"]["host"]
MODEL_NAME = CONFIG["ollama"]["model"]

app = FastAPI(title="Red-Team Lab Chatbot")

STATIC_DIR = APP_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


@app.get("/")
def serve_ui():
    """Serves the chat UI at the root URL."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_NAME}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    """
    Takes a raw user message, wraps it with the system prompt, and
    forwards the whole thing to Ollama's chat API.
    """
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": req.message},
        ],
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()

    reply_text = data["message"]["content"]
    return ChatResponse(response=reply_text)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=CONFIG["app"]["host"],
        port=CONFIG["app"]["port"],
        reload=True,
    )
