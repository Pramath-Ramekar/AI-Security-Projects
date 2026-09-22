import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
CHROMA_PERSIST_DIR = str(BASE_DIR / "chroma_db")
DATA_DIR = str(BASE_DIR / "data")
LOG_DIR = str(BASE_DIR / "logs")
