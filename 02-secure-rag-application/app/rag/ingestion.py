"""
Step 6 — Document Ingestion Pipeline
Loads all .txt files from data/, chunks, embeds, and stores in ChromaDB.

Run:
    python -m app.rag.ingestion
    python -m app.rag.ingestion --reset
"""
import argparse
import hashlib
import sys
from pathlib import Path

import chromadb

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.config import CHROMA_PERSIST_DIR, DATA_DIR
from langchain_text_splitters import RecursiveCharacterTextSplitter

# Department → metadata/access config
DEPARTMENT_CONFIG = {
    "hr": {
        "classification": "internal",
        "access_employee": True,
        "access_engineer": True,
        "access_finance": True,
        "access_admin": True,
    },
    "engineering": {
        "classification": "confidential",
        "access_employee": False,
        "access_engineer": True,
        "access_finance": False,
        "access_admin": True,
    },
    "finance": {
        "classification": "confidential",
        "access_employee": False,
        "access_engineer": False,
        "access_finance": True,
        "access_admin": True,
    },
    "security": {
        "classification": "restricted",
        "access_employee": False,
        "access_engineer": False,
        "access_finance": False,
        "access_admin": True,
    },
    "secrets": {
        "classification": "restricted",
        "access_employee": False,
        "access_engineer": False,
        "access_finance": False,
        "access_admin": True,
    },
    "malicious": {
        "classification": "untrusted",
        "access_employee": True,
        "access_engineer": True,
        "access_finance": True,
        "access_admin": True,
    },
}


def _chunk_id(filepath: str, idx: int) -> str:
    h = hashlib.md5(f"{filepath}::{idx}".encode()).hexdigest()[:8]
    return f"{Path(filepath).stem}_{idx}_{h}"


def _get_embedding_function():
    try:
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
        return DefaultEmbeddingFunction()
    except Exception:
        pass
    try:
        from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2
        return ONNXMiniLM_L6_V2()
    except Exception:
        pass
    return None


def load_documents():
    docs = []
    data_path = Path(DATA_DIR)
    for txt in sorted(data_path.rglob("*.txt")):
        rel = txt.relative_to(data_path)
        if len(rel.parts) < 2:
            continue
        dept = rel.parts[0]
        if dept not in DEPARTMENT_CONFIG:
            print(f"  skip (unknown dept): {rel}")
            continue
        text = txt.read_text(encoding="utf-8", errors="replace")
        docs.append({"text": text, "filepath": str(txt), "filename": txt.name, "department": dept, **DEPARTMENT_CONFIG[dept]})
        print(f"  loaded: {rel}")
    return docs


def ingest(reset: bool = False):
    print("=" * 50)
    print("STEP 6 — Document Ingestion Pipeline")
    print("=" * 50)

    print(f"\n[1/5] Loading documents from {DATA_DIR} ...")
    raw = load_documents()
    print(f"  → {len(raw)} documents loaded")

    print("\n[2/5] Splitting into chunks ...")
    splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=120, separators=["\n\n", "\n", ". ", " ", ""])
    chunks = []
    for doc in raw:
        for i, text in enumerate(splitter.split_text(doc["text"])):
            text = text.strip()
            if not text:
                continue
            chunks.append({
                "id": _chunk_id(doc["filepath"], i),
                "text": text,
                "metadata": {
                    "department": doc["department"],
                    "filename": doc["filename"],
                    "filepath": doc["filepath"],
                    "classification": doc["classification"],
                    "access_employee": doc["access_employee"],
                    "access_engineer": doc["access_engineer"],
                    "access_finance": doc["access_finance"],
                    "access_admin": doc["access_admin"],
                    "chunk_index": i,
                },
            })
    print(f"  → {len(chunks)} chunks created")

    print("\n[3/5] Connecting to ChromaDB ...")
    ef = _get_embedding_function()
    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)

    if reset:
        try:
            client.delete_collection("aegis_documents")
            print("  → Deleted existing collection")
        except Exception:
            pass

    kwargs = {"name": "aegis_documents", "metadata": {"hnsw:space": "cosine"}}
    if ef is not None:
        kwargs["embedding_function"] = ef
    collection = client.get_or_create_collection(**kwargs)
    print(f"  → Collection ready (embedding_fn={'custom' if ef else 'default'})")

    print("\n[4/5] Filtering already-indexed chunks ...")
    existing_ids = set(collection.get(include=[])["ids"])
    new_chunks = [c for c in chunks if c["id"] not in existing_ids]
    print(f"  → {len(existing_ids)} existing, {len(new_chunks)} new")

    if new_chunks:
        print("\n[5/5] Adding new chunks to ChromaDB ...")
        batch_size = 50
        added = 0
        for i in range(0, len(new_chunks), batch_size):
            batch = new_chunks[i : i + batch_size]
            collection.add(
                documents=[c["text"] for c in batch],
                metadatas=[c["metadata"] for c in batch],
                ids=[c["id"] for c in batch],
            )
            added += len(batch)
            print(f"  → {added}/{len(new_chunks)} added", end="\r")
        print()
    else:
        print("\n[5/5] Nothing new to add — skipping")

    total = collection.count()
    print(f"\n{'=' * 50}")
    print(f"Ingestion complete. Collection size: {total} chunks")
    print(f"ChromaDB path: {CHROMA_PERSIST_DIR}")
    print("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest documents into ChromaDB")
    parser.add_argument("--reset", action="store_true", help="Delete and recreate the collection")
    args = parser.parse_args()
    ingest(reset=args.reset)
