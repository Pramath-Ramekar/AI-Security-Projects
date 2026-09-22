"""
Step 7 — Retriever (Vulnerable + Secure variants)

VulnerableRetriever: no RBAC — fetches from all documents
SecureRetriever:     RBAC-filtered — ChromaDB where-clause by role
"""
from typing import Any, Dict, List, Optional
from pathlib import Path
import sys

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

import chromadb
from app.config import CHROMA_PERSIST_DIR


def _get_ef():
    try:
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
        return DefaultEmbeddingFunction()
    except Exception:
        pass
    try:
        from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2
        return ONNXMiniLM_L6_V2()
    except Exception:
        return None


class RetrievedChunk:
    def __init__(self, text: str, metadata: Dict[str, Any], distance: float):
        self.text = text
        self.metadata = metadata
        self.distance = distance
        self.score = max(0.0, 1.0 - distance)

    def __repr__(self):
        return f"Chunk(dept={self.metadata.get('department')}, score={self.score:.3f}, file={self.metadata.get('filename')})"


class _BaseRetriever:
    def __init__(self):
        self._collection = None

    @property
    def collection(self):
        if self._collection is None:
            ef = _get_ef()
            client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
            kwargs = {"name": "aegis_documents"}
            if ef is not None:
                kwargs["embedding_function"] = ef
            self._collection = client.get_collection(**kwargs)
        return self._collection

    def _query(self, query: str, n_results: int, where: Optional[Dict] = None) -> List[RetrievedChunk]:
        total = self.collection.count()
        if total == 0:
            return []
        n = min(n_results, total)

        kwargs: Dict[str, Any] = {
            "query_texts": [query],
            "n_results": n,
            "include": ["documents", "metadatas", "distances"],
        }
        if where:
            kwargs["where"] = where

        try:
            res = self.collection.query(**kwargs)
        except Exception as e:
            print(f"  [retriever] query error: {e}")
            return []

        return [
            RetrievedChunk(text=doc, metadata=meta, distance=dist)
            for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0])
        ]


class VulnerableRetriever(_BaseRetriever):
    """No access control — retrieves from ALL documents regardless of user role."""

    def retrieve_for_user(self, query: str, username: str, n_results: int = 5) -> List[RetrievedChunk]:
        return self._query(query, n_results)


class SecureRetriever(_BaseRetriever):
    """RBAC-enforced — filters ChromaDB by role-specific access field."""

    ROLE_ACCESS_FIELD = {
        "employee": "access_employee",
        "engineer": "access_engineer",
        "finance":  "access_finance",
        "admin":    "access_admin",
    }

    def retrieve_for_user(
        self,
        query: str,
        username: str,
        n_results: int = 5,
        role: Optional[str] = None,
    ) -> List[RetrievedChunk]:
        if role is None:
            from app.security.access_control import get_user_role
            role = get_user_role(username)

        field = self.ROLE_ACCESS_FIELD.get(role or "")
        if field is None:
            return []

        where = {field: {"$eq": True}}
        try:
            return self._query(query, n_results, where=where)
        except Exception:
            # Fallback: fetch more, filter in Python
            all_chunks = self._query(query, n_results * 4)
            return [c for c in all_chunks if c.metadata.get(field) is True][:n_results]
