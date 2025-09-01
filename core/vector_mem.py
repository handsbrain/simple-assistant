# core/vector_mem.py
from __future__ import annotations
import os, json, hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import chromadb
from chromadb.config import Settings
from openai import OpenAI

EMBED_MODEL = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
MEM_DIR = Path(os.getenv("MEMORY_DIR", "state/vector_store"))
MEM_DIR.mkdir(parents=True, exist_ok=True)

# One persistent client & collection
_client = chromadb.PersistentClient(
    # If you previously passed Settings(), you can still do so; PersistentClient
    # now accepts keyword args directly.
    path=str(MEM_DIR),
)
try:
    _collection = _client.get_or_create_collection(
        name="memories",
        metadata={"hnsw:space": "cosine"},
        get_or_create=True,
    )
except Exception:
    # Fallback for older chroma signatures
    _collection = _client.get_or_create_collection("memories")

_openai = OpenAI()

def _embed(texts: List[str]) -> List[List[float]]:
    # Small batching is fine for our scale
    if not texts:
        return []
    resp = _openai.embeddings.create(model=EMBED_MODEL, input=texts)
    return [d.embedding for d in resp.data]

def _stable_id(text: str, meta: Dict[str, Any]) -> str:
    # deterministic id to avoid dupes
    j = json.dumps({"t": text, "m": meta}, sort_keys=True)
    return hashlib.sha1(j.encode("utf-8")).hexdigest()

def add_memory(
    text: str,
    kind: str = "rule",           # "rule" | "example" | "note"
    tags: Optional[List[str]] = None,
    author: Optional[str] = None,
    source: Optional[str] = None
) -> str:
    """
    Store a lesson/rule/example as a vector with metadata.
    Returns the chroma id.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("empty memory text")
    
    # Validate input
    if len(text) > 10000:  # Reasonable limit for memory content
        raise ValueError("memory text too long (max 10000 characters)")
    
    if kind not in ["rule", "example", "note"]:
        raise ValueError(f"invalid kind: {kind}")
    
    if tags and len(tags) > 20:
        raise ValueError("too many tags (max 20)")
    
    # Sanitize tags
    if tags:
        tags = [tag.strip()[:50] for tag in tags if tag.strip()]  # Limit tag length
    
    # IMPORTANT: Chroma 0.5.x allows only primitive metadata; lists are not allowed.
    tag_str = ",".join(tags) if tags else ""
    meta = {
        "kind": str(kind or "rule"),
        "tags": tag_str,
        "author": (author or "").lower()[:100],  # Limit author length
        "source": (source or "")[:100],  # Limit source length
    }
    
    try:
        vid = _stable_id(text, meta)
        vec = _embed([text])[0]
        _collection.add(
            ids=[vid],
            embeddings=[vec],
            documents=[text],
            metadatas=[meta],
        )
        return vid
    except Exception as e:
        raise RuntimeError(f"Failed to add memory: {type(e).__name__}: {e}")

def search_memory(
    query: str,
    k: int = 8,
    where: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Semantic search with optional metadata filtering.
    `where` must use only primitive-compatible filters (e.g., {"kind": "rule"},
    {"tags": {"$contains": "reply"}} since we store tags as a comma-joined string).
    """
    qv = _embed([query])[0]
    res = _collection.query(
        query_embeddings=[qv],
        n_results=max(1, int(k)),
        where=where or None,
        include=["documents", "metadatas", "distances", "ids"],
    )
    out: List[Dict[str, Any]] = []
    if not res or not res.get("ids"):
        return out
    for i in range(len(res["ids"][0])):
        out.append({
            "id": res["ids"][0][i],
            "text": res["documents"][0][i],
            "score": float(res["distances"][0][i]) if "distances" in res else None,
            "meta": res["metadatas"][0][i],
        })
    return out

def all_stats() -> Dict[str, Any]:
    return {
        "collection": _collection.name,
        "count": _collection.count(),
        "path": str(MEM_DIR),
        "embed_model": EMBED_MODEL,
    }
