"""RAG over the company secure-coding policy.

Documents in POLICY_DIR (.md / .txt / .pdf) are split by heading, then indexed with either
  * Ollama embeddings + in-memory vector store  (when SECURESCAN_OLLAMA_EMBED_MODEL is set), or
  * BM25 keyword retrieval                      (default; no model needed, works in CI).
"""
from __future__ import annotations

import logging
import re
import threading
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

from ..config import get_settings
from ..models import Finding

log = logging.getLogger("securescan.rag")
POLICY_ID_RE = re.compile(r"SCP-\d+(?:\.\d+)?")

# Extra search terms per CWE so keyword retrieval finds the right policy section.
CWE_HINTS = {
    "CWE-798": "secrets credentials hard-coded environment variables", "CWE-89": "SQL injection parameterized",
    "CWE-78": "OS command injection subprocess shell", "CWE-77": "command injection shell",
    "CWE-94": "eval dynamic code execution", "CWE-95": "eval dynamic code execution",
    "CWE-79": "XSS output encoding escaping", "CWE-502": "insecure deserialization pickle yaml",
    "CWE-327": "cryptography MD5 SHA-1", "CWE-328": "weak hash MD5 SHA-1", "CWE-330": "random tokens secrets",
    "CWE-295": "TLS certificate verification", "CWE-22": "path traversal file paths",
    "CWE-918": "SSRF outbound requests", "CWE-489": "debug mode", "CWE-215": "debug mode",
    "CWE-1321": "prototype pollution", "CWE-347": "JWT verify algorithm", "CWE-611": "XML",
}


def _load_documents(policy_dir: Path) -> list[Document]:
    docs: list[Document] = []
    header_split = MarkdownHeaderTextSplitter([("#", "h1"), ("##", "h2"), ("###", "h3")])
    chunker = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=150)
    for path in sorted(policy_dir.glob("**/*")):
        if path.suffix.lower() in {".md", ".txt"}:
            text = path.read_text(encoding="utf-8", errors="replace")
        elif path.suffix.lower() == ".pdf":
            try:
                from pypdf import PdfReader
                text = "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)
            except Exception as exc:  # pypdf optional
                log.warning("Skipping PDF policy %s: %s", path.name, exc)
                continue
        else:
            continue
        for section in header_split.split_text(text):
            heading = section.metadata.get("h2") or section.metadata.get("h1") or path.stem
            for chunk in chunker.split_text(section.page_content):
                docs.append(Document(page_content=chunk, metadata={"source": path.name, "section": heading}))
    return docs


_TOKEN_RE = re.compile(r"[a-z0-9]+")


class _BM25Retriever:
    """Minimal keyword retriever (Okapi BM25) - no model needed, deterministic, works offline in CI."""

    def __init__(self, docs: list[Document], k: int = 3):
        from rank_bm25 import BM25Okapi

        self.docs, self.k = docs, k
        self._bm25 = BM25Okapi([self._tokens(d.page_content + " " + d.metadata.get("section", "")) for d in docs])

    @staticmethod
    def _tokens(text: str) -> list[str]:
        return _TOKEN_RE.findall(text.lower())

    def invoke(self, query: str) -> list[Document]:
        scores = self._bm25.get_scores(self._tokens(query))
        ranked = sorted(range(len(self.docs)), key=lambda i: scores[i], reverse=True)
        return [self.docs[i] for i in ranked[: self.k] if scores[i] > 0]


class PolicyStore:
    def __init__(self, policy_dir: Path | None = None):
        s = get_settings()
        self.policy_dir = policy_dir or s.policy_dir
        self.docs = _load_documents(self.policy_dir) if self.policy_dir.is_dir() else []
        self.mode = "empty"
        self._retriever = None
        if not self.docs:
            return
        if s.ollama_embed_model:
            try:
                from langchain_core.vectorstores import InMemoryVectorStore
                from langchain_ollama import OllamaEmbeddings

                emb = OllamaEmbeddings(model=s.ollama_embed_model, base_url=s.ollama_base_url)
                store = InMemoryVectorStore.from_documents(self.docs, emb)
                self._retriever = store.as_retriever(search_kwargs={"k": 3})
                self.mode = f"embeddings:{s.ollama_embed_model}"
                return
            except Exception as exc:
                log.warning("Embedding index failed (%s); falling back to BM25", exc)
        self._retriever = _BM25Retriever(self.docs, k=3)
        self.mode = "bm25"

    @staticmethod
    def query_for(f: Finding) -> str:
        hints = " ".join(CWE_HINTS.get(c, "") for c in f.cwe)
        extra = "dependencies vulnerable upgrade pinned fixed version" if f.category == "SCA" else ""
        if f.category == "SECRET":
            extra = "secrets credentials committed rotate environment variables"
        return f"{f.title} {f.rule_id.replace('.', ' ')} {hints} {extra} {f.description[:300]}"

    def retrieve(self, f: Finding) -> list[Document]:
        if self._retriever is None:
            return []
        try:
            return self._retriever.invoke(self.query_for(f))
        except Exception as exc:
            log.warning("Policy retrieval failed: %s", exc)
            return []

    @staticmethod
    def references(docs: list[Document]) -> list[str]:
        refs = []
        for d in docs:
            ids = POLICY_ID_RE.findall(d.page_content)
            refs.extend(ids or [d.metadata.get("section", "")])
        return list(dict.fromkeys(r for r in refs if r))[:6]


_store: PolicyStore | None = None
_lock = threading.Lock()


def get_policy_store() -> PolicyStore:
    global _store
    with _lock:
        if _store is None:
            _store = PolicyStore()
        return _store


def reload_policy_store() -> PolicyStore:
    global _store
    with _lock:
        _store = PolicyStore()
        return _store
