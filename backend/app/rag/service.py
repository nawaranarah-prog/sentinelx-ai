"""Knowledge base: UPLOAD → EXTRACT → CHUNK → EMBED → STORE → RETRIEVE."""

import io
import re
from pathlib import Path

import numpy as np
from sqlalchemy.orm import Session

from app.models import KnowledgeChunk, KnowledgeDocument
from app.rag.embedding import cosine_matrix, embed, tokenize

SEED_DIR = Path(__file__).parent / "seed_docs"
ALLOWED_DOC_EXTENSIONS = {".txt": "text/plain", ".md": "text/markdown", ".markdown": "text/markdown",
                          ".pdf": "application/pdf"}
CHUNK_CHARS = 900
CHUNK_OVERLAP = 150


class DocumentRejected(Exception):
    pass


def extract_text(filename: str, content: bytes) -> tuple[str, str]:
    ext = Path(filename.lower()).suffix
    if ext not in ALLOWED_DOC_EXTENSIONS:
        raise DocumentRejected("Unsupported document type. Upload .txt, .md or .pdf files.")
    if not content.strip():
        raise DocumentRejected("The document is empty.")
    if ext == ".pdf":
        if not content.startswith(b"%PDF"):
            raise DocumentRejected("The file does not look like a valid PDF.")
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
        try:
            reader = PdfReader(io.BytesIO(content))
            if reader.is_encrypted:
                raise DocumentRejected("Encrypted PDFs are not supported.")
            text = "\n\n".join((page.extract_text() or "") for page in reader.pages[:300])
        except (PdfReadError, ValueError, KeyError) as exc:
            raise DocumentRejected(f"Could not read the PDF ({type(exc).__name__}).") from None
    else:
        if b"\x00" in content[:2048]:
            raise DocumentRejected("The file appears to be binary, not text.")
        text = content.decode("utf-8", errors="replace")
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) < 20:
        raise DocumentRejected("No extractable text found in the document.")
    return text, ALLOWED_DOC_EXTENSIONS[ext]


def chunk_text(text: str) -> list[tuple[str, str]]:
    """Split on markdown headings/paragraphs, then pack into ~CHUNK_CHARS chunks with overlap.

    Returns (heading, chunk_text) pairs.
    """
    sections: list[tuple[str, str]] = []
    heading = ""
    buf: list[str] = []
    for line in text.split("\n"):
        m = re.match(r"^#{1,4}\s+(.*)", line)
        if m:
            if buf:
                sections.append((heading, "\n".join(buf).strip()))
                buf = []
            heading = m.group(1).strip()[:200]
        else:
            buf.append(line)
    if buf:
        sections.append((heading, "\n".join(buf).strip()))
    chunks: list[tuple[str, str]] = []
    for head, body in sections:
        if not body:
            continue
        paras = [p.strip() for p in body.split("\n\n") if p.strip()]
        cur = ""
        for p in paras:
            if len(cur) + len(p) + 2 <= CHUNK_CHARS:
                cur = f"{cur}\n\n{p}" if cur else p
                continue
            if cur:
                chunks.append((head, cur))
                cur = cur[-CHUNK_OVERLAP:] + "\n\n" + p if len(p) < CHUNK_CHARS else ""
            while len(p) > CHUNK_CHARS:
                chunks.append((head, p[:CHUNK_CHARS]))
                p = p[CHUNK_CHARS - CHUNK_OVERLAP:]
            if not cur:
                cur = p
        if cur.strip():
            chunks.append((head, cur))
    return chunks


def index_document(db: Session, workspace_id: int, title: str, filename: str, text: str, content_type: str,
                   category: str = "general", origin: str = "upload", user_id: int | None = None) -> KnowledgeDocument:
    doc = KnowledgeDocument(workspace_id=workspace_id, title=title[:255], filename=filename[:255],
                            content_type=content_type, category=category[:48], origin=origin,
                            char_count=len(text), uploaded_by_id=user_id)
    db.add(doc)
    db.flush()
    pieces = chunk_text(text)
    for i, (head, body) in enumerate(pieces):
        db.add(KnowledgeChunk(document_id=doc.id, workspace_id=workspace_id, ordinal=i, heading=head, content=body,
                              embedding=embed(f"{title} {head} {body}")))
    doc.chunk_count = len(pieces)
    db.flush()
    return doc


def seed_knowledge_base(db: Session, workspace_id: int) -> int:
    n = 0
    for path in sorted(SEED_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        first = text.splitlines()[0].lstrip("# ").strip() if text else path.stem
        category = path.stem.split("_")[0]
        index_document(db, workspace_id, first, path.name, text, "text/markdown", category=category, origin="built-in")
        n += 1
    return n


def search(db: Session, workspace_id: int, query: str, k: int = 5, min_score: float = 0.05) -> list[dict]:
    rows = db.query(KnowledgeChunk.id, KnowledgeChunk.document_id, KnowledgeChunk.heading, KnowledgeChunk.content,
                    KnowledgeChunk.embedding).filter(KnowledgeChunk.workspace_id == workspace_id).all()
    if not rows or not tokenize(query):
        return []
    matrix = np.asarray([r.embedding for r in rows], dtype=np.float32)
    scores = cosine_matrix(embed(query), matrix)
    order = np.argsort(-scores)[:k]
    doc_ids = {rows[i].document_id for i in order}
    titles = {d.id: d.title for d in db.query(KnowledgeDocument).filter(KnowledgeDocument.id.in_(doc_ids))}
    out = []
    for i in order:
        s = float(scores[i])
        if s < min_score:
            continue
        r = rows[i]
        out.append({"chunk_id": r.id, "document_id": r.document_id, "document_title": titles.get(r.document_id, ""),
                    "heading": r.heading, "content": r.content, "score": round(s, 3)})
    return out
