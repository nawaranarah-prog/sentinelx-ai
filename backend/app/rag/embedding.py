"""Local lexical embeddings via feature hashing.

This is deliberately simple and dependency-free: unigrams + bigrams are hashed into a fixed-size
vector with sublinear term frequency and L2 normalization. It captures lexical overlap (not deep
semantics). It is labelled "local hashing embedding" everywhere in the UI and docs.
"""

import hashlib
import math
import re

import numpy as np

DIM = 768
EMBEDDING_NAME = "sentinelx-hash-v1 (local lexical feature hashing, 768 dims, unigrams+bigrams)"
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.\-]*[a-z0-9]|[a-z0-9]")
STOPWORDS = set("""a an the and or but if then else of to in on at by for with from as is are was were be been being
this that these those it its into over under about after before between during without within than so such
can could should would may might must will shall do does did done have has had not no nor only own same too very
i me my we our you your he she they them their what which who whom how why when where all any both each few more
most other some""".split())


def tokenize(text: str) -> list[str]:
    toks = [t for t in _TOKEN.findall(text.lower()) if t not in STOPWORDS and len(t) > 1]
    return [t.rstrip(".") for t in toks]


def _bucket(term: str) -> tuple[int, float]:
    h = hashlib.blake2b(term.encode(), digest_size=8).digest()
    idx = int.from_bytes(h[:4], "little") % DIM
    sign = 1.0 if h[4] & 1 else -1.0
    return idx, sign


def embed(text: str) -> list[float]:
    toks = tokenize(text)
    counts: dict[str, int] = {}
    for t in toks:
        counts[t] = counts.get(t, 0) + 1
    for a, b in zip(toks, toks[1:], strict=False):
        bg = a + " " + b
        counts[bg] = counts.get(bg, 0) + 1
    vec = np.zeros(DIM, dtype=np.float32)
    for term, c in counts.items():
        idx, sign = _bucket(term)
        weight = (1.0 + math.log(c)) * (0.6 if " " in term else 1.0)
        vec[idx] += sign * weight
    norm = float(np.linalg.norm(vec))
    if norm > 0:
        vec /= norm
    return [round(float(x), 5) for x in vec]


def cosine_matrix(query: list[float], matrix: np.ndarray) -> np.ndarray:
    q = np.asarray(query, dtype=np.float32)
    return matrix @ q
