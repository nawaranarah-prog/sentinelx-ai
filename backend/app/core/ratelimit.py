import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    """In-process sliding-window rate limiter.

    Suitable for a single backend instance. A multi-instance deployment should move this
    state to a shared store (e.g. Redis); see docs/security.md.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: float = 60.0) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False, window_seconds - (now - q[0])
            q.append(now)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def enforce(request: Request, bucket: str, limit: int, key_suffix: str | None = None) -> None:
    key = f"{bucket}:{key_suffix or client_ip(request)}"
    ok, retry_after = limiter.check(key, limit)
    if not ok:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait and try again.",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
