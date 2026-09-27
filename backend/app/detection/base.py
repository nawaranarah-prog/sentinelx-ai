from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass(slots=True)
class Ev:
    id: int
    uid: str
    ts: datetime
    type: str
    user: str | None
    src: str | None
    dst: str | None
    host: str | None
    process: str | None
    command: str | None
    action: str | None
    status: str | None
    bytes: int | None
    resource: str | None
    meta: dict

    @property
    def cmd_text(self) -> str:
        return f"{self.process or ''} {self.command or ''}".lower()


@dataclass
class Candidate:
    rule_key: str
    dedupe_key: str
    title: str
    description: str
    severity: str
    confidence: float
    ts: datetime
    last_seen: datetime
    events: list[Ev]
    explanation: str
    mitre: list[dict]
    false_positives: list[str]
    recommendations: list[str]
    stage: str
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    evidence_summary: dict = field(default_factory=dict)


@dataclass
class RuleContext:
    business_hours: tuple[int, int] = (7, 20)
    indicators: list[dict] = field(default_factory=list)
    privileged_logon_users: set[str] = field(default_factory=set)


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def max_severity(*sevs: str) -> str:
    return max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0))


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_duration(delta: timedelta) -> str:
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs} s"
    mins, s = divmod(secs, 60)
    if mins < 60:
        return f"{mins} min {s} s" if s else f"{mins} min"
    hours, m = divmod(mins, 60)
    return f"{hours} h {m} min"


def fmt_bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def is_off_hours(dt: datetime, business_hours: tuple[int, int]) -> bool:
    start, end = business_hours
    return not (start <= dt.hour < end)


def cluster_by_gap(events: list[Ev], gap: timedelta) -> list[list[Ev]]:
    """Split time-sorted events into clusters where consecutive events are at most `gap` apart."""
    clusters: list[list[Ev]] = []
    for e in events:
        if clusters and e.ts - clusters[-1][-1].ts <= gap:
            clusters[-1].append(e)
        else:
            clusters.append([e])
    return clusters


def densest_window(events: list[Ev], window: timedelta) -> tuple[int, datetime, datetime]:
    """Max number of events inside any sliding window of length `window` (events time-sorted)."""
    best, best_i, best_j = 0, 0, 0
    j = 0
    for i in range(len(events)):
        while events[i].ts - events[j].ts > window:
            j += 1
        if i - j + 1 > best:
            best, best_i, best_j = i - j + 1, j, i
    if not events:
        return 0, datetime.min, datetime.min
    return best, events[best_i].ts, events[best_j].ts


def most_common(values, default=None):
    vals = [v for v in values if v]
    return Counter(vals).most_common(1)[0][0] if vals else default


def distinct(values) -> list:
    seen: dict = {}
    for v in values:
        if v and v not in seen:
            seen[v] = None
    return list(seen)


def join_limited(items: list, limit: int = 5) -> str:
    items = [str(i) for i in items]
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"
