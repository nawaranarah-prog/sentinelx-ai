"""Live telemetry simulation for DEMO workspaces.

A background thread periodically generates a small batch of synthetic Nova Bank events (timestamped
"now") and pushes them through the real ingestion pipeline. State is in-process: a restart stops it.
"""

import logging
import random
import threading
from datetime import UTC, datetime, timedelta

from app.database import session as dbs
from app.demo.generator import (
    _Builder,
    _credential_compromise,
    _insider_cloud_exfil,
    _macro_powershell,
    _normal_day,
    _people,
)
from app.ingestion.normalizer import RowError, normalize_record
from app.models import Workspace
from app.services.pipeline import ingest_rows

log = logging.getLogger(__name__)
TICK_SECONDS = 20
ATTACKS = [_macro_powershell, _insider_cloud_exfil, _credential_compromise]


class _Sim:
    def __init__(self, workspace_id: int):
        self.workspace_id = workspace_id
        self.running = False
        self.ticks = 0
        self.events_generated = 0
        self.last_tick: datetime | None = None
        self.last_error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.rng = random.Random()

    def status(self) -> dict:
        return {"running": self.running, "ticks": self.ticks, "events_generated": self.events_generated,
                "last_tick": self.last_tick.isoformat() + "Z" if self.last_tick else None,
                "tick_seconds": TICK_SECONDS, "last_error": self.last_error}

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, name=f"sim-{self.workspace_id}", daemon=True)
        self._thread.start()

    def pause(self) -> None:
        self._stop.set()
        self.running = False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # keep the simulation alive, surface the error in status
                log.exception("simulation tick failed")
                self.last_error = type(exc).__name__
            self._stop.wait(TICK_SECONDS)

    def tick(self) -> int:
        now = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
        b = _Builder(f"SIM{self.workspace_id}-{int(now.timestamp())}", self.rng)
        people = self.rng.sample(_people(), 4)
        _normal_day(b, now - timedelta(hours=8), people, weekend=False)
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        # Ordinary activity: a sample of independent routine events, re-timed into the last tick window.
        recs = self.rng.sample(b.records, min(len(b.records), self.rng.randint(15, 40)))
        for r in recs:
            r["timestamp"] = (now - timedelta(seconds=self.rng.randint(0, TICK_SECONDS))).strftime(fmt)
        if self.ticks and self.ticks % 6 == 0:
            attack = ATTACKS[(self.ticks // 6 - 1) % len(ATTACKS)]
            ab = _Builder(b.prefix + "A", self.rng)
            attack(ab, now)
            # Shift the whole scenario so its last event is "now", preserving the attack sequence.
            last = max(datetime.strptime(r["timestamp"], fmt) for r in ab.records)
            offset = now - last
            for r in ab.records:
                r["timestamp"] = (datetime.strptime(r["timestamp"], fmt) + offset).strftime(fmt)
            recs += ab.records
        rows = []
        for r in recs:
            try:
                rows.append(normalize_record(r))
            except RowError:
                continue
        db = dbs.SessionLocal()
        try:
            ws = db.get(Workspace, self.workspace_id)
            if ws is None:
                self.pause()
                return 0
            stats = ingest_rows(db, ws, rows, source_label="nova-bank-simulation")
        finally:
            db.close()
        self.ticks += 1
        self.events_generated += stats.get("accepted", 0)
        self.last_tick = now
        return stats.get("accepted", 0)


_sims: dict[int, _Sim] = {}
_guard = threading.Lock()


def get_sim(workspace_id: int) -> _Sim:
    with _guard:
        if workspace_id not in _sims:
            _sims[workspace_id] = _Sim(workspace_id)
        return _sims[workspace_id]


def stop_all() -> None:
    for s in list(_sims.values()):
        s.pause()
