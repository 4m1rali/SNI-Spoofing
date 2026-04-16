"""
Connection statistics.

Python's GIL makes integer += on a single object atomic for CPython, so
simple counters don't need a lock.  We only take the lock for the
log_summary() read to get a consistent snapshot across all fields.
"""
from __future__ import annotations

import threading
from logger_setup import get_logger

log = get_logger("stats")


class Stats:
    __slots__ = ("_lock", "total", "active", "failed", "relayed")

    def __init__(self) -> None:
        self._lock   = threading.Lock()
        self.total   = 0
        self.active  = 0
        self.failed  = 0
        self.relayed = 0

    def new_connection(self) -> None:
        self.total  += 1
        self.active += 1

    def connection_done(self) -> None:
        v = self.active - 1
        self.active = v if v >= 0 else 0

    def connection_failed(self) -> None:
        self.failed += 1
        v = self.active - 1
        self.active = v if v >= 0 else 0

    def relay_started(self) -> None:
        self.relayed += 1

    def log_summary(self) -> None:
        with self._lock:
            t, r, f, a = self.total, self.relayed, self.failed, self.active
        log.info(
            "Session summary — total: %d  relayed: %d  failed: %d  active: %d",
            t, r, f, a,
        )


stats = Stats()
