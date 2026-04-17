from __future__ import annotations

import sys
import threading
import time
from collections import defaultdict
from logger_setup import get_logger

log = get_logger("stats")

_UNITS = ((1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "KB"), (1, "B"))


def _fmt_bytes(n: int) -> str:
    for thr, unit in _UNITS:
        if n >= thr:
            return f"{n / thr:.1f}{unit}"
    return f"{n}B"


def _fmt_uptime(sec: float) -> str:
    s = int(sec)
    h, r = divmod(s, 3600)
    m, s = divmod(r, 60)
    if h:  return f"{h}h {m}m {s}s"
    if m:  return f"{m}m {s}s"
    return f"{s}s"


def _set_title(title: str) -> None:
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        except Exception:
            pass
    else:
        try:
            sys.stdout.write(f"\033]0;{title}\007")
            sys.stdout.flush()
        except Exception:
            pass


class Stats:
    __slots__ = (
        "_lock", "_start",
        "total", "active", "failed", "relayed",
        "bytes_in", "bytes_out",
        "_sni_counts", "_ip_counts",
    )

    def __init__(self) -> None:
        self._lock      = threading.Lock()
        self._start     = time.monotonic()
        self.total      = 0
        self.active     = 0
        self.failed     = 0
        self.relayed    = 0
        self.bytes_in   = 0
        self.bytes_out  = 0
        self._sni_counts: dict[str, int] = defaultdict(int)
        self._ip_counts:  dict[str, int] = defaultdict(int)

    def new_connection(self)   -> None: self.total += 1;  self.active += 1
    def relay_started(self)    -> None: self.relayed += 1
    def add_bytes_in(self, n)  -> None: self.bytes_in  += n
    def add_bytes_out(self, n) -> None: self.bytes_out += n

    def connection_done(self) -> None:
        v = self.active - 1
        self.active = v if v >= 0 else 0

    def connection_failed(self) -> None:
        self.failed += 1
        v = self.active - 1
        self.active = v if v >= 0 else 0

    def record_sni(self, sni: str) -> None:
        with self._lock:
            self._sni_counts[sni] += 1

    def record_ip(self, ip: str) -> None:
        with self._lock:
            self._ip_counts[ip] += 1

    def top_snis(self, n: int = 5) -> list[tuple[str, int]]:
        with self._lock:
            return sorted(self._sni_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def snapshot(self) -> dict:
        with self._lock:
            return dict(
                uptime    = _fmt_uptime(time.monotonic() - self._start),
                total     = self.total,
                active    = self.active,
                relayed   = self.relayed,
                failed    = self.failed,
                bytes_in  = _fmt_bytes(self.bytes_in),
                bytes_out = _fmt_bytes(self.bytes_out),
            )

    def update_title(self) -> None:
        s = self.snapshot()
        _set_title(
            f"NexNull"
            f"  |  Req: {s['total']}"
            f"  Active: {s['active']}"
            f"  Failed: {s['failed']}"
            f"  Up: {s['bytes_in']}"
            f"  Dn: {s['bytes_out']}"
            f"  {s['uptime']}"
        )

    def log_summary(self) -> None:
        s = self.snapshot()
        log.info(
            "Stats  uptime: %-10s  total: %-6d  active: %-4d  "
            "relayed: %-6d  failed: %-4d  up: %-8s  dn: %s",
            s["uptime"], s["total"], s["active"],
            s["relayed"], s["failed"],
            s["bytes_in"], s["bytes_out"],
        )
        top = self.top_snis(5)
        if top:
            log.info("Top SNIs: %s",
                     "  ".join(f"{sni}({n})" for sni, n in top))

    def log_bypass_rate(self) -> None:
        from bypass.fake_tcp import _bypass_ok, _bypass_fail
        total = _bypass_ok + _bypass_fail
        rate  = (_bypass_ok / total * 100) if total else 0.0
        log.info(
            "Bypass rate: %.1f%%  ok=%d  fail=%d  total=%d",
            rate, _bypass_ok, _bypass_fail, total,
        )


stats = Stats()
