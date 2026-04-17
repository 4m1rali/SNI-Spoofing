"""
NexNull -- Logging subsystem

- 256-color ANSI, pure-ASCII badges (safe in every Windows code page)
- UTF-8 + ANSI VT auto-enabled on Windows
- VERBOSE level (15) between DEBUG and INFO
- Suppresses harmless asyncio WinError 6 noise
- Optional plain-text file handler
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional


# ── Bootstrap Windows console (UTF-8 + ANSI VT) ──────────────────────────────
def _bootstrap_windows() -> bool:
    if sys.platform != "win32":
        return bool(
            getattr(sys.stdout, "isatty", lambda: False)()
            or os.environ.get("COLORTERM")
            or os.environ.get("WT_SESSION")
        )
    try:
        import ctypes, ctypes.wintypes
        k32 = ctypes.windll.kernel32
        k32.SetConsoleOutputCP(65001)
        k32.SetConsoleCP(65001)
        h = k32.GetStdHandle(-11)
        if h not in (-1, 0):
            m = ctypes.wintypes.DWORD()
            if k32.GetConsoleMode(h, ctypes.byref(m)):
                k32.SetConsoleMode(h, m.value | 0x0004)
    except Exception:
        pass
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        import ctypes, ctypes.wintypes
        k32 = ctypes.windll.kernel32
        h   = k32.GetStdHandle(-11)
        m   = ctypes.wintypes.DWORD()
        if k32.GetConsoleMode(h, ctypes.byref(m)):
            return bool(m.value & 0x0004)
    except Exception:
        pass
    return False


_COLOR_OK = _bootstrap_windows()


def _supports_color() -> bool:
    return _COLOR_OK


# ── VERBOSE level ─────────────────────────────────────────────────────────────
VERBOSE = 15
logging.addLevelName(VERBOSE, "VERBOSE")

def _verbose(self: logging.Logger, msg: str, *args, **kw) -> None:
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, msg, args, **kw)

logging.Logger.verbose = _verbose  # type: ignore[attr-defined]


# ── ANSI primitives ───────────────────────────────────────────────────────────
_R  = "\033[0m"
_B  = "\033[1m"
_D  = "\033[2m"
_I  = "\033[3m"

def _fg(n: int) -> str:
    return f"\033[38;5;{n}m"

def _bg(n: int) -> str:
    return f"\033[48;5;{n}m"


# ── Per-level theme: (badge, badge-color, message-color) ─────────────────────
# Pure ASCII badges -- render in every code page
_THEMES: dict[int, tuple[str, str, str]] = {
    logging.DEBUG:    ("[.]",  _fg(240),       _fg(244)),   # grey
    VERBOSE:          ("[>]",  _fg(75),        _fg(153)),   # sky blue
    logging.INFO:     ("[+]",  _fg(77),        _fg(255)),   # green / white
    logging.WARNING:  ("[!]",  _fg(220),       _fg(229)),   # amber
    logging.ERROR:    ("[x]",  _fg(196),       _fg(203)),   # red
    logging.CRITICAL: ("[!!]", _B + _fg(196),  _B + _fg(203)),  # bold red
}

_TIME_C  = _fg(238)   # very dark grey  -- timestamp
_NAME_C  = _fg(141)   # soft purple     -- module name
_DIM_B   = _D         # dim brackets

DATE_FMT = "%H:%M:%S"


# ── Noise filter ──────────────────────────────────────────────────────────────
class _OverlappedFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "asyncio" and record.levelno == logging.ERROR:
            msg = record.getMessage()
            if "overlapped" in msg and (
                "WinError 6" in msg or "handle is invalid" in msg
            ):
                return False
            if record.exc_info:
                exc = record.exc_info[1]
                if isinstance(exc, OSError) and getattr(exc, "winerror", None) == 6:
                    return False
        return True


# ── Color formatter ───────────────────────────────────────────────────────────
class _ColorFmt(logging.Formatter):
    """
    Format:
      [HH:MM:SS] [badge] [LEVEL   ] [name]  message
    """
    def __init__(self) -> None:
        super().__init__(datefmt=DATE_FMT)

    def format(self, record: logging.LogRecord) -> str:
        badge, bc, mc = _THEMES.get(record.levelno, ("[?]", _fg(255), _fg(255)))

        ts   = f"{_TIME_C}{self.formatTime(record, self.datefmt)}{_R}"
        bdg  = f"{bc}{_B}{badge:<5}{_R}"
        lvl  = f"{bc}{record.levelname:<8}{_R}"
        name = f"{_NAME_C}{record.name}{_R}"
        msg  = f"{mc}{record.getMessage()}{_R}"

        line = (
            f"{_DIM_B}[{_R}{ts}{_DIM_B}]{_R} "
            f"{bdg} "
            f"{_DIM_B}[{_R}{lvl}{_DIM_B}]{_R} "
            f"{_DIM_B}[{_R}{name}{_DIM_B}]{_R}  "
            f"{msg}"
        )

        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            line += f"\n{_D}{record.exc_text}{_R}"
        if record.stack_info:
            line += f"\n{_D}{self.formatStack(record.stack_info)}{_R}"
        return line


# ── Plain formatter ───────────────────────────────────────────────────────────
_PLAIN_FMT = logging.Formatter(
    "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)


# ── Public API ────────────────────────────────────────────────────────────────
def setup_logger(
    name: str = "root",
    level: int = logging.DEBUG,
    log_file: Optional[str] = None,
) -> logging.Logger:
    real_name = "" if name == "root" else name
    logger    = logging.getLogger(real_name)
    if logger.handlers:
        return logger

    logger.setLevel(level)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(_ColorFmt() if _COLOR_OK else _PLAIN_FMT)
    console.addFilter(_OverlappedFilter())
    logger.addHandler(console)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        fh.addFilter(_OverlappedFilter())
        logger.addHandler(fh)

    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
