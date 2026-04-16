"""
Centralized logging configuration for the project.
Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

Features:
  - Colored output per log level (console)
  - Optional plain-text file handler (no ANSI codes)
  - Suppresses the noisy asyncio WinError 6 overlapped-cancel traceback
  - Module-level get_logger() for child loggers
"""
import logging
import sys
import os
from typing import Optional

# ── ANSI color codes ──────────────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_COLORS = {
    logging.DEBUG:    "\033[36m",      # Cyan
    logging.INFO:     "\033[32m",      # Green
    logging.WARNING:  "\033[33m",      # Yellow
    logging.ERROR:    "\033[31m",      # Red
    logging.CRITICAL: "\033[1;31m",    # Bold Red
}

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ── Suppress asyncio WinError 6 overlapped-cancel noise ──────────────────────
class _SuppressOverlappedCancelFilter(logging.Filter):
    """
    Drops the 'Cancelling an overlapped future failed ... WinError 6'
    error that asyncio emits when a socket is closed while a pending
    overlapped I/O operation is being cancelled.  This is harmless and
    expected behaviour on Windows when both relay tasks share sockets.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "asyncio" and record.levelno == logging.ERROR:
            msg = record.getMessage()
            if "overlapped" in msg and ("WinError 6" in msg or "handle is invalid" in msg):
                return False
            # Also suppress if the exception info contains WinError 6
            if record.exc_info:
                exc = record.exc_info[1]
                if isinstance(exc, OSError) and exc.winerror == 6:
                    return False
        return True


# ── Colored formatter ─────────────────────────────────────────────────────────
class _ColorFormatter(logging.Formatter):
    """
    Applies per-level ANSI colors to the level name and message.
    Falls back gracefully when the terminal doesn't support colors.
    """

    def __init__(self):
        super().__init__(datefmt=DATE_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        color = _COLORS.get(record.levelno, "")
        level_str = f"{color}{_BOLD}{record.levelname:<8}{_RESET}"
        time_str  = f"{_DIM}{self.formatTime(record, self.datefmt)}{_RESET}"
        name_str  = f"\033[35m{record.name}{_RESET}"          # Magenta for logger name

        base = f"[{time_str}] [{level_str}] [{name_str}] {color}{record.getMessage()}{_RESET}"

        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            base += f"\n{_DIM}{record.exc_text}{_RESET}"
        if record.stack_info:
            base += f"\n{_DIM}{self.formatStack(record.stack_info)}{_RESET}"

        return base


# ── Plain formatter (for file output) ────────────────────────────────────────
_PLAIN_FORMAT = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
_PlainFormatter = logging.Formatter(_PLAIN_FORMAT, datefmt=DATE_FORMAT)


# ── Enable and detect ANSI color support ─────────────────────────────────────
def _enable_windows_ansi() -> bool:
    """
    On Windows, enable ANSI escape processing for the console via
    SetConsoleMode.  Works for cmd.exe, Windows Terminal, and PyInstaller
    frozen executables.  Returns True if ANSI is now available.
    """
    try:
        import ctypes
        import ctypes.wintypes
        kernel32 = ctypes.windll.kernel32
        # Get handle to stdout (STD_OUTPUT_HANDLE = -11)
        handle = kernel32.GetStdHandle(-11)
        if handle == -1:
            return False
        mode = ctypes.wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        ENABLE_VT = 0x0004
        if mode.value & ENABLE_VT:
            return True  # already enabled
        return bool(kernel32.SetConsoleMode(handle, mode.value | ENABLE_VT))
    except Exception:
        return False


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    # Try to enable ANSI on Windows first
    if sys.platform == "win32":
        return _enable_windows_ansi()
    # Unix: check isatty
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return True
    if os.environ.get("WT_SESSION") or os.environ.get("COLORTERM"):
        return True
    return False


# ── Public API ────────────────────────────────────────────────────────────────
def setup_logger(
    name: str = "root",
    level: int = logging.DEBUG,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Configure the root logger (or a named logger) with a colored console
    handler and an optional plain-text file handler.

    Parameters
    ----------
    name     : Logger name; "root" maps to the real Python root logger.
    level    : Minimum log level (default DEBUG).
    log_file : If given, also write plain-text logs to this file path.
    """
    real_name = "" if name == "root" else name
    logger = logging.getLogger(real_name)

    if logger.handlers:
        return logger  # already configured

    logger.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    if _supports_color():
        console_handler.setFormatter(_ColorFormatter())
    else:
        console_handler.setFormatter(_PlainFormatter)
    console_handler.addFilter(_SuppressOverlappedCancelFilter())
    logger.addHandler(console_handler)

    # Optional file handler (plain text, no ANSI)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(_PlainFormatter)
        file_handler.addFilter(_SuppressOverlappedCancelFilter())
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger by name (inherits root handler automatically)."""
    return logging.getLogger(name)
