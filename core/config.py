from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass

from utils.network_tools import get_default_interface_ipv4


def _get_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(os.path.join(__file__, "..")))


@dataclass(frozen=True)
class Config:
    listen_host:     str
    listen_port:     int
    fake_sni:        bytes
    connect_ip:      str
    connect_port:    int
    interface_ipv4:  str

    data_mode:       str   = "tls"
    bypass_method:   str   = "wrong_seq"
    bypass_timeout:  float = 2.0
    fake_delay_ms:   float = 1.0    # ms to wait before injecting fake packet
    connect_timeout: float = 5.0    # TCP connect timeout in seconds

    recv_buffer:     int   = 65536
    max_connections: int   = 0
    idle_timeout:    int   = 0      # relay idle timeout seconds (0=off)
    rate_limit:      int   = 0      # max new connections per second per IP (0=off)

    browser_profile: str   = "random"  # chrome / firefox / safari / edge / random
    ttl_spoof:       bool  = True      # randomize TTL on fake packet

    log_level:       str   = "INFO"
    log_client_sni:  bool  = True
    log_file:        str   = ""
    stats_interval:  int   = 0

    def validate(self) -> None:
        from logger_setup import get_logger
        log = get_logger("config")
        ok  = True

        if not self.interface_ipv4:
            log.error("Cannot determine local interface IP -- check network")
            ok = False
        if not (1 <= self.listen_port <= 65535):
            log.error("Invalid LISTEN_PORT: %d", self.listen_port)
            ok = False
        if not (1 <= self.connect_port <= 65535):
            log.error("Invalid CONNECT_PORT: %d", self.connect_port)
            ok = False
        if self.data_mode != "tls":
            log.error("Unsupported DATA_MODE: %s (only 'tls' supported)", self.data_mode)
            ok = False
        if self.bypass_method != "wrong_seq":
            log.error("Unsupported BYPASS_METHOD: %s (only 'wrong_seq' supported)", self.bypass_method)
            ok = False
        if self.bypass_timeout <= 0:
            log.error("BYPASS_TIMEOUT must be > 0, got %s", self.bypass_timeout)
            ok = False
        if self.connect_timeout <= 0:
            log.error("CONNECT_TIMEOUT must be > 0, got %s", self.connect_timeout)
            ok = False
        if self.fake_delay_ms < 0:
            log.error("FAKE_DELAY_MS must be >= 0, got %s", self.fake_delay_ms)
            ok = False
        if self.recv_buffer < 1024:
            log.error("RECV_BUFFER must be >= 1024, got %d", self.recv_buffer)
            ok = False
        if self.max_connections < 0:
            log.error("MAX_CONNECTIONS must be >= 0, got %d", self.max_connections)
            ok = False
        if self.idle_timeout < 0:
            log.error("IDLE_TIMEOUT must be >= 0, got %d", self.idle_timeout)
            ok = False
        if self.rate_limit < 0:
            log.error("RATE_LIMIT must be >= 0, got %d", self.rate_limit)
            ok = False

        if not ok:
            sys.exit(1)

    def log_level_int(self) -> int:
        from logger_setup import VERBOSE
        return {
            "DEBUG":    logging.DEBUG,
            "VERBOSE":  VERBOSE,
            "INFO":     logging.INFO,
            "WARNING":  logging.WARNING,
            "ERROR":    logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }.get(self.log_level.upper(), logging.INFO)


def load_config() -> Config:
    path = os.path.join(_get_exe_dir(), "config.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        print(f"\n  ERROR: config.json not found at:\n  {path}")
        print("  Place config.json in the same folder as main.exe\n")
        input("  Press Enter to exit...")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"\n  ERROR: config.json is not valid JSON:\n  {exc}\n")
        input("  Press Enter to exit...")
        sys.exit(1)

    cfg = Config(
        listen_host     = raw.get("LISTEN_HOST",      "0.0.0.0"),
        listen_port     = int(raw["LISTEN_PORT"]),
        fake_sni        = raw["FAKE_SNI"].encode(),
        connect_ip      = raw["CONNECT_IP"],
        connect_port    = int(raw["CONNECT_PORT"]),
        interface_ipv4  = get_default_interface_ipv4(raw["CONNECT_IP"]),
        data_mode       = raw.get("DATA_MODE",         "tls"),
        bypass_method   = raw.get("BYPASS_METHOD",     "wrong_seq"),
        bypass_timeout  = float(raw.get("BYPASS_TIMEOUT",   2.0)),
        fake_delay_ms   = float(raw.get("FAKE_DELAY_MS",    1.0)),
        connect_timeout = float(raw.get("CONNECT_TIMEOUT",  5.0)),
        recv_buffer     = int(raw.get("RECV_BUFFER",        65536)),
        max_connections = int(raw.get("MAX_CONNECTIONS",    0)),
        idle_timeout    = int(raw.get("IDLE_TIMEOUT",       0)),
        rate_limit      = int(raw.get("RATE_LIMIT",         0)),
        browser_profile = raw.get("BROWSER_PROFILE",   "random"),
        ttl_spoof       = bool(raw.get("TTL_SPOOF",         True)),
        log_level       = raw.get("LOG_LEVEL",         "INFO"),
        log_client_sni  = bool(raw.get("LOG_CLIENT_SNI",   True)),
        log_file        = raw.get("LOG_FILE",          ""),
        stats_interval  = int(raw.get("STATS_INTERVAL",    0)),
    )
    cfg.validate()
    return cfg
