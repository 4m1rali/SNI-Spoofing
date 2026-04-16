"""
Runtime configuration — loaded once at startup from config.json.
"""
import json
import os
import sys
from dataclasses import dataclass

from utils.network_tools import get_default_interface_ipv4


def _get_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__ + "/.."))


@dataclass(frozen=True)
class Config:
    listen_host:    str
    listen_port:    int
    fake_sni:       bytes
    connect_ip:     str
    connect_port:   int
    interface_ipv4: str
    data_mode:      str = "tls"
    bypass_method:  str = "wrong_seq"
    log_client_sni: bool = True   # log the real SNI from client TLS hello
    log_file:       str  = ""     # write logs to this file if non-empty

    def validate(self) -> None:
        from logger_setup import get_logger
        log = get_logger("config")
        ok = True
        if not self.interface_ipv4:
            log.error("Could not determine local interface IP — check network connectivity")
            ok = False
        if not (1 <= self.listen_port <= 65535):
            log.error("Invalid LISTEN_PORT: %d", self.listen_port)
            ok = False
        if not (1 <= self.connect_port <= 65535):
            log.error("Invalid CONNECT_PORT: %d", self.connect_port)
            ok = False
        if self.data_mode != "tls":
            log.error("Unsupported DATA_MODE: %s  (only 'tls' supported)", self.data_mode)
            ok = False
        if self.bypass_method != "wrong_seq":
            log.error("Unsupported BYPASS_METHOD: %s  (only 'wrong_seq' supported)", self.bypass_method)
            ok = False
        if not ok:
            sys.exit(1)


def load_config() -> Config:
    """Load and validate config.json, exit with a friendly message on error."""
    path = os.path.join(_get_exe_dir(), "config.json")
    try:
        with open(path, "r") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: config.json not found at: {path}")
        print("Place config.json in the same folder as main.exe")
        input("Press Enter to exit...")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: config.json is not valid JSON: {exc}")
        input("Press Enter to exit...")
        sys.exit(1)

    cfg = Config(
        listen_host    = raw.get("LISTEN_HOST", "0.0.0.0"),
        listen_port    = int(raw["LISTEN_PORT"]),
        fake_sni       = raw["FAKE_SNI"].encode(),
        connect_ip     = raw["CONNECT_IP"],
        connect_port   = int(raw["CONNECT_PORT"]),
        interface_ipv4 = get_default_interface_ipv4(raw["CONNECT_IP"]),
        data_mode      = raw.get("DATA_MODE", "tls"),
        bypass_method  = raw.get("BYPASS_METHOD", "wrong_seq"),
        log_client_sni = bool(raw.get("LOG_CLIENT_SNI", True)),
        log_file       = raw.get("LOG_FILE", ""),
    )
    cfg.validate()
    return cfg
