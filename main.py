"""
SNI-Spoofing — entry point.

Responsibilities:
  - Admin check
  - Logger bootstrap
  - Config load
  - Start WinDivert thread
  - Run async accept loop
"""
import asyncio
import ctypes
import signal
import socket
import sys
import threading
import logging

# ── Admin check (must happen before anything else) ────────────────────────────
def _require_admin() -> None:
    try:
        ok = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        ok = False
    if not ok:
        print("=" * 55)
        print("  ERROR: Administrator privileges required!")
        print("=" * 55)
        print()
        print("  WinDivert needs Admin rights to capture packets.")
        print('  Right-click main.exe → "Run as administrator"')
        print()
        input("  Press Enter to exit...")
        sys.exit(1)

_require_admin()

# ── Logging (before any imports that call get_logger) ─────────────────────────
from logger_setup import setup_logger, get_logger
from core.config import load_config
from core.stats import stats
from core.relay import handle, active_connections, _apply_keepalive
from bypass.fake_tcp import FakeTcpInjector

cfg = load_config()
setup_logger("root", level=logging.DEBUG, log_file=cfg.log_file or None)
log = get_logger("main")

log.info(
    "Config — listen=%s:%d  target=%s:%d  iface=%s  log_sni=%s",
    cfg.listen_host, cfg.listen_port,
    cfg.connect_ip, cfg.connect_port,
    cfg.interface_ipv4,
    cfg.log_client_sni,
)

# ── Accept loop ───────────────────────────────────────────────────────────────
async def _serve() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setblocking(False)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((cfg.listen_host, cfg.listen_port))
    _apply_keepalive(server)
    server.listen(128)
    log.info("Listening on %s:%d", cfg.listen_host, cfg.listen_port)

    loop      = asyncio.get_running_loop()
    stop      = asyncio.Event()

    def _on_signal(*_) -> None:
        log.info("Shutdown signal — stopping")
        stats.log_summary()
        stop.set()

    try:
        loop.add_signal_handler(signal.SIGINT,  _on_signal)
        loop.add_signal_handler(signal.SIGTERM, _on_signal)
    except NotImplementedError:
        pass  # Windows: KeyboardInterrupt handles it

    try:
        while not stop.is_set():
            try:
                client, addr = await asyncio.wait_for(
                    loop.sock_accept(server), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            client.setblocking(False)
            _apply_keepalive(client)
            asyncio.create_task(handle(client, addr, cfg))
    except KeyboardInterrupt:
        log.info("Interrupted")
        stats.log_summary()
    finally:
        server.close()


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Build WinDivert filter scoped to the local↔target path only
    w_filter = (
        f"tcp and ("
        f"(ip.SrcAddr == {cfg.interface_ipv4} and ip.DstAddr == {cfg.connect_ip})"
        f" or "
        f"(ip.SrcAddr == {cfg.connect_ip} and ip.DstAddr == {cfg.interface_ipv4})"
        f")"
    )
    injector = FakeTcpInjector(w_filter, active_connections)
    threading.Thread(target=injector.run, daemon=True).start()

    print("=" * 55)
    print("  SNI Spoofing Tool — Free Internet Access for Iran")
    print("=" * 55)
    print("  If this tool helps you access the free internet,")
    print("  please consider supporting the project.")
    print("  More tools and projects are in development to help")
    print("  people in Iran bypass censorship — your support")
    print("  makes it possible.")
    print()
    print("  Donate via USDT (BEP20):")
    print("  0x76a768B53Ca77B43086946315f0BDF21156bF424")
    print()
    print("  Telegram: @patterniha")
    print("=" * 55)
    print()

    asyncio.run(_serve())
