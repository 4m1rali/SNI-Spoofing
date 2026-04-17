from __future__ import annotations

import asyncio
import ctypes
import random
import signal
import socket
import sys
import threading

from facts import FUN_FACTS


def _require_admin() -> None:
    try:
        ok = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        ok = False
    if not ok:
        W = 58
        print()
        print("  +" + "-" * W + "+")
        print("  |" + "  ADMINISTRATOR PRIVILEGES REQUIRED  ".center(W) + "|")
        print("  +" + "-" * W + "+")
        print("  |" + " " * W + "|")
        print("  |  WinDivert needs Admin rights to intercept packets.  |")
        print("  |" + " " * W + "|")
        print('  |    Right-click main.exe -> "Run as administrator"    |')
        print("  |" + " " * W + "|")
        print("  +" + "-" * W + "+")
        print()
        input("  Press Enter to exit...")
        sys.exit(1)


_require_admin()

from logger_setup import setup_logger, get_logger, _supports_color, _fg, _R, _B, _D
from core.config import load_config
from core.stats import stats
from core.relay import handle, active_connections, _apply_keepalive
from bypass.fake_tcp import FakeTcpInjector

cfg = load_config()
setup_logger("root", level=cfg.log_level_int(), log_file=cfg.log_file or None)
log = get_logger("main")

_LOGO = r"""
  _   _           _  _       _ _
 | \ | | _____  _| \| |_   _| | |
 |  \| |/ _ \ \/ / .` | | | | | |
 | |\  |  __/>  <| |\  | |_| | | |
 |_| \_|\___/_/\_\_| \_|\__,_|_|_|
"""


def _print_banner() -> None:
    W = 58

    if _supports_color():
        C  = _fg(75)
        G  = _fg(77)
        Y  = _fg(220)
        DG = _fg(240)
        W2 = _fg(255)
        P  = _fg(141)
        PK = _fg(213)

        for line in _LOGO.splitlines():
            print(f"  {C}{_B}{line}{_R}")
        print(f"  {DG}  DPI Bypass Proxy  |  SNI Spoofing  |  WinDivert{_R}")
        print()

        div = f"  {DG}+" + "-" * W + f"+{_R}"

        def row(label: str, val: str, vc: str = W2) -> str:
            content = f"  {DG}|{_R}  {W2}{label:<12}{_R}{vc}{val}{_R}"
            visible = len(f"  {label:<12}{val}")
            pad = W - visible - 2
            return content + " " * max(pad, 1) + f"{DG}|{_R}"

        print(div)
        print(row("Listen",    f"{cfg.listen_host}:{cfg.listen_port}", G))
        print(row("Target",    f"{cfg.connect_ip}:{cfg.connect_port}", G))
        print(row("Fake SNI",  cfg.fake_sni.decode(), Y))
        print(row("Interface", cfg.interface_ipv4, C))
        print(row("Log Level", cfg.log_level, P))
        print(row("Log SNI",   "ON" if cfg.log_client_sni else "OFF",
                  G if cfg.log_client_sni else DG))
        if cfg.max_connections:
            print(row("Max Conn",  str(cfg.max_connections), Y))
        if cfg.log_file:
            print(row("Log File",  cfg.log_file, DG))
        print(div)
        print()

        print(div)
        def srow(text: str, color: str = W2) -> str:
            visible = len(text)
            pad = W - visible - 2
            return f"  {DG}|{_R}  {color}{text}{_R}" + " " * max(pad, 1) + f"{DG}|{_R}"

        print(srow("Based on the original work of patterniha", PK))
        print(srow("github.com/patterniha/SNI-Spoofing", DG))
        print(srow("Full respect and credit to the original author  (c)", DG))
        print(f"  {DG}|{_R}" + " " * (W + 2) + f"{DG}|{_R}")
        print(srow("Support free internet access for Iran", W2))
        print(srow("Telegram  @patterniha", C))
        print(srow("Channel   t.me/projectXhttp", C))
        print(srow("USDT BEP20  0x76a768B53Ca77B43086946315f0BDF21156bF424", Y))
        print(div)
        print()

    else:
        W2 = W
        div = "  +" + "-" * W + "+"
        print()
        for line in _LOGO.splitlines():
            print(" " + line)
        print()
        print(div)
        print("  |" + "  NexNull -- DPI Bypass Proxy".ljust(W) + "|")
        print(div)
        print(f"  |  {'Listen':<12}{cfg.listen_host}:{cfg.listen_port}".ljust(W + 3) + "|")
        print(f"  |  {'Target':<12}{cfg.connect_ip}:{cfg.connect_port}".ljust(W + 3) + "|")
        print(f"  |  {'Fake SNI':<12}{cfg.fake_sni.decode()}".ljust(W + 3) + "|")
        print(f"  |  {'Interface':<12}{cfg.interface_ipv4}".ljust(W + 3) + "|")
        print(f"  |  {'Log Level':<12}{cfg.log_level}".ljust(W + 3) + "|")
        print(f"  |  {'Log SNI':<12}{'ON' if cfg.log_client_sni else 'OFF'}".ljust(W + 3) + "|")
        print(div)
        print()
        print(div)
        print("  |  Based on original work by patterniha".ljust(W + 3) + "|")
        print("  |  github.com/patterniha/SNI-Spoofing".ljust(W + 3) + "|")
        print("  |" + " " * W + "|")
        print("  |  Telegram: @patterniha".ljust(W + 3) + "|")
        print("  |  USDT BEP20: 0x76a768B53Ca77B43086946315f0BDF21156bF424  |")
        print(div)
        print()


def _get_fact_with_sni() -> tuple[str, list[str]]:
    face, lines = random.choice(FUN_FACTS)
    resolved = []
    for line in lines:
        resolved.append(line.replace("{FAKE_SNI}", cfg.fake_sni.decode()))
    return face, resolved


def _print_fun_fact() -> None:
    face, lines = _get_fact_with_sni()
    W = 60

    if _supports_color():
        C  = _fg(213)
        Y  = _fg(220)
        DG = _fg(240)
        W2 = _fg(255)

        div   = f"  {DG}+" + "-" * W + f"+{_R}"
        empty = f"  {DG}|{_R}" + " " * (W + 2) + f"{DG}|{_R}"

        def box_line(text: str, color: str = W2) -> str:
            visible = len(text)
            pad = W - visible - 2
            return f"  {DG}|{_R}  {color}{text}{_R}" + " " * max(pad, 1) + f"{DG}|{_R}"

        print(div)
        print(box_line(f"Nex-chan says  {face}", C))
        print(empty)
        for i, line in enumerate(lines):
            color = W2 if i < len(lines) - 1 else Y
            print(box_line(line, color))
        print(empty)
        print(div)
        print()
    else:
        div = "  +" + "-" * W + "+"
        print(div)
        print(f"  |  Nex-chan says  {face}".ljust(W + 3) + "|")
        print("  |" + " " * W + "|")
        for line in lines:
            print(f"  |  {line}".ljust(W + 3) + "|")
        print("  |" + " " * W + "|")
        print(div)
        print()


def _startup_prompt() -> None:
    _print_fun_fact()
    if _supports_color():
        C = _fg(213)
        print(f"  {C}{_B}Press Enter to continue...{_R}  ", end="", flush=True)
        input()
        print()
    else:
        input("  Press Enter to continue...  ")
        print()


async def _title_loop(interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        stats.update_title()


async def _stats_loop(interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        stats.log_summary()


async def _serve() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setblocking(False)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((cfg.listen_host, cfg.listen_port))
    _apply_keepalive(server)
    server.listen(256)
    log.info("Listening on %s:%d", cfg.listen_host, cfg.listen_port)

    stats.update_title()

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    def _on_signal(*_) -> None:
        log.info("Shutdown signal -- stopping")
        stats.log_summary()
        stop.set()

    try:
        loop.add_signal_handler(signal.SIGINT,  _on_signal)
        loop.add_signal_handler(signal.SIGTERM, _on_signal)
    except NotImplementedError:
        pass

    asyncio.create_task(_title_loop(2.0))

    if cfg.stats_interval > 0:
        asyncio.create_task(_stats_loop(cfg.stats_interval))

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
        log.info("Interrupted -- shutting down")
        stats.log_summary()
    finally:
        server.close()


if __name__ == "__main__":
    _print_banner()
    _startup_prompt()

    log.info("WinDivert injector starting")
    w_filter = (
        f"tcp and ("
        f"(ip.SrcAddr == {cfg.interface_ipv4} and ip.DstAddr == {cfg.connect_ip})"
        f" or "
        f"(ip.SrcAddr == {cfg.connect_ip} and ip.DstAddr == {cfg.interface_ipv4})"
        f")"
    )
    injector = FakeTcpInjector(w_filter, active_connections)
    threading.Thread(target=injector.run, daemon=True, name="windivert").start()

    asyncio.run(_serve())
