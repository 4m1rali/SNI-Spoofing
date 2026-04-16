import asyncio
import ctypes
import os
import socket
import sys
import threading
import json
import logging

from logger_setup import setup_logger, get_logger
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

# ── Logging setup ────────────────────────────────────────────────────────────
setup_logger("root", level=logging.DEBUG)
log = get_logger("main")


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


if not is_admin():
    print("=" * 55)
    print("  ERROR: Administrator privileges required!")
    print("=" * 55)
    print()
    print("  WinDivert needs Admin rights to capture packets.")
    print("  Please right-click main.exe and select:")
    print('  "Run as administrator"')
    print()
    input("  Press Enter to exit...")
    sys.exit(1)


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# ── Config ───────────────────────────────────────────────────────────────────
config_path = os.path.join(get_exe_dir(), 'config.json')
with open(config_path, 'r') as f:
    config = json.load(f)

LISTEN_HOST   = config["LISTEN_HOST"]
LISTEN_PORT   = config["LISTEN_PORT"]
FAKE_SNI      = config["FAKE_SNI"].encode()
CONNECT_IP    = config["CONNECT_IP"]
CONNECT_PORT  = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE      = "tls"
BYPASS_METHOD  = "wrong_seq"

log.info("Config loaded — listen=%s:%d  target=%s:%d  iface=%s",
         LISTEN_HOST, LISTEN_PORT, CONNECT_IP, CONNECT_PORT, INTERFACE_IPV4)

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


def _close_sockets(*socks: socket.socket):
    """Close sockets silently, ignoring already-closed handles."""
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


async def relay_main_loop(
    sock_1: socket.socket,
    sock_2: socket.socket,
    peer_task: asyncio.Task,
    first_prefix_data: bytes,
    label: str = "relay",
):
    """
    Forward data from sock_1 → sock_2.

    Normal termination is an EOF (empty read) or any socket error — both are
    handled gracefully without printing tracebacks.  The peer relay task is
    cancelled after the sockets are closed so that the pending overlapped I/O
    on *already-closed* handles is never left in flight (avoids WinError 6).
    """
    loop = asyncio.get_running_loop()
    try:
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
            except OSError as exc:
                log.debug("[%s] sock_recv error: %s", label, exc)
                break

            if not data:
                log.debug("[%s] EOF received — closing relay", label)
                break

            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""

            try:
                await loop.sock_sendall(sock_2, data)
            except OSError as exc:
                log.debug("[%s] sock_sendall error: %s", label, exc)
                break

    finally:
        # Close both sockets *before* cancelling so there are no pending
        # overlapped operations on them when asyncio tries to cancel the future.
        _close_sockets(sock_1, sock_2)
        if not peer_task.done():
            peer_task.cancel()
            try:
                await asyncio.shield(peer_task)
            except (asyncio.CancelledError, Exception):
                pass  # peer task ended — that's fine


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    log.info("New connection from %s", incoming_remote_addr)
    loop = asyncio.get_running_loop()
    try:
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32), FAKE_SNI, os.urandom(32)
            )
        else:
            log.error("Unknown DATA_MODE: %s", DATA_MODE)
            sys.exit("impossible mode!")

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)

        src_port = outgoing_sock.getsockname()[1]
        log.debug("Outgoing socket bound to %s:%d", INTERFACE_IPV4, src_port)

        fake_injective_conn = FakeInjectiveConnection(
            outgoing_sock, INTERFACE_IPV4, CONNECT_IP,
            src_port, CONNECT_PORT, fake_data, BYPASS_METHOD, incoming_sock,
        )
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn

        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
            log.debug("Connected to %s:%d", CONNECT_IP, CONNECT_PORT)
        except OSError as exc:
            log.warning("Connection to %s:%d failed: %s", CONNECT_IP, CONNECT_PORT, exc)
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
            _close_sockets(outgoing_sock, incoming_sock)
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                msg = fake_injective_conn.t2a_msg
                if msg == "unexpected_close":
                    raise ValueError("unexpected_close")
                if msg == "fake_data_ack_recv":
                    log.debug("Bypass handshake complete (fake_data_ack_recv)")
                else:
                    log.error("Unknown t2a_msg: %s", msg)
                    sys.exit("impossible t2a msg!")
            except (asyncio.TimeoutError, ValueError) as exc:
                log.warning("Bypass handshake failed (%s) — dropping connection", exc)
                fake_injective_conn.monitor = False
                del fake_injective_connections[fake_injective_conn.id]
                _close_sockets(outgoing_sock, incoming_sock)
                return
        else:
            log.error("Unknown BYPASS_METHOD: %s", BYPASS_METHOD)
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False
        del fake_injective_connections[fake_injective_conn.id]

        log.info("Relay started: %s <-> %s:%d", incoming_remote_addr, CONNECT_IP, CONNECT_PORT)

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b"", label="outbound→incoming")
        )
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"", label="incoming→outbound")

        log.info("Relay closed: %s", incoming_remote_addr)

    except Exception:
        log.exception("Unhandled exception in handle() for %s", incoming_remote_addr)
        sys.exit("handle should not raise exception")


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
    mother_sock.listen()
    log.info("Listening on %s:%d", LISTEN_HOST, LISTEN_PORT)

    loop = asyncio.get_running_loop()
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  11)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
        asyncio.create_task(handle(incoming_sock, addr))


if __name__ == "__main__":
    w_filter = (
        "tcp and ("
        "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP + ")"
        " or "
        "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4 + ")"
        ")"
    )
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()

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

    asyncio.run(main())
