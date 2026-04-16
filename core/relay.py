"""
Relay — async TCP forwarding between client and target server.

Performance notes:
  - sock_recv / sock_sendall are cached as locals to avoid per-call attribute
    lookup on the event loop object inside the hot path.
  - SNI logging is only wired on the client→server direction and only when
    enabled in config; the flag is read once outside the loop.
  - TCP_NODELAY is set on both sockets to eliminate Nagle-algorithm latency
    on small TLS record writes.
  - Socket close + peer cancel order is chosen to avoid WinError 6.
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys

from core.config import Config
from core.stats import stats
from bypass.fake_tcp import FakeInjectiveConnection
from logger_setup import get_logger
from utils.packet_templates import ClientHelloMaker
from utils.sni_extractor import extract_sni

log = get_logger("relay")

# Registry of active bypass connections — shared with WinDivert thread
active_connections: dict[tuple, FakeInjectiveConnection] = {}

_RECV_BUF = 65536


# ── Socket helpers ────────────────────────────────────────────────────────────
def _apply_keepalive(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  11)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
    # Disable Nagle — send data immediately without waiting to fill a segment.
    # Critical for low-latency TLS record delivery.
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def _close(*socks: socket.socket) -> None:
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


def _remove_conn(conn: FakeInjectiveConnection) -> None:
    conn.monitor = False
    active_connections.pop(conn.id, None)


# ── Relay pipes ───────────────────────────────────────────────────────────────
async def _pipe(
    src: socket.socket,
    dst: socket.socket,
    peer: asyncio.Task,
    label: str,
) -> None:
    """Plain relay — forward bytes from src → dst with no extra logic."""
    loop    = asyncio.get_running_loop()
    _recv   = loop.sock_recv       # cache to avoid per-call attr lookup
    _send   = loop.sock_sendall
    try:
        while True:
            try:
                data = await _recv(src, _RECV_BUF)
            except OSError as exc:
                log.debug("[%s] recv: %s", label, exc)
                break
            if not data:
                log.debug("[%s] EOF", label)
                break
            try:
                await _send(dst, data)
            except OSError as exc:
                log.debug("[%s] send: %s", label, exc)
                break
    finally:
        _close(src, dst)
        if not peer.done():
            peer.cancel()
            try:
                await asyncio.shield(peer)
            except (asyncio.CancelledError, Exception):
                pass


async def _pipe_with_sni_log(
    src: socket.socket,
    dst: socket.socket,
    peer: asyncio.Task,
    label: str,
    addr: tuple,
) -> None:
    """
    Relay with SNI extraction on the first chunk only.
    Used for the client→server direction when LOG_CLIENT_SNI is enabled.
    After the first chunk, falls through to the same tight loop as _pipe.
    """
    loop    = asyncio.get_running_loop()
    _recv   = loop.sock_recv
    _send   = loop.sock_sendall
    try:
        # ── First chunk — parse SNI then continue as normal ───────────────────
        try:
            data = await _recv(src, _RECV_BUF)
        except OSError as exc:
            log.debug("[%s] recv: %s", label, exc)
            return
        if not data:
            log.debug("[%s] EOF on first chunk", label)
            return

        sni = extract_sni(data)
        if sni:
            log.info("Client SNI: %-40s  peer=%s", sni, addr)
        else:
            log.debug("No SNI in first chunk  peer=%s", addr)

        try:
            await _send(dst, data)
        except OSError as exc:
            log.debug("[%s] send: %s", label, exc)
            return

        # ── Remaining chunks — tight loop, no SNI check ───────────────────────
        while True:
            try:
                data = await _recv(src, _RECV_BUF)
            except OSError as exc:
                log.debug("[%s] recv: %s", label, exc)
                break
            if not data:
                log.debug("[%s] EOF", label)
                break
            try:
                await _send(dst, data)
            except OSError as exc:
                log.debug("[%s] send: %s", label, exc)
                break
    finally:
        _close(src, dst)
        if not peer.done():
            peer.cancel()
            try:
                await asyncio.shield(peer)
            except (asyncio.CancelledError, Exception):
                pass


# ── Full connection handler ───────────────────────────────────────────────────
async def handle(
    incoming: socket.socket,
    addr: tuple,
    cfg: Config,
) -> None:
    stats.new_connection()
    log.info("New connection from %s  [active=%d]", addr, stats.active)
    loop = asyncio.get_running_loop()

    try:
        fake_data = ClientHelloMaker.get_client_hello_with(
            os.urandom(32), os.urandom(32), cfg.fake_sni, os.urandom(32)
        )

        out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        out.setblocking(False)
        out.bind((cfg.interface_ipv4, 0))
        _apply_keepalive(out)
        src_port = out.getsockname()[1]
        log.debug("Outgoing socket bound to %s:%d", cfg.interface_ipv4, src_port)

        conn = FakeInjectiveConnection(
            out, cfg.interface_ipv4, cfg.connect_ip,
            src_port, cfg.connect_port,
            fake_data, cfg.bypass_method, incoming,
        )
        active_connections[conn.id] = conn

        # ── TCP connect ───────────────────────────────────────────────────────
        try:
            await loop.sock_connect(out, (cfg.connect_ip, cfg.connect_port))
            log.debug("Connected to %s:%d", cfg.connect_ip, cfg.connect_port)
        except OSError as exc:
            log.warning("Connect failed %s:%d — %s", cfg.connect_ip, cfg.connect_port, exc)
            _remove_conn(conn)
            _close(out, incoming)
            stats.connection_failed()
            return

        # ── Bypass handshake ──────────────────────────────────────────────────
        try:
            await asyncio.wait_for(conn.t2a_event.wait(), timeout=2.0)
            msg = conn.t2a_msg
            if msg == "unexpected_close":
                raise ValueError("unexpected_close")
            if msg == "fake_data_ack_recv":
                log.debug("Bypass handshake complete")
            else:
                log.error("Unknown t2a_msg: %s", msg)
                sys.exit("impossible t2a msg!")
        except (asyncio.TimeoutError, ValueError) as exc:
            log.warning("Bypass failed (%s) — dropping %s", exc, addr)
            _remove_conn(conn)
            _close(out, incoming)
            stats.connection_failed()
            return

        _remove_conn(conn)
        stats.relay_started()
        log.info("Relay started: %s <-> %s:%d", addr, cfg.connect_ip, cfg.connect_port)

        # ── Bidirectional relay ───────────────────────────────────────────────
        # out→in: plain pipe (server data, no SNI parsing needed)
        oti = asyncio.create_task(
            _pipe(out, incoming, asyncio.current_task(), "out→in")
        )
        # in→out: optionally parse SNI from first client chunk
        if cfg.log_client_sni:
            await _pipe_with_sni_log(incoming, out, oti, "in→out", addr)
        else:
            await _pipe(incoming, out, oti, "in→out")

        log.info("Relay closed: %s", addr)

    except Exception:
        log.exception("Unhandled error in handle() for %s", addr)
        sys.exit("handle should not raise")
    finally:
        stats.connection_done()
