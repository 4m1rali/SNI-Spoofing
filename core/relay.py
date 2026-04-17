from __future__ import annotations

import asyncio
import collections
import os
import socket
import sys
import time

from core.config import Config
from core.stats import stats
from bypass.fake_tcp import FakeInjectiveConnection
from logger_setup import get_logger
from utils.packet_templates import ClientHelloMaker
from utils.sni_extractor import extract_sni

log = get_logger("relay")

active_connections: dict[tuple, FakeInjectiveConnection] = {}

_rate_buckets: dict[str, collections.deque] = {}


def _apply_keepalive(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  11)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,   1)


def _close(*socks: socket.socket) -> None:
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


def _remove_conn(conn: FakeInjectiveConnection) -> None:
    conn.monitor = False
    active_connections.pop(conn.id, None)


def _check_rate_limit(ip: str, limit: int) -> bool:
    now = time.monotonic()
    if ip not in _rate_buckets:
        _rate_buckets[ip] = collections.deque()
    bucket = _rate_buckets[ip]
    cutoff = now - 1.0
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= limit:
        return False
    bucket.append(now)
    return True


async def _pipe(
    src: socket.socket,
    dst: socket.socket,
    peer: asyncio.Task,
    label: str,
    buf: int,
    byte_counter: str,
    idle_timeout: int = 0,
) -> None:
    loop  = asyncio.get_running_loop()
    _recv = loop.sock_recv
    _send = loop.sock_sendall
    add   = getattr(stats, f"add_{byte_counter}")
    try:
        while True:
            try:
                if idle_timeout > 0:
                    data = await asyncio.wait_for(_recv(src, buf), timeout=idle_timeout)
                else:
                    data = await _recv(src, buf)
            except asyncio.TimeoutError:
                log.debug("[%s] idle timeout (%ds)", label, idle_timeout)
                break
            except OSError as exc:
                log.debug("[%s] recv: %s", label, exc)
                break
            if not data:
                log.debug("[%s] EOF", label)
                break
            add(len(data))
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


async def _pipe_sni(
    src: socket.socket,
    dst: socket.socket,
    peer: asyncio.Task,
    label: str,
    buf: int,
    addr: tuple,
    idle_timeout: int = 0,
) -> None:
    loop  = asyncio.get_running_loop()
    _recv = loop.sock_recv
    _send = loop.sock_sendall

    accumulated = b""
    sni_found   = False

    try:
        while not sni_found:
            try:
                if idle_timeout > 0:
                    chunk = await asyncio.wait_for(_recv(src, buf), timeout=idle_timeout)
                else:
                    chunk = await _recv(src, buf)
            except asyncio.TimeoutError:
                log.debug("[%s] idle timeout waiting for SNI", label)
                return
            except OSError as exc:
                log.debug("[%s] recv: %s", label, exc)
                return
            if not chunk:
                log.debug("[%s] EOF before SNI", label)
                return

            accumulated += chunk
            sni = extract_sni(accumulated)
            if sni:
                log.info("SNI  %-40s  from %s", sni, addr[0])
                stats.record_sni(sni)
                sni_found = True
            elif len(accumulated) > 16384:
                log.debug("SNI not found after %d bytes  peer=%s", len(accumulated), addr)
                sni_found = True

        stats.add_bytes_in(len(accumulated))
        try:
            await _send(dst, accumulated)
        except OSError as exc:
            log.debug("[%s] send: %s", label, exc)
            return

        while True:
            try:
                if idle_timeout > 0:
                    data = await asyncio.wait_for(_recv(src, buf), timeout=idle_timeout)
                else:
                    data = await _recv(src, buf)
            except asyncio.TimeoutError:
                log.debug("[%s] idle timeout", label)
                break
            except OSError as exc:
                log.debug("[%s] recv: %s", label, exc)
                break
            if not data:
                log.debug("[%s] EOF", label)
                break
            stats.add_bytes_in(len(data))
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


async def handle(
    incoming: socket.socket,
    addr: tuple,
    cfg: Config,
) -> None:
    ip = addr[0]

    if cfg.rate_limit and not _check_rate_limit(ip, cfg.rate_limit):
        log.warning("Rate limit hit  %s  (limit=%d/s)", ip, cfg.rate_limit)
        _close(incoming)
        return

    if cfg.max_connections and stats.active >= cfg.max_connections:
        log.warning("Connection limit reached (%d) -- rejecting %s:%d",
                    cfg.max_connections, ip, addr[1])
        _close(incoming)
        return

    stats.new_connection()
    stats.record_ip(ip)
    log.info("CONN  %s:%d  [active=%d  total=%d]",
             ip, addr[1], stats.active, stats.total)
    loop = asyncio.get_running_loop()

    try:
        from utils.fingerprint import get_profile
        profile   = get_profile(cfg.browser_profile)
        fake_data = ClientHelloMaker.get_client_hello_with(
            os.urandom(32), os.urandom(32), cfg.fake_sni, os.urandom(32),
            profile=profile,
        )
        log.debug("Using browser profile: %s", profile.name)

        out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        out.setblocking(False)
        out.bind((cfg.interface_ipv4, 0))
        _apply_keepalive(out)
        src_port = out.getsockname()[1]
        log.debug("Outgoing socket %s:%d", cfg.interface_ipv4, src_port)

        conn = FakeInjectiveConnection(
            out, cfg.interface_ipv4, cfg.connect_ip,
            src_port, cfg.connect_port,
            fake_data, cfg.bypass_method, incoming,
            fake_delay_ms   = cfg.fake_delay_ms,
            ttl_spoof       = cfg.ttl_spoof,
            browser_profile = cfg.browser_profile,
        )
        active_connections[conn.id] = conn

        try:
            await asyncio.wait_for(
                loop.sock_connect(out, (cfg.connect_ip, cfg.connect_port)),
                timeout=cfg.connect_timeout,
            )
            log.debug("TCP connected to %s:%d", cfg.connect_ip, cfg.connect_port)
        except (OSError, asyncio.TimeoutError) as exc:
            log.warning("TCP connect failed %s:%d -- %s",
                        cfg.connect_ip, cfg.connect_port, exc)
            _remove_conn(conn)
            _close(out, incoming)
            stats.connection_failed()
            return

        try:
            await asyncio.wait_for(conn.t2a_event.wait(), timeout=cfg.bypass_timeout)
            msg = conn.t2a_msg
            if msg == "unexpected_close":
                raise ValueError("unexpected_close")
            if msg == "fake_data_ack_recv":
                log.debug("Bypass handshake OK  %s:%d", ip, addr[1])
            else:
                log.error("Unknown t2a_msg: %s", msg)
                sys.exit("impossible t2a msg!")
        except (asyncio.TimeoutError, ValueError) as exc:
            log.warning("Bypass failed (%s) -- dropping %s:%d", exc, ip, addr[1])
            _remove_conn(conn)
            _close(out, incoming)
            stats.connection_failed()
            return

        _remove_conn(conn)
        stats.relay_started()
        log.info("RELAY %s:%d  <->  %s:%d",
                 ip, addr[1], cfg.connect_ip, cfg.connect_port)

        buf     = cfg.recv_buffer
        idle    = cfg.idle_timeout
        oti     = asyncio.create_task(
            _pipe(out, incoming, asyncio.current_task(), "out->in", buf, "bytes_out", idle)
        )
        if cfg.log_client_sni:
            await _pipe_sni(incoming, out, oti, "in->out", buf, addr, idle)
        else:
            await _pipe(incoming, out, oti, "in->out", buf, "bytes_in", idle)

        log.info("CLOSE %s:%d", ip, addr[1])

    except Exception:
        log.exception("Unhandled error in handle() for %s", addr)
        sys.exit("handle should not raise")
    finally:
        stats.connection_done()
        stats.update_title()
