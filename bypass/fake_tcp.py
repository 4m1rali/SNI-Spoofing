"""
FakeTcpInjector — WinDivert packet injector implementing the wrong_seq
SNI bypass technique.

Performance notes:
  - A module-level ThreadPoolExecutor replaces per-connection Thread()
    spawning, eliminating thread creation overhead for every connection.
  - Frequently accessed connection fields are read into locals before the
    with-block to reduce attribute lookups inside the lock.
  - _u32 result for (syn_seq + 1) is computed once and reused for both
    seq and ack validation in the inbound path.
"""
from __future__ import annotations

import asyncio
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from pydivert.packet import Packet

from bypass.injector import TcpInjector
from core.connection import MonitorConnection
from logger_setup import get_logger

log = get_logger("fake_tcp")

# Shared pool — avoids spawning a new OS thread for every fake-send
_THREAD_POOL = ThreadPoolExecutor(max_workers=32, thread_name_prefix="fake-send")


# ── TCP flag helpers ──────────────────────────────────────────────────────────
def _is_syn(p: Packet) -> bool:
    t = p.tcp
    return t.syn and not t.ack and not t.rst and not t.fin and len(t.payload) == 0

def _is_syn_ack(p: Packet) -> bool:
    t = p.tcp
    return t.syn and t.ack and not t.rst and not t.fin and len(t.payload) == 0

def _is_pure_ack(p: Packet) -> bool:
    t = p.tcp
    return t.ack and not t.syn and not t.rst and not t.fin and len(t.payload) == 0

def _u32(n: int) -> int:
    return n & 0xFFFFFFFF


# ── Connection state ──────────────────────────────────────────────────────────
class FakeInjectiveConnection(MonitorConnection):
    __slots__ = (
        "fake_data", "sch_fake_sent", "fake_sent",
        "t2a_event", "t2a_msg", "bypass_method",
        "peer_sock", "running_loop",
    )

    def __init__(
        self,
        sock: socket.socket,
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
        fake_data: bytes,
        bypass_method: str,
        peer_sock: socket.socket,
    ) -> None:
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data     = fake_data
        self.sch_fake_sent = False
        self.fake_sent     = False
        self.t2a_event     = asyncio.Event()
        self.t2a_msg       = ""
        self.bypass_method = bypass_method
        self.peer_sock     = peer_sock
        self.running_loop  = asyncio.get_running_loop()


# ── Injector ──────────────────────────────────────────────────────────────────
class FakeTcpInjector(TcpInjector):

    def __init__(
        self,
        w_filter: str,
        connections: dict[tuple, FakeInjectiveConnection],
    ) -> None:
        super().__init__(w_filter)
        self.connections = connections

    # ── Fake packet injection ─────────────────────────────────────────────────
    def _send_fake(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        """Mutate packet into fake ClientHello and inject with wrong seq."""
        fake_data            = conn.fake_data          # local — avoids repeated attr lookup
        packet.tcp.psh       = True
        packet.ip.packet_len = packet.ip.packet_len + len(fake_data)
        packet.tcp.payload   = fake_data
        if packet.ipv4:
            packet.ipv4.ident = _u32(packet.ipv4.ident + 1)
        packet.tcp.seq_num = _u32(conn.syn_seq + 1 - len(fake_data))
        conn.fake_sent = True
        self.w.send(packet, True)

    def _fake_send_task(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        """Submitted to thread pool — waits 1 ms then injects fake packet."""
        time.sleep(0.001)
        lock = conn.thread_lock
        with lock:
            if not conn.monitor:
                return
            if conn.bypass_method == "wrong_seq":
                self._send_fake(packet, conn)
            else:
                sys.exit(f"Unsupported bypass method: {conn.bypass_method!r}")

    # ── Error handling ────────────────────────────────────────────────────────
    def _unexpected(self, packet: Packet, conn: FakeInjectiveConnection, reason: str) -> None:
        log.warning(
            "Unexpected packet [%s:%d → %s:%d]: %s",
            conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, reason,
        )
        log.debug("Packet: %s", packet)
        conn.sock.close()
        conn.peer_sock.close()
        conn.monitor = False
        conn.t2a_msg = "unexpected_close"
        conn.running_loop.call_soon_threadsafe(conn.t2a_event.set)
        self.w.send(packet, False)

    # ── Inbound state machine ─────────────────────────────────────────────────
    def _on_inbound(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        syn_seq = conn.syn_seq
        if syn_seq == -1:
            self._unexpected(packet, conn, "inbound packet before SYN sent")
            return

        seq          = packet.tcp.seq_num
        ack          = packet.tcp.ack_num
        expected_ack = _u32(syn_seq + 1)   # computed once, used twice below

        if _is_syn_ack(packet):
            syn_ack_seq = conn.syn_ack_seq
            if syn_ack_seq != -1 and syn_ack_seq != seq:
                self._unexpected(packet, conn,
                    f"SYN-ACK seq changed: got {seq}, had {syn_ack_seq}")
                return
            if ack != expected_ack:
                self._unexpected(packet, conn,
                    f"SYN-ACK ack mismatch: got {ack}, want {expected_ack}")
                return
            conn.syn_ack_seq = seq
            self.w.send(packet, False)
            return

        if _is_pure_ack(packet) and conn.fake_sent:
            syn_ack_seq = conn.syn_ack_seq
            if syn_ack_seq == -1 or _u32(syn_ack_seq + 1) != seq:
                self._unexpected(packet, conn,
                    f"ACK seq mismatch: got {seq}, want {_u32(syn_ack_seq + 1)}")
                return
            if ack != expected_ack:
                self._unexpected(packet, conn,
                    f"ACK ack mismatch: got {ack}, want {expected_ack}")
                return
            conn.monitor = False
            conn.t2a_msg = "fake_data_ack_recv"
            conn.running_loop.call_soon_threadsafe(conn.t2a_event.set)
            return

        self._unexpected(packet, conn, "unexpected inbound packet")

    # ── Outbound state machine ────────────────────────────────────────────────
    def _on_outbound(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        if conn.sch_fake_sent:
            self._unexpected(packet, conn, "outbound packet after fake already scheduled")
            return

        seq = packet.tcp.seq_num
        ack = packet.tcp.ack_num

        if _is_syn(packet):
            if ack != 0:
                self._unexpected(packet, conn, "SYN has non-zero ack_num")
                return
            syn_seq = conn.syn_seq
            if syn_seq != -1 and syn_seq != seq:
                self._unexpected(packet, conn,
                    f"SYN seq changed: got {seq}, had {syn_seq}")
                return
            conn.syn_seq = seq
            self.w.send(packet, False)
            return

        if _is_pure_ack(packet):
            syn_seq = conn.syn_seq
            if syn_seq == -1 or _u32(syn_seq + 1) != seq:
                self._unexpected(packet, conn,
                    f"ACK seq mismatch: got {seq}, want {_u32(syn_seq + 1)}")
                return
            syn_ack_seq = conn.syn_ack_seq
            if syn_ack_seq == -1 or ack != _u32(syn_ack_seq + 1):
                self._unexpected(packet, conn,
                    f"ACK ack mismatch: got {ack}, want {_u32(syn_ack_seq + 1)}")
                return
            self.w.send(packet, False)
            conn.sch_fake_sent = True
            _THREAD_POOL.submit(self._fake_send_task, packet, conn)
            return

        self._unexpected(packet, conn, "unexpected outbound packet")

    # ── Dispatcher ────────────────────────────────────────────────────────────
    def inject(self, packet: Packet) -> None:
        conns = self.connections   # local ref — avoids self lookup in hot path
        w     = self.w

        if packet.is_inbound:
            c_id = (
                packet.ip.dst_addr, packet.tcp.dst_port,
                packet.ip.src_addr, packet.tcp.src_port,
            )
            conn = conns.get(c_id)
            if conn is None:
                w.send(packet, False)
                return
            with conn.thread_lock:
                if conn.monitor:
                    self._on_inbound(packet, conn)
                else:
                    w.send(packet, False)

        elif packet.is_outbound:
            c_id = (
                packet.ip.src_addr, packet.tcp.src_port,
                packet.ip.dst_addr, packet.tcp.dst_port,
            )
            conn = conns.get(c_id)
            if conn is None:
                w.send(packet, False)
                return
            with conn.thread_lock:
                if conn.monitor:
                    self._on_outbound(packet, conn)
                else:
                    w.send(packet, False)

        else:
            log.error("Packet with impossible direction — dropping")
            sys.exit("impossible direction!")
