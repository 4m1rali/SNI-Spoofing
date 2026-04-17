from __future__ import annotations

import asyncio
import os
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from pydivert.packet import Packet

from bypass.injector import TcpInjector
from core.connection import MonitorConnection
from utils.humanize import human_delay_s
from logger_setup import get_logger

log = get_logger("fake_tcp")

_THREAD_POOL = ThreadPoolExecutor(max_workers=64, thread_name_prefix="fake-send")

_bypass_ok   = 0
_bypass_fail = 0

_COMMON_TTLS = [64, 128]


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

def _random_ip_id() -> int:
    return struct.unpack("!H", os.urandom(2))[0]

def _spoof_ttl() -> int:
    base = random.choice(_COMMON_TTLS)
    return base - random.randint(1, 8)


class FakeInjectiveConnection(MonitorConnection):
    __slots__ = (
        "fake_data", "sch_fake_sent", "fake_sent",
        "t2a_event", "t2a_msg", "bypass_method",
        "peer_sock", "running_loop",
        "fake_delay_ms", "syn_time",
        "ttl_spoof", "browser_profile",
    )

    def __init__(
        self,
        sock: socket.socket,
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
        fake_data: bytes,
        bypass_method: str,
        peer_sock: socket.socket,
        fake_delay_ms: float = 1.0,
        ttl_spoof: bool = True,
        browser_profile: str = "chrome",
    ) -> None:
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data       = fake_data
        self.sch_fake_sent   = False
        self.fake_sent       = False
        self.t2a_event       = asyncio.Event()
        self.t2a_msg         = ""
        self.bypass_method   = bypass_method
        self.peer_sock       = peer_sock
        self.running_loop    = asyncio.get_running_loop()
        self.fake_delay_ms   = fake_delay_ms
        self.syn_time        = 0.0
        self.ttl_spoof       = ttl_spoof
        self.browser_profile = browser_profile


class FakeTcpInjector(TcpInjector):

    def __init__(
        self,
        w_filter: str,
        connections: dict[tuple, FakeInjectiveConnection],
    ) -> None:
        super().__init__(w_filter)
        self.connections = connections

    def _send_fake(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        fake_data = conn.fake_data

        packet.tcp.psh       = True
        packet.ip.packet_len = packet.ip.packet_len + len(fake_data)
        packet.tcp.payload   = fake_data

        if packet.ipv4:
            packet.ipv4.ident = _random_ip_id()
            if conn.ttl_spoof:
                packet.ip.ttl = _spoof_ttl()

        packet.tcp.seq_num = _u32(conn.syn_seq + 1 - len(fake_data))
        conn.fake_sent = True
        self.w.send(packet, True)

        log.debug(
            "Fake injected  %s:%d -> %s:%d  seq=%d  len=%d  ttl=%s",
            conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port,
            packet.tcp.seq_num, len(fake_data),
            packet.ip.ttl if conn.ttl_spoof else "default",
        )

    def _fake_send_task(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        delay_s = human_delay_s(conn.fake_delay_ms)

        if conn.syn_time > 0:
            elapsed   = time.monotonic() - conn.syn_time
            remaining = delay_s - elapsed
            if remaining > 0:
                time.sleep(remaining)
        else:
            time.sleep(delay_s)

        with conn.thread_lock:
            if not conn.monitor:
                return
            if conn.bypass_method == "wrong_seq":
                try:
                    self._send_fake(packet, conn)
                except Exception as exc:
                    log.error("Fake send failed  %s:%d: %s",
                              conn.src_ip, conn.src_port, exc)
                    conn.monitor = False
                    conn.t2a_msg = "unexpected_close"
                    conn.running_loop.call_soon_threadsafe(conn.t2a_event.set)
            else:
                log.error("Unsupported bypass method: %r", conn.bypass_method)
                sys.exit(f"Unsupported bypass method: {conn.bypass_method!r}")

    def _signal_done(self, conn: FakeInjectiveConnection, msg: str) -> None:
        global _bypass_ok, _bypass_fail
        conn.monitor = False
        conn.t2a_msg = msg
        if msg == "fake_data_ack_recv":
            _bypass_ok += 1
            log.debug("Bypass OK  %s:%d  (ok=%d fail=%d)",
                      conn.src_ip, conn.src_port, _bypass_ok, _bypass_fail)
        else:
            _bypass_fail += 1
            log.debug("Bypass FAIL  %s:%d  reason=%s  (ok=%d fail=%d)",
                      conn.src_ip, conn.src_port, msg, _bypass_ok, _bypass_fail)
        conn.running_loop.call_soon_threadsafe(conn.t2a_event.set)

    def _unexpected(self, packet: Packet, conn: FakeInjectiveConnection, reason: str) -> None:
        log.warning("Unexpected packet  %s:%d -> %s:%d  %s",
                    conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, reason)
        log.debug(
            "Flags: syn=%s ack=%s rst=%s fin=%s psh=%s  seq=%d ack=%d  payload=%d",
            packet.tcp.syn, packet.tcp.ack, packet.tcp.rst,
            packet.tcp.fin, packet.tcp.psh,
            packet.tcp.seq_num, packet.tcp.ack_num, len(packet.tcp.payload),
        )
        conn.sock.close()
        conn.peer_sock.close()
        self._signal_done(conn, "unexpected_close")
        self.w.send(packet, False)

    def _on_inbound(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        syn_seq = conn.syn_seq
        if syn_seq == -1:
            self._unexpected(packet, conn, "inbound before SYN sent")
            return

        seq          = packet.tcp.seq_num
        ack          = packet.tcp.ack_num
        expected_ack = _u32(syn_seq + 1)

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
            log.debug("SYN-ACK  %s:%d  seq=%d ack=%d",
                      conn.src_ip, conn.src_port, seq, ack)
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
            self._signal_done(conn, "fake_data_ack_recv")
            return

        if _is_pure_ack(packet) and not conn.fake_sent:
            self.w.send(packet, False)
            return

        self._unexpected(packet, conn, "unexpected inbound packet")

    def _on_outbound(self, packet: Packet, conn: FakeInjectiveConnection) -> None:
        if conn.sch_fake_sent:
            self._unexpected(packet, conn, "outbound after fake scheduled")
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
            conn.syn_seq  = seq
            conn.syn_time = time.monotonic()
            log.debug("SYN  %s:%d  seq=%d", conn.src_ip, conn.src_port, seq)
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
            log.debug("ACK  %s:%d  seq=%d ack=%d -- scheduling fake inject",
                      conn.src_ip, conn.src_port, seq, ack)
            self.w.send(packet, False)
            conn.sch_fake_sent = True
            _THREAD_POOL.submit(self._fake_send_task, packet, conn)
            return

        self._unexpected(packet, conn, "unexpected outbound packet")

    def inject(self, packet: Packet) -> None:
        conns = self.connections
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
            log.error("Packet with impossible direction -- dropping")
            sys.exit("impossible direction!")
