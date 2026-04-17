from __future__ import annotations

import os
import random
import struct
from dataclasses import dataclass
from typing import Optional


def _grease() -> bytes:
    choices = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
        0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ]
    return struct.pack("!H", random.choice(choices))


@dataclass
class BrowserProfile:
    name:             str
    cipher_suites:    list[bytes]
    supported_groups: bytes
    sig_algs:         bytes
    alpn_protos:      list[bytes]
    tls_versions:     bytes
    psk_modes:        bytes
    compress_cert:    Optional[bytes] = None


def _ext(type_id: int, data: bytes) -> bytes:
    return struct.pack("!HH", type_id, len(data)) + data


def _sni_ext(sni: bytes) -> bytes:
    n    = len(sni)
    body = b"\x00" + struct.pack("!H", n) + sni
    list_body = struct.pack("!H", len(body)) + body
    return _ext(0x0000, list_body)


def _alpn_ext(protos: list[bytes]) -> bytes:
    proto_list = b"".join(struct.pack("!B", len(p)) + p for p in protos)
    return _ext(0x0010, struct.pack("!H", len(proto_list)) + proto_list)


def _key_share_ext() -> tuple[bytes, bytes]:
    pub = os.urandom(32)
    ks_entry = b"\x00\x1d" + struct.pack("!H", 32) + pub
    body = struct.pack("!H", len(ks_entry)) + ks_entry
    return _ext(0x0033, body), pub


def build_client_hello(
    profile: BrowserProfile,
    sni: bytes,
) -> bytes:
    rnd      = os.urandom(32)
    sess_id  = os.urandom(32)
    ks_ext, _pub = _key_share_ext()

    grease_cs = _grease()
    cs_list   = [grease_cs] + profile.cipher_suites + [b"\x00\xff"]
    cs_body   = b"".join(cs_list)
    cs_field  = struct.pack("!H", len(cs_body)) + cs_body

    compress  = b"\x01\x00"

    exts = []
    exts.append(_grease_ext())
    exts.append(_sni_ext(sni))
    exts.append(_ext(0x0017, b""))
    exts.append(_ext(0xFF01, b"\x00"))
    exts.append(_ext(0x000A, profile.supported_groups))
    exts.append(_ext(0x000B, b"\x01\x00"))
    exts.append(_ext(0x0023, b""))
    exts.append(_alpn_ext(profile.alpn_protos))
    exts.append(_ext(0x0016, b""))
    exts.append(_ext(0x0005, b"\x01\x00\x00\x00\x00"))
    exts.append(_ext(0x000D, profile.sig_algs))
    exts.append(_ext(0x0012, b""))
    exts.append(ks_ext)
    exts.append(_ext(0x002B, profile.tls_versions))
    exts.append(_ext(0x002D, profile.psk_modes))
    if profile.compress_cert:
        exts.append(_ext(0x001B, profile.compress_cert))

    pad_needed = _calc_padding(exts)
    if pad_needed > 0:
        exts.append(_ext(0x0015, bytes(pad_needed)))

    ext_body  = b"".join(exts)
    ext_field = struct.pack("!H", len(ext_body)) + ext_body

    hello_body = (
        b"\x03\x03"
        + rnd
        + struct.pack("!B", 32) + sess_id
        + cs_field
        + compress
        + ext_field
    )

    hs_header = b"\x01" + (len(hello_body)).to_bytes(3, "big")
    record_body = hs_header + hello_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_body)) + record_body

    return record


def _grease_ext() -> bytes:
    g = struct.unpack("!H", _grease())[0]
    return _ext(g, b"\x00")


def _calc_padding(exts: list[bytes]) -> int:
    total = sum(len(e) for e in exts) + 2
    jitter = random.randint(-12, 12)
    target = 512 + jitter
    needed = target - total - 4
    return max(0, needed)


CHROME_124 = BrowserProfile(
    name = "Chrome/124",
    cipher_suites = [
        b"\x13\x01", b"\x13\x02", b"\x13\x03",
        b"\xc0\x2b", b"\xc0\x2f", b"\xc0\x2c", b"\xc0\x30",
        b"\xcc\xa9", b"\xcc\xa8",
        b"\xc0\x13", b"\xc0\x14",
        b"\x00\x9c", b"\x00\x9d",
        b"\x00\x2f", b"\x00\x35",
    ],
    supported_groups = b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19",
    sig_algs = (
        b"\x00\x12"
        b"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01"
        b"\x08\x06\x06\x01\x02\x01"
    ),
    alpn_protos  = [b"h2", b"http/1.1"],
    tls_versions = b"\x04\x03\x04\x03\x03",
    psk_modes    = b"\x01\x01",
    compress_cert = b"\x00\x02\x00\x02",
)

FIREFOX_125 = BrowserProfile(
    name = "Firefox/125",
    cipher_suites = [
        b"\x13\x01", b"\x13\x03", b"\x13\x02",
        b"\xc0\x2b", b"\xc0\x2f", b"\xcc\xa9", b"\xcc\xa8",
        b"\xc0\x2c", b"\xc0\x30",
        b"\xc0\x0a", b"\xc0\x09", b"\xc0\x13", b"\xc0\x14",
        b"\x00\x33", b"\x00\x39", b"\x00\x2f", b"\x00\x35",
    ],
    supported_groups = b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19",
    sig_algs = (
        b"\x00\x1a"
        b"\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06"
        b"\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01\x03\x03\x03\x01"
    ),
    alpn_protos  = [b"h2", b"http/1.1"],
    tls_versions = b"\x04\x03\x04\x03\x03",
    psk_modes    = b"\x01\x01",
)

SAFARI_17 = BrowserProfile(
    name = "Safari/17",
    cipher_suites = [
        b"\xc0\x2c", b"\xc0\x2b", b"\xc0\x30", b"\xc0\x2f",
        b"\x13\x02", b"\x13\x03", b"\x13\x01",
        b"\xcc\xa9", b"\xcc\xa8",
        b"\xc0\x14", b"\xc0\x13",
        b"\x00\x9d", b"\x00\x9c",
        b"\x00\x35", b"\x00\x2f",
    ],
    supported_groups = b"\x00\x06\x00\x1d\x00\x17\x00\x18",
    sig_algs = (
        b"\x00\x10"
        b"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01"
        b"\x08\x06\x06\x01"
    ),
    alpn_protos  = [b"h2", b"http/1.1"],
    tls_versions = b"\x04\x03\x04\x03\x03",
    psk_modes    = b"\x01\x01",
)

EDGE_124 = BrowserProfile(
    name = "Edge/124",
    cipher_suites    = CHROME_124.cipher_suites,
    supported_groups = b"\x00\x0a\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00",
    sig_algs         = CHROME_124.sig_algs,
    alpn_protos      = [b"h2", b"http/1.1"],
    tls_versions     = CHROME_124.tls_versions,
    psk_modes        = CHROME_124.psk_modes,
    compress_cert    = CHROME_124.compress_cert,
)

PROFILES: dict[str, BrowserProfile] = {
    "chrome":  CHROME_124,
    "firefox": FIREFOX_125,
    "safari":  SAFARI_17,
    "edge":    EDGE_124,
    "random":  CHROME_124,
}


def get_profile(name: str) -> BrowserProfile:
    name = name.lower().strip()
    if name == "random":
        return random.choice([CHROME_124, FIREFOX_125, SAFARI_17, EDGE_124])
    return PROFILES.get(name, CHROME_124)
