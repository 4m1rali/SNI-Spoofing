"""
TLS SNI extractor.

Parses the server_name extension from a raw TLS ClientHello and returns
the hostname string.  Returns None if the data is not a valid ClientHello
or if no SNI extension is present.

This is used to log the *real* destination hostname the client intends to
reach, before we replace the SNI with the spoofed value.
"""
from __future__ import annotations

import struct


# TLS record / handshake constants
_TLS_HANDSHAKE          = 0x16
_TLS_HANDSHAKE_HELLO    = 0x01
_EXT_SERVER_NAME        = 0x0000
_NAME_TYPE_HOST_NAME    = 0x00


def extract_sni(data: bytes) -> str | None:
    """
    Return the SNI hostname from a TLS ClientHello byte string,
    or None if it cannot be parsed.

    Parameters
    ----------
    data : raw bytes received from the client socket (first chunk)
    """
    try:
        return _parse(data)
    except Exception:
        return None


def _parse(data: bytes) -> str | None:
    # ── TLS record header (5 bytes) ───────────────────────────────────────────
    if len(data) < 5:
        return None
    content_type = data[0]
    if content_type != _TLS_HANDSHAKE:
        return None
    # record_version = data[1:3]  # not checked — may be 0x0301 or 0x0303
    record_len = struct.unpack_from("!H", data, 3)[0]
    if len(data) < 5 + record_len:
        return None

    # ── Handshake header (4 bytes) ────────────────────────────────────────────
    pos = 5
    handshake_type = data[pos]
    if handshake_type != _TLS_HANDSHAKE_HELLO:
        return None
    # handshake_len is 3 bytes big-endian
    hs_len = int.from_bytes(data[pos + 1: pos + 4], "big")
    pos += 4
    end = pos + hs_len
    if len(data) < end:
        return None

    # ── ClientHello body ──────────────────────────────────────────────────────
    # legacy_version (2) + random (32)
    pos += 34
    if pos >= end:
        return None

    # session_id
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos + 2 > end:
        return None

    # cipher_suites
    cs_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2 + cs_len
    if pos + 1 > end:
        return None

    # compression_methods
    cm_len = data[pos]
    pos += 1 + cm_len
    if pos + 2 > end:
        return None

    # ── Extensions ────────────────────────────────────────────────────────────
    ext_total = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    ext_end = pos + ext_total
    if len(data) < ext_end:
        return None

    while pos + 4 <= ext_end:
        ext_type = struct.unpack_from("!H", data, pos)[0]
        ext_len  = struct.unpack_from("!H", data, pos + 2)[0]
        pos += 4
        if ext_type == _EXT_SERVER_NAME:
            return _parse_sni_ext(data, pos, pos + ext_len)
        pos += ext_len

    return None


def _parse_sni_ext(data: bytes, start: int, end: int) -> str | None:
    """Parse the server_name extension value and return the host_name."""
    pos = start
    if pos + 2 > end:
        return None
    list_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    list_end = pos + list_len
    if list_end > end:
        return None

    while pos + 3 <= list_end:
        name_type = data[pos]
        name_len  = struct.unpack_from("!H", data, pos + 1)[0]
        pos += 3
        if name_type == _NAME_TYPE_HOST_NAME:
            return data[pos: pos + name_len].decode("ascii", errors="replace")
        pos += name_len

    return None
