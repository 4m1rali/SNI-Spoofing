from __future__ import annotations

import struct

_TLS_HANDSHAKE       = 0x16
_TLS_CLIENT_HELLO    = 0x01
_EXT_SERVER_NAME     = 0x0000
_NAME_HOST           = 0x00


def extract_sni(data: bytes) -> str | None:
    """
    Extract the SNI hostname from a TLS ClientHello.

    Handles:
    - TLS 1.0 / 1.2 / 1.3 records
    - Variable-length session IDs, cipher suites, compression methods
    - Multiple extensions in any order
    - International domain names (decoded as UTF-8 with fallback to ASCII)
    - Partial records (returns None gracefully)

    Returns the hostname string or None if not found / not parseable.
    """
    try:
        return _parse(data)
    except Exception:
        return None


def _parse(data: bytes) -> str | None:
    if len(data) < 5:
        return None

    if data[0] != _TLS_HANDSHAKE:
        return None

    record_len = struct.unpack_from("!H", data, 3)[0]
    if len(data) < 5 + record_len:
        return None

    pos = 5
    if data[pos] != _TLS_CLIENT_HELLO:
        return None

    hs_len = int.from_bytes(data[pos + 1 : pos + 4], "big")
    pos += 4
    end = pos + hs_len
    if len(data) < end:
        return None

    pos += 2 + 32
    if pos >= end:
        return None

    sid_len = data[pos]
    pos += 1 + sid_len
    if pos + 2 > end:
        return None

    cs_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2 + cs_len
    if pos + 1 > end:
        return None

    cm_len = data[pos]
    pos += 1 + cm_len
    if pos + 2 > end:
        return None

    ext_total = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    ext_end = pos + ext_total
    if len(data) < ext_end:
        ext_end = len(data)

    while pos + 4 <= ext_end:
        ext_type = struct.unpack_from("!H", data, pos)[0]
        ext_len  = struct.unpack_from("!H", data, pos + 2)[0]
        pos += 4
        if ext_type == _EXT_SERVER_NAME:
            result = _parse_sni_ext(data, pos, pos + ext_len)
            if result:
                return result
        pos += ext_len

    return None


def _parse_sni_ext(data: bytes, start: int, end: int) -> str | None:
    pos = start
    if pos + 2 > end:
        return None

    list_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    list_end = min(pos + list_len, end)

    while pos + 3 <= list_end:
        name_type = data[pos]
        name_len  = struct.unpack_from("!H", data, pos + 1)[0]
        pos += 3
        if name_type == _NAME_HOST and pos + name_len <= list_end:
            raw = data[pos : pos + name_len]
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    return raw.decode("ascii", errors="replace")
                except Exception:
                    return None
        pos += name_len

    return None
