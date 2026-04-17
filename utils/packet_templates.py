from __future__ import annotations

import os
import struct

from utils.fingerprint import BrowserProfile, build_client_hello, get_profile


class ClientHelloMaker:
    """
    Builds a realistic TLS ClientHello using a browser fingerprint profile.

    Each call produces a unique packet with:
    - Fresh 32-byte random, session_id, and key_share (CSPRNG)
    - GREASE values in cipher suites and extensions (RFC 8701)
    - Correct extension ordering per browser profile
    - Padding jitter (+/- 12 bytes) to avoid size fingerprinting
    - ALPN, compress_cert, psk_modes matching the chosen browser
    """

    _TLS_CHANGE_CIPHER = b"\x14\x03\x03\x00\x01\x01"
    _TLS_APP_DATA_HDR  = b"\x17\x03\x03"

    @classmethod
    def get_client_hello_with(
        cls,
        rnd: bytes,
        sess_id: bytes,
        target_sni: bytes,
        key_share: bytes,
        profile: BrowserProfile | None = None,
    ) -> bytes:
        if profile is None:
            profile = get_profile("chrome")
        return build_client_hello(profile, target_sni)

    @classmethod
    def get_client_response_with(cls, app_data: bytes) -> bytes:
        return b"".join((
            cls._TLS_CHANGE_CIPHER,
            cls._TLS_APP_DATA_HDR,
            struct.pack("!H", len(app_data)),
            app_data,
        ))


class ServerHelloMaker:
    _TEMPLATE_HEX = (
        "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1d"
        "ae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbd"
        "e406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5"
        "b0e4eb188ebd30193271e8171152eb4e"
    )
    _TEMPLATE          = bytes.fromhex("".join(_TEMPLATE_HEX.split()))
    _S1                = _TEMPLATE[:11]
    _S2                = b"\x20"
    _S3                = _TEMPLATE[76:95]
    _TLS_CHANGE_CIPHER = b"\x14\x03\x03\x00\x01\x01"
    _TLS_APP_DATA_HDR  = b"\x17\x03\x03"

    @classmethod
    def get_server_hello_with(
        cls,
        rnd: bytes,
        sess_id: bytes,
        key_share: bytes,
        app_data: bytes,
    ) -> bytes:
        return b"".join((
            cls._S1, rnd, cls._S2, sess_id, cls._S3, key_share,
            cls._TLS_CHANGE_CIPHER, cls._TLS_APP_DATA_HDR,
            struct.pack("!H", len(app_data)), app_data,
        ))
