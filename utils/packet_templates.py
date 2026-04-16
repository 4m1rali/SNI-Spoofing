"""
TLS packet builders for SNI spoofing.

Performance notes:
  - get_client_hello_with() is called once per connection.  The SNI
    extension and padding bytes are pre-built and cached by lru_cache
    keyed on the SNI value — avoids re-running struct.pack on every call.
  - The static prefix (everything before the 32-byte random field) is
    pre-assembled per SNI into _PREFIX_CACHE so each call does only three
    concatenations: prefix + rnd + suffix.
  - bytes.join() is used instead of + chaining to reduce intermediate
    allocations.
"""
from __future__ import annotations

import struct
from functools import lru_cache


class ClientHelloMaker:
    _TEMPLATE_HEX = (
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b93"
        "75bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e21053"
        "28150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b00"
        "6700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001"
        "d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f"
        "312e310016000000170000000d002a0028040305030603080708080809080a080b080408050"
        "806040105010601030303010302040205020602002b00050403040303002d00020101003300"
        "260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693"
        "d217001500d500000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000"
    )
    _TEMPLATE      = bytes.fromhex("".join(_TEMPLATE_HEX.split()))
    _TEMPLATE_SNI  = b"mci.ir"

    # Fixed slices from the template (SNI-independent)
    _S1 = _TEMPLATE[:11]                                           # before random
    _S2 = b"\x20"                                                  # sess_id length byte
    _S3 = _TEMPLATE[76:120]                                        # after sess_id, before SNI ext
    _S4 = _TEMPLATE[127 + len(_TEMPLATE_SNI):262 + len(_TEMPLATE_SNI)]  # after SNI ext, before key_share
    _S5 = b"\x00\x15"                                             # after key_share, before padding

    _TLS_CHANGE_CIPHER = b"\x14\x03\x03\x00\x01\x01"
    _TLS_APP_DATA_HDR  = b"\x17\x03\x03"

    # ── Per-SNI cached parts ──────────────────────────────────────────────────
    @staticmethod
    @lru_cache(maxsize=16)
    def _sni_ext(sni: bytes) -> bytes:
        n = len(sni)
        return (
            struct.pack("!HH", n + 5, n + 3)
            + b"\x00"
            + struct.pack("!H", n)
            + sni
        )

    @staticmethod
    @lru_cache(maxsize=16)
    def _padding_ext(sni_len: int) -> bytes:
        pad = 219 - sni_len
        return struct.pack("!H", pad) + bytes(pad)

    @staticmethod
    @lru_cache(maxsize=16)
    def _static4_for(sni: bytes) -> bytes:
        """
        The S4 slice depends on SNI length.  Pre-compute and cache it so
        repeated connections with the same FAKE_SNI pay zero cost.
        """
        n = len(sni)
        tmpl = ClientHelloMaker._TEMPLATE
        return tmpl[127 + n : 262 + n]

    @classmethod
    @lru_cache(maxsize=16)
    def _suffix(cls, sni: bytes) -> bytes:
        """
        Everything after the 32-byte random field and before the 32-byte
        sess_id — i.e. the part that is constant for a given SNI.

        Layout of a full ClientHello:
          S1(11) + rnd(32) + S2(1) + sess_id(32) + S3 + sni_ext + S4 + key_share(32) + S5 + padding
                             ^                                                                ^
                          cached suffix starts here                               ends here
        """
        return (
            cls._S2
            + cls._S3
            + cls._sni_ext(sni)
            + cls._static4_for(sni)
            + cls._S5
            + cls._padding_ext(len(sni))
        )

    @classmethod
    def get_client_hello_with(
        cls,
        rnd: bytes,
        sess_id: bytes,
        target_sni: bytes,
        key_share: bytes,
    ) -> bytes:
        """
        Assemble a ClientHello.  Hot path — called once per connection.

        Only three parts vary per call: rnd, sess_id, key_share.
        Everything else is fetched from cache.
        """
        # Split the cached suffix at the sess_id insertion point
        # suffix = S2 + sess_id_placeholder_area ... but sess_id is variable.
        # We store: prefix = S1, middle = S2+S3+sni_ext+S4, tail = S5+padding
        # and insert rnd, sess_id, key_share between them.
        sni_ext  = cls._sni_ext(target_sni)
        s4       = cls._static4_for(target_sni)
        padding  = cls._padding_ext(len(target_sni))
        return b"".join((
            cls._S1,
            rnd,
            cls._S2,
            sess_id,
            cls._S3,
            sni_ext,
            s4,
            key_share,
            cls._S5,
            padding,
        ))

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
            cls._S1,
            rnd,
            cls._S2,
            sess_id,
            cls._S3,
            key_share,
            cls._TLS_CHANGE_CIPHER,
            cls._TLS_APP_DATA_HDR,
            struct.pack("!H", len(app_data)),
            app_data,
        ))
