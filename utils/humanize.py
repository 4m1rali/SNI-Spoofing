from __future__ import annotations

import math
import os
import random
import struct
import time


def _secure_float() -> float:
    raw = struct.unpack("!Q", os.urandom(8))[0]
    return (raw & 0x000FFFFFFFFFFFFF) / (1 << 52)


def _gauss(mu: float, sigma: float) -> float:
    u1 = max(1e-10, _secure_float())
    u2 = _secure_float()
    z  = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
    return mu + sigma * z


def _weibull(scale: float, shape: float) -> float:
    u = max(1e-10, _secure_float())
    return scale * (-math.log(u)) ** (1.0 / shape)


def human_delay_s(base_ms: float = 1.0) -> float:
    """
    Return a human-like delay in seconds for the fake packet injection.

    Models the time between a TCP ACK completing the handshake and the
    first data packet from a real browser.  Real browsers show:
      - A short Gaussian component (TLS stack processing, ~0.5-3ms)
      - Occasional longer pauses (GC, scheduler, ~5-20ms) modeled by Weibull

    base_ms: the configured FAKE_DELAY_MS value (nominal center)
    """
    sigma   = base_ms * 0.3
    gauss_s = max(0.0, _gauss(base_ms, sigma)) / 1000.0

    if _secure_float() < 0.08:
        extra_s = _weibull(scale=0.008, shape=1.5)
        return gauss_s + extra_s

    return gauss_s


def human_recv_pause_s() -> float:
    """
    Tiny inter-read pause to avoid perfectly uniform recv() timing.
    Real TCP stacks have scheduler jitter of ~0.1-0.5ms.
    Returns 0 most of the time (no sleep needed in hot path).
    """
    if _secure_float() < 0.05:
        return _gauss(0.0002, 0.0001)
    return 0.0


def jitter_bytes(size: int, variance: int = 16) -> int:
    """
    Return a slightly varied buffer size to avoid perfectly uniform
    packet sizes.  Keeps the value within [size//2, size*2].
    """
    delta = int(_gauss(0, variance))
    result = size + delta
    return max(size // 2, min(size * 2, result))
