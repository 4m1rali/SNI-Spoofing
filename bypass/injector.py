from __future__ import annotations

import sys
import time
from abc import ABC, abstractmethod

from pydivert import WinDivert
from pydivert.packet import Packet
from logger_setup import get_logger

log = get_logger("injector")


class TcpInjector(ABC):
    def __init__(self, w_filter: str) -> None:
        self._filter = w_filter
        self.w: WinDivert = WinDivert(w_filter)
        self._packets_recv  = 0
        self._packets_sent  = 0
        self._errors        = 0

    @abstractmethod
    def inject(self, packet: Packet) -> None: ...

    def run(self) -> None:
        log.info("WinDivert injector started  filter=%r", self._filter)
        backoff = 0.5
        while True:
            try:
                with self.w:
                    backoff = 0.5
                    while True:
                        try:
                            packet = self.w.recv(65536)
                            self._packets_recv += 1
                            self.inject(packet)
                        except Exception as exc:
                            self._errors += 1
                            log.error(
                                "Injector recv/inject error #%d: %s",
                                self._errors, exc, exc_info=True,
                            )
            except Exception as exc:
                self._errors += 1
                log.error(
                    "WinDivert handle lost (error #%d): %s -- reconnecting in %.1fs",
                    self._errors, exc, backoff,
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                try:
                    self.w = WinDivert(self._filter)
                except Exception as e2:
                    log.error("WinDivert reconnect failed: %s", e2)

    def log_stats(self) -> None:
        log.info(
            "Injector stats  recv=%d  errors=%d",
            self._packets_recv, self._errors,
        )
