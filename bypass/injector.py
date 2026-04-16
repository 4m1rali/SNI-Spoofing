"""
TcpInjector — abstract base class for WinDivert-based packet injectors.
"""
import sys
from abc import ABC, abstractmethod

from pydivert import WinDivert
from pydivert.packet import Packet
from logger_setup import get_logger

log = get_logger("injector")


class TcpInjector(ABC):
    def __init__(self, w_filter: str) -> None:
        self.w: WinDivert = WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Packet) -> None: ...

    def run(self) -> None:
        """Blocking receive-and-inject loop. Run in a daemon thread."""
        log.info("WinDivert injector started")
        with self.w:
            while True:
                try:
                    packet = self.w.recv(65536)
                    self.inject(packet)
                except Exception as exc:
                    log.error("Injector error: %s", exc, exc_info=True)
