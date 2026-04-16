"""
MonitorConnection — tracks TCP state for a single intercepted connection.
"""
import socket
import threading


class MonitorConnection:
    """
    Holds the TCP sequence state for one connection being monitored by
    the WinDivert thread.  Access to mutable fields must be done while
    holding `thread_lock`.
    """
    __slots__ = (
        "monitor", "syn_seq", "syn_ack_seq",
        "src_ip", "dst_ip", "src_port", "dst_port",
        "id", "thread_lock", "sock",
    )

    def __init__(
        self,
        sock: socket.socket,
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
    ) -> None:
        self.monitor     = True
        self.syn_seq     = -1
        self.syn_ack_seq = -1
        self.src_ip      = src_ip
        self.dst_ip      = dst_ip
        self.src_port    = src_port
        self.dst_port    = dst_port
        self.id          = (src_ip, src_port, dst_ip, dst_port)
        self.thread_lock = threading.Lock()
        self.sock        = sock
