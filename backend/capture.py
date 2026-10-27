"""Scapy-based network packet capture with background controls."""

from threading import Event, Lock, Thread

from scapy.all import get_if_list, sniff
from scapy.layers.inet import IP

from backend.parser import parse_packet
from database import insert_packet

_state_lock = Lock()
_stop_event = Event()
_capture_thread = None
_state = {
    "running": False,
    "interface": None,
    "error": None,
    "packets_captured": 0,
}


class CaptureAlreadyRunningError(RuntimeError):
    """Raised when a capture is already active."""


def _process_packet(packet):
    """Store IPv4 packet metadata and ignore non-IP packets."""
    if packet is None or not packet.haslayer(IP):
        return
    metadata = parse_packet(packet)
    if not metadata or not metadata.get("source_ip"):
        return
    insert_packet(metadata)
    with _state_lock:
        _state["packets_captured"] += 1


def capture_packets(interface, count=1):
    """Capture packets synchronously for backwards compatibility."""
    if not interface:
        raise ValueError("Network interface must be provided.")
    return sniff(iface=interface, count=count, prn=_process_packet)


def list_interfaces():
    """Return available network interface names."""
    return sorted(set(get_if_list()))


def capture_status():
    """Return a snapshot of capture state."""
    with _state_lock:
        return dict(_state)


def _capture_worker(interface):
    global _capture_thread
    try:
        while not _stop_event.is_set():
            sniff(
                iface=interface,
                prn=_process_packet,
                store=False,
                timeout=1,
                stop_filter=lambda packet: _stop_event.is_set(),
            )
    except Exception as exc:
        with _state_lock:
            _state["error"] = str(exc) or exc.__class__.__name__
    finally:
        with _state_lock:
            _state["running"] = False
            _capture_thread = None


def start_capture(interface):
    """Start background capture or raise for an invalid interface/state."""
    global _capture_thread
    if not isinstance(interface, str) or not interface.strip():
        raise ValueError("Network interface must be provided.")
    interface = interface.strip()
    if interface not in list_interfaces():
        raise ValueError(f"Unknown network interface: {interface}")
    with _state_lock:
        if _state["running"]:
            raise CaptureAlreadyRunningError("Packet capture is already running.")
        _stop_event.clear()
        _state.update(
            running=True,
            interface=interface,
            error=None,
            packets_captured=0,
        )
        _capture_thread = Thread(
            target=_capture_worker,
            args=(interface,),
            name="packet-capture",
            daemon=True,
        )
        _capture_thread.start()
    return capture_status()


def stop_capture():
    """Stop background capture and return its latest state."""
    with _state_lock:
        thread = _capture_thread
        if thread is None:
            return dict(_state)
        _stop_event.set()
    thread.join(timeout=2)
    with _state_lock:
        if not thread.is_alive():
            _state["running"] = False
        return dict(_state)
