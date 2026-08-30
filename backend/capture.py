"""Scapy-based network packet capture."""

from scapy.all import sniff


def capture_packets(interface, count=1):
    """Capture packets from the selected network interface."""
    if not interface:
        raise ValueError("Network interface must be provided.")

    return sniff(iface=interface, count=count)