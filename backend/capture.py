"""Scapy-based network packet capture."""

from scapy.all import sniff
from backend.parser import parse_packet
from database import insert_packet


def _process_packet(packet):
    """Callback for sniff: parse the packet and store it in the database."""
    metadata = parse_packet(packet)
    if metadata and metadata.get("source_ip"):
        insert_packet(metadata)


def capture_packets(interface, count=1):
    """Capture packets from the selected network interface."""
    if not interface:
        raise ValueError("Network interface must be provided.")

    return sniff(iface=interface, count=count, prn=_process_packet)
